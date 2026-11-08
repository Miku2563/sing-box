package transport

import (
	"context"
	crand "crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/dialer"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/dns"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	mDNS "github.com/miekg/dns"
)

const (
	udpDefaultPort         = 53
	udpDefaultQueryTimeout = 5 * time.Second
	udpDefaultIdleTimeout  = 30 * time.Second
	udpMinEDNSSize         = 512
	// DNS Flag Day 2020 推荐值:超过约 1400 字节的 UDP 报文容易被 IP 分片并在网络中被丢弃
	udpMaxEDNSSize   = 1232
	udpMaxPacketSize = 65535
	udpMaxInflight   = 4096

	// 重传:发出后若在 udpRetransmitInterval 内没有应答,用同一 ID 重发一次。
	// 剩余时间的一半小于该值时按一半计算;低于 udpMinRetransmit 则不重传。
	udpRetransmitInterval = 1500 * time.Millisecond
	udpMinRetransmit      = 300 * time.Millisecond
)

var (
	_ adapter.DNSTransport         = (*UDPTransport)(nil)
	_ adapter.IdleConnectionKeeper = (*UDPTransport)(nil)
)

func RegisterUDP(registry *dns.TransportRegistry) {
	dns.RegisterTransport[option.RemoteDNSServerOptions](registry, C.DNSTypeUDP, NewUDP)
}

// UDPTransport 是基于单个已连接 UDP socket 的 DNS 传输实现。
// 同一时刻复用一个 session 承载并发查询,超时无应答会重传一次,截断时回退到 TCP。
type UDPTransport struct {
	dns.TransportAdapter
	logger logger.ContextLogger

	dialer       N.Dialer
	serverAddr   M.Socksaddr
	queryTimeout time.Duration
	idleTimeout  time.Duration
	keepIdle     atomic.Bool

	mu      sync.Mutex
	session *udpSession
	closed  bool
}

func NewUDP(ctx context.Context, logger log.ContextLogger, tag string, options option.RemoteDNSServerOptions) (adapter.DNSTransport, error) {
	transportDialer, err := dns.NewRemoteDialer(ctx, options)
	if err != nil {
		return nil, err
	}
	serverAddr := options.DNSServerAddressOptions.Build()
	if serverAddr.Port == 0 {
		serverAddr.Port = udpDefaultPort
	}
	if !serverAddr.IsValid() {
		return nil, E.New("invalid server address: ", serverAddr)
	}
	return NewUDPRaw(logger, dns.NewTransportAdapterWithRemoteOptions(C.DNSTypeUDP, tag, options), transportDialer, serverAddr), nil
}

func NewUDPRaw(logger logger.ContextLogger, ta dns.TransportAdapter, dialerInstance N.Dialer, serverAddr M.Socksaddr) *UDPTransport {
	return &UDPTransport{
		TransportAdapter: ta,
		logger:           logger,
		dialer:           dialerInstance,
		serverAddr:       serverAddr,
		queryTimeout:     udpDefaultQueryTimeout,
		idleTimeout:      udpDefaultIdleTimeout,
	}
}

func (t *UDPTransport) Start(stage adapter.StartStage, scope *adapter.Scope) error {
	if stage != adapter.StartStateStart {
		return nil
	}
	scope.Add(t.Close)
	return dialer.InitializeDetour(t.dialer)
}

// Close 关闭传输并拒绝后续查询。可重复调用,返回值符合 scope.Add 的 func() error 签名。
func (t *UDPTransport) Close() error {
	t.mu.Lock()
	if t.closed {
		t.mu.Unlock()
		return nil
	}
	t.closed = true
	session := t.session
	t.session = nil
	t.mu.Unlock()

	if session != nil {
		session.close(E.New("DNS transport closed"))
	}
	return nil
}

// Reset 丢弃当前 session,下次查询时重新建立连接(例如网络切换后)。
// 在途查询会收到 udpSessionClosedError,并由 exchangeUDP 换新会话重试一次。
func (t *UDPTransport) Reset() {
	t.mu.Lock()
	session := t.session
	t.session = nil
	t.mu.Unlock()

	if session != nil {
		session.close(E.New("DNS transport reset"))
	}
}

// SetKeepIdleConnections 设置是否保持空闲连接。
// 从 true 改回 false 时,需要为已有 session 重新武装空闲定时器,
// 否则该 session 及其 readLoop 会一直存活。
func (t *UDPTransport) SetKeepIdleConnections(keep bool) {
	t.keepIdle.Store(keep)
	if keep {
		return
	}
	t.mu.Lock()
	session := t.session
	t.mu.Unlock()

	if session != nil {
		session.rearmIdle()
	}
}

func (t *UDPTransport) CloseIdleConnections() {
	t.mu.Lock()
	session := t.session
	t.mu.Unlock()

	if session != nil {
		session.closeIfIdle()
	}
}

func (t *UDPTransport) Exchange(ctx context.Context, message *mDNS.Msg) (*mDNS.Msg, error) {
	query := udpPrepareQuery(message)

	response, err := t.exchangeUDP(ctx, query)
	if err != nil {
		return nil, err
	}

	// 部分老旧服务器不支持 EDNS0,会返回 FORMERR,去掉 OPT 后重试一次。
	if response.Rcode == mDNS.RcodeFormatError && query.IsEdns0() != nil {
		t.logger.DebugContext(ctx, "server rejected EDNS0, retrying without OPT record")
		query = udpStripEDNS0(query)
		response, err = t.exchangeUDP(ctx, query)
		if err != nil {
			return nil, err
		}
	}

	if response.Truncated {
		t.logger.DebugContext(ctx, "UDP response truncated, retrying over TCP")
		return t.exchangeTCP(ctx, query)
	}
	return response, nil
}

func (t *UDPTransport) ExchangeAsync(ctx context.Context, message *mDNS.Msg, callback func(response *mDNS.Msg, err error)) {
	go func() {
		callback(t.Exchange(ctx, message))
	}()
}

// exchangeUDP 在 UDP session 上完成一次查询。
// 若会话在"获取之后、使用之前/期间"被关闭(空闲到期、Reset、CloseIdleConnections、读错误),
// 换一个新会话重试一次,避免把本可恢复的失败暴露给调用方。
func (t *UDPTransport) exchangeUDP(ctx context.Context, query *mDNS.Msg) (*mDNS.Msg, error) {
	ctx, cancel := context.WithTimeout(ctx, t.queryTimeout)
	defer cancel()

	for attempt := 0; ; attempt++ {
		session, err := t.acquireSession(ctx)
		if err != nil {
			return nil, err
		}
		response, err := session.exchange(ctx, query)
		if err != nil && attempt == 0 && ctx.Err() == nil {
			var closed *udpSessionClosedError
			if errors.As(err, &closed) {
				t.logger.DebugContext(ctx, "UDP session closed during query, retrying on a new session: ", err)
				continue
			}
		}
		return response, err
	}
}

// acquireSession 返回可用 session,必要时建立新连接。
// 拨号在锁外进行,避免阻塞其他查询;竞争时保留先建立的 session。
func (t *UDPTransport) acquireSession(ctx context.Context) (*udpSession, error) {
	t.mu.Lock()
	if t.closed {
		t.mu.Unlock()
		return nil, E.New("DNS transport closed")
	}
	if s := t.session; s != nil && !s.isClosed() {
		t.mu.Unlock()
		return s, nil
	}
	t.mu.Unlock()

	conn, err := t.dialer.DialContext(ctx, N.NetworkUDP, t.serverAddr)
	if err != nil {
		return nil, E.Cause(err, "dial UDP connection to ", t.serverAddr)
	}
	session := newUDPSession(conn, t.logger, t.idleTimeout, &t.keepIdle)

	t.mu.Lock()
	if t.closed {
		t.mu.Unlock()
		session.close(E.New("DNS transport closed"))
		return nil, E.New("DNS transport closed")
	}
	if existing := t.session; existing != nil && !existing.isClosed() {
		t.mu.Unlock()
		session.close(E.New("superseded by concurrent dial"))
		return existing, nil
	}
	t.session = session
	t.mu.Unlock()

	go session.readLoop()
	return session, nil
}

// exchangeTCP 通过 TCP 重新发送查询(用于 UDP 截断回退)。每次使用一次性连接。
func (t *UDPTransport) exchangeTCP(ctx context.Context, query *mDNS.Msg) (*mDNS.Msg, error) {
	ctx, cancel := context.WithTimeout(ctx, t.queryTimeout)
	defer cancel()

	conn, err := t.dialer.DialContext(ctx, N.NetworkTCP, t.serverAddr)
	if err != nil {
		return nil, E.Cause(err, "dial TCP connection to ", t.serverAddr)
	}
	defer conn.Close()

	// ctx 超时或取消时立即打断阻塞的读写。
	stop := context.AfterFunc(ctx, func() {
		_ = conn.SetDeadline(time.Now())
	})
	defer stop()

	packet, err := query.Pack()
	if err != nil {
		return nil, E.Cause(err, "pack DNS query")
	}
	if len(packet) > 0xFFFF {
		return nil, E.New("DNS query too large for TCP framing")
	}
	frame := make([]byte, 2+len(packet))
	binary.BigEndian.PutUint16(frame, uint16(len(packet)))
	copy(frame[2:], packet)
	if _, err = conn.Write(frame); err != nil {
		return nil, E.Cause(err, "write TCP query")
	}

	var header [2]byte
	if _, err = io.ReadFull(conn, header[:]); err != nil {
		return nil, E.Cause(err, "read TCP response length")
	}
	body := make([]byte, binary.BigEndian.Uint16(header[:]))
	if _, err = io.ReadFull(conn, body); err != nil {
		return nil, E.Cause(err, "read TCP response")
	}

	var response mDNS.Msg
	if err = response.Unpack(body); err != nil {
		return nil, E.Cause(err, "unpack TCP response")
	}
	if !response.Response || response.Id != query.Id || !udpQuestionMatches(query, &response) {
		return nil, E.New("unexpected TCP response from ", t.serverAddr)
	}
	return &response, nil
}

// ---------------------------------------------------------------------------
// udpSession: 单个已连接 UDP socket 上的多路复用会话
// ---------------------------------------------------------------------------

// udpSessionClosedError 标记"会话已关闭"这一类可恢复错误,
// 调用方可据此换新会话重试。
type udpSessionClosedError struct{ cause error }

func (e *udpSessionClosedError) Error() string { return e.cause.Error() }
func (e *udpSessionClosedError) Unwrap() error { return e.cause }

type udpSession struct {
	conn        net.Conn
	logger      logger.ContextLogger
	idleTimeout time.Duration
	keepIdle    *atomic.Bool

	mu        sync.Mutex
	pending   map[uint16]*udpPendingQuery
	idleTimer *time.Timer
	closed    bool
	err       error
	done      chan struct{}
}

type udpPendingQuery struct {
	query    *mDNS.Msg
	response chan *mDNS.Msg // 缓冲为 1,每个查询只会收到一次投递
}

func newUDPSession(conn net.Conn, lg logger.ContextLogger, idleTimeout time.Duration, keepIdle *atomic.Bool) *udpSession {
	s := &udpSession{
		conn:        conn,
		logger:      lg,
		idleTimeout: idleTimeout,
		keepIdle:    keepIdle,
		pending:     make(map[uint16]*udpPendingQuery),
		done:        make(chan struct{}),
	}
	s.mu.Lock()
	s.armIdleLocked()
	s.mu.Unlock()
	return s
}

// readLoop 持续读取 UDP 响应并按 ID + Question 分发。
func (s *udpSession) readLoop() {
	buf := make([]byte, udpMaxPacketSize)
	for {
		n, err := s.conn.Read(buf)
		if err != nil {
			if s.isClosed() {
				return
			}
			// ICMP 错误与某次发送相关,不应使整个会话失败;由各查询的超时兜底。
			if errors.Is(err, syscall.ECONNREFUSED) || errors.Is(err, syscall.ECONNRESET) {
				s.logger.Debug("ignored ICMP error on UDP session: ", err)
				continue
			}
			s.close(E.Cause(err, "read UDP response"))
			return
		}

		// miekg/dns 的 Unpack 会复制所需数据,因此可以安全复用 buf。
		var response mDNS.Msg
		if err = response.Unpack(buf[:n]); err != nil {
			s.logger.Debug("discarded malformed UDP response: ", err)
			continue
		}
		if !response.Response {
			continue
		}
		s.dispatch(&response)
	}
}

func (s *udpSession) dispatch(response *mDNS.Msg) {
	s.mu.Lock()
	waiter := s.pending[response.Id]
	if waiter == nil || !udpQuestionMatches(waiter.query, response) {
		s.mu.Unlock()
		// 重传后服务器可能应答两次,第二个包会走到这里,属于正常现象
		s.logger.Debug("dropped unmatched UDP response, id=", response.Id)
		return
	}
	delete(s.pending, response.Id)
	s.armIdleLocked()
	s.mu.Unlock()

	waiter.response <- response
}

// exchange 在该会话上发送一条查询并等待响应。
// 调用方的 query 不会被修改:内部使用会话分配的 ID 发送,返回前恢复原 ID。
// 发出后若在重传延迟内没有应答,用同一 ID 重发一次(只重传一次)。
func (s *udpSession) exchange(ctx context.Context, query *mDNS.Msg) (*mDNS.Msg, error) {
	id, pending, err := s.register(query)
	if err != nil {
		return nil, err
	}
	defer s.unregister(id, pending)

	wireMsg := *query
	wireMsg.Id = id
	wireMsg.Compress = true
	packet, err := wireMsg.Pack()
	if err != nil {
		return nil, E.Cause(err, "pack DNS query")
	}
	if _, err = s.conn.Write(packet); err != nil {
		return nil, E.Cause(err, "write UDP query")
	}

	var retryC <-chan time.Time
	if d := udpRetransmitDelay(ctx); d > 0 {
		timer := time.NewTimer(d)
		defer timer.Stop()
		retryC = timer.C
	}

	for {
		select {
		case response := <-pending.response:
			response.Id = query.Id
			return response, nil
		case <-retryC:
			retryC = nil // 只重传一次;nil channel 在 select 中永远阻塞
			s.logger.Debug("no UDP response, retransmitting, id=", id)
			if _, werr := s.conn.Write(packet); werr != nil {
				// 重传失败不终止查询:原请求的应答仍可能到达,由 ctx 超时兜底
				s.logger.Debug("UDP retransmit failed: ", werr)
			}
		case <-ctx.Done():
			return nil, E.Cause(ctx.Err(), "wait UDP response")
		case <-s.done:
			return nil, s.err
		}
	}
}

func (s *udpSession) register(query *mDNS.Msg) (uint16, *udpPendingQuery, error) {
	pending := &udpPendingQuery{
		query:    query,
		response: make(chan *mDNS.Msg, 1),
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return 0, nil, s.err
	}
	if len(s.pending) >= udpMaxInflight {
		return 0, nil, E.New("too many in-flight UDP DNS queries")
	}
	s.stopIdleLocked()

	// 随机起点 + 线性探测,保证不与在途 ID 冲突(在途数量远小于 65536)。
	id := udpRandomID()
	for {
		if _, used := s.pending[id]; !used {
			break
		}
		id++
	}
	s.pending[id] = pending
	return id, pending, nil
}

func (s *udpSession) unregister(id uint16, pending *udpPendingQuery) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.pending[id] == pending {
		delete(s.pending, id)
	}
	s.armIdleLocked()
}

// armIdleLocked 在没有在途查询且未设置保持连接时启动空闲计时器。调用方需持有 s.mu。
func (s *udpSession) armIdleLocked() {
	if s.closed || s.idleTimeout <= 0 || len(s.pending) > 0 || s.keepIdle.Load() {
		return
	}
	if s.idleTimer == nil {
		s.idleTimer = time.AfterFunc(s.idleTimeout, s.onIdle)
		return
	}
	s.idleTimer.Reset(s.idleTimeout)
}

// rearmIdle 供外部(SetKeepIdleConnections(false))在需要时重新武装空闲计时器。
func (s *udpSession) rearmIdle() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.armIdleLocked()
}

func (s *udpSession) stopIdleLocked() {
	if s.idleTimer != nil {
		s.idleTimer.Stop()
	}
}

func (s *udpSession) onIdle() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.pending) == 0 && !s.keepIdle.Load() {
		s.shutdownLocked(E.New("UDP session idle timeout"))
	}
}

// closeIfIdle 仅在没有在途查询时关闭,检查与关闭在同一把锁内完成,避免竞争。
func (s *udpSession) closeIfIdle() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.pending) == 0 {
		s.shutdownLocked(E.New("UDP session closed while idle"))
	}
}

func (s *udpSession) close(err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.shutdownLocked(err)
}

// shutdownLocked 关闭会话并唤醒所有等待者。调用方需持有 s.mu。
// 关闭原因被包装为 udpSessionClosedError,便于调用方识别并重试。
func (s *udpSession) shutdownLocked(err error) {
	if s.closed {
		return
	}
	if err == nil {
		err = E.New("UDP session closed")
	}
	s.closed = true
	s.err = &udpSessionClosedError{cause: err}
	s.pending = nil
	s.stopIdleLocked()
	close(s.done)
	_ = s.conn.Close()
}

func (s *udpSession) isClosed() bool {
	select {
	case <-s.done:
		return true
	default:
		return false
	}
}

// ---------------------------------------------------------------------------
// 报文辅助函数
// ---------------------------------------------------------------------------

// udpRetransmitDelay 计算重传前的等待时间;返回 0 表示不重传。
// 取 udpRetransmitInterval 与 ctx 剩余时间一半中的较小者,低于 udpMinRetransmit 则放弃。
func udpRetransmitDelay(ctx context.Context) time.Duration {
	d := udpRetransmitInterval
	if dl, ok := ctx.Deadline(); ok {
		if half := time.Until(dl) / 2; half < d {
			d = half
		}
	}
	if d < udpMinRetransmit {
		return 0
	}
	return d
}

// udpPrepareQuery 返回查询的浅拷贝:启用压缩,并将 EDNS0 UDP 尺寸限制在 [512, 1232]。
// 不修改调用方的 message。
func udpPrepareQuery(message *mDNS.Msg) *mDNS.Msg {
	query := *message
	query.Compress = true

	opt := message.IsEdns0()
	if opt == nil {
		return &query
	}
	requested := opt.UDPSize()
	size := udpClamp(int(requested), udpMinEDNSSize, udpMaxEDNSSize)
	if uint16(size) == requested {
		return &query
	}

	replacement := *opt
	replacement.SetUDPSize(uint16(size))
	extra := make([]mDNS.RR, len(message.Extra))
	for i, rr := range message.Extra {
		if rr == mDNS.RR(opt) {
			extra[i] = &replacement
		} else {
			extra[i] = rr
		}
	}
	query.Extra = extra
	return &query
}

// udpStripEDNS0 返回去掉 OPT 记录的浅拷贝,用于 FORMERR 降级重试。
func udpStripEDNS0(message *mDNS.Msg) *mDNS.Msg {
	query := *message
	extra := make([]mDNS.RR, 0, len(message.Extra))
	for _, rr := range message.Extra {
		if _, isOPT := rr.(*mDNS.OPT); !isOPT {
			extra = append(extra, rr)
		}
	}
	query.Extra = extra
	return &query
}

// udpQuestionMatches 校验响应的 Question 与查询一致(名称不区分大小写、类型、类)。
func udpQuestionMatches(query, response *mDNS.Msg) bool {
	if len(query.Question) != 1 {
		return true
	}
	if len(response.Question) != 1 {
		return false
	}
	q, r := query.Question[0], response.Question[0]
	return q.Qtype == r.Qtype && q.Qclass == r.Qclass && strings.EqualFold(q.Name, r.Name)
}

// udpRandomID 使用密码学随机数生成查询 ID,降低被伪造响应命中的概率。
func udpRandomID() uint16 {
	var b [2]byte
	if _, err := crand.Read(b[:]); err != nil {
		return uint16(time.Now().UnixNano())
	}
	return binary.BigEndian.Uint16(b[:])
}

func udpClamp(v, lo, hi int) int {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}
