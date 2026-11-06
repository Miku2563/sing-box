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
	udpMaxEDNSSize         = 4096
	udpMaxPacketSize       = 65535
	udpMaxInflight         = 4096
)

var (
	_ adapter.DNSTransport         = (*UDPTransport)(nil)
	_ adapter.IdleConnectionKeeper = (*UDPTransport)(nil)
)

func RegisterUDP(registry *dns.TransportRegistry) {
	dns.RegisterTransport[option.RemoteDNSServerOptions](registry, C.DNSTypeUDP, NewUDP)
}

// UDPTransport 是基于单个已连接 UDP socket 的 DNS 传输实现。
// 同一时刻复用一个 session 承载并发查询,超时截断时回退到 TCP。
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
func (t *UDPTransport) Reset() {
	t.mu.Lock()
	session := t.session
	t.session = nil
	t.mu.Unlock()

	if session != nil {
		session.close(E.New("DNS transport reset"))
	}
}

func (t *UDPTransport) SetKeepIdleConnections(keep bool) {
	t.keepIdle.Store(keep)
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

func (t *UDPTransport) exchangeUDP(ctx context.Context, query *mDNS.Msg) (*mDNS.Msg, error) {
	ctx, cancel := context.WithTimeout(ctx, t.queryTimeout)
	defer cancel()

	session, err := t.acquireSession(ctx)
	if err != nil {
		return nil, err
	}
	return session.exchange(ctx, query)
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

	select {
	case response := <-pending.response:
		response.Id = query.Id
		return response, nil
	case <-ctx.Done():
		return nil, E.Cause(ctx.Err(), "wait UDP response")
	case <-s.done:
		return nil, s.err
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
func (s *udpSession) shutdownLocked(err error) {
	if s.closed {
		return
	}
	if err == nil {
		err = E.New("UDP session closed")
	}
	s.closed = true
	s.err = err
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

// udpPrepareQuery 返回查询的浅拷贝:启用压缩,并将 EDNS0 UDP 尺寸限制在 [512, 4096]。
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
