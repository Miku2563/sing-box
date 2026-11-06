package transport

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/badhttp"
	"github.com/sagernet/sing-box/common/dialer"
	sTLS "github.com/sagernet/sing-box/common/tls"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/dns"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/buf"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	mDNS "github.com/miekg/dns"
	"golang.org/x/net/http2"
)

const (
	MimeType = "application/dns-message"

	// 连续超时达到多少次才重置底层连接池（避免单次丢包误杀健康的 HTTP/2 多路复用连接）
	maxConsecutiveTimeouts = 3

	// ExchangeAsync 最大并发协程数限制（防止 DNS 风暴导致 Goroutine 暴涨 OOM）
	maxAsyncConcurrency = 64

	// DNS 报文最大合法尺寸 (64KB)，防止恶意服务端 Chunked 响应打爆内存
	maxDNSMessageSize = 65535

	// 当降级到 HTTP/1.1 后，尝试恢复到 HTTP/2 的探测间隔
	fallbackRecoveryInterval = 5 * time.Minute
)

var (
	_ adapter.DNSTransport         = (*HTTPSTransport)(nil)
	_ adapter.IdleConnectionKeeper = (*HTTPSTransport)(nil)

	errFallback = errors.New("fallback to http/1.1")
)

func RegisterHTTPS(registry *dns.TransportRegistry) {
	dns.RegisterTransport[option.RemoteHTTPSDNSServerOptions](registry, C.DNSTypeHTTPS, NewHTTPS)
}

type HTTPSTransport struct {
	dns.TransportAdapter
	logger              logger.ContextLogger
	dialer              N.Dialer
	destination         *url.URL
	headers             http.Header
	serverAddr          M.Socksaddr
	fallback            *atomic.Bool
	plainHTTP           bool
	keepIdle            atomic.Bool
	consecutiveTimeouts atomic.Uint32
	asyncSem            chan struct{}
	transportAccess     sync.Mutex
	transport           *HTTPSTransportWrapper
	transportResetAt    time.Time
}

func NewHTTPS(ctx context.Context, logger log.ContextLogger, tag string, options option.RemoteHTTPSDNSServerOptions) (adapter.DNSTransport, error) {
	transportDialer, err := dns.NewRemoteDialer(ctx, options.RemoteDNSServerOptions)
	if err != nil {
		return nil, err
	}
	tlsOptions := common.PtrValueOrDefault(options.TLS)
	tlsOptions.Enabled = true
	tlsConfig, err := sTLS.NewClient(ctx, logger, options.Server, tlsOptions)
	if err != nil {
		return nil, err
	}
	if len(tlsConfig.NextProtos()) == 0 {
		tlsConfig.SetNextProtos([]string{http2.NextProtoTLS, "http/1.1"})
	}
	headers := options.Headers.Build()
	host := headers.Get("Host")
	if host != "" {
		headers.Del("Host")
	} else {
		if tlsConfig.ServerName() != "" {
			host = tlsConfig.ServerName()
		} else {
			host = options.Server
		}
	}
	destinationAddress := M.ParseSocksaddrHostPort(host, options.ServerPort)
	destinationURL := url.URL{Scheme: "https"}
	if options.ServerPort != 0 && options.ServerPort != 443 {
		destinationURL.Host = destinationAddress.String()
	} else if destinationAddress.IsIPv6() {
		destinationURL.Host = "[" + destinationAddress.AddrString() + "]"
	} else {
		destinationURL.Host = destinationAddress.AddrString()
	}
	path := options.Path
	if path == "" {
		path = "/dns-query"
	}
	err = badhttp.URLSetPath(&destinationURL, path)
	if err != nil {
		return nil, err
	}
	serverAddr := options.DNSServerAddressOptions.Build()
	if serverAddr.Port == 0 {
		serverAddr.Port = 443
	}
	if !serverAddr.IsValid() {
		return nil, E.New("invalid server address: ", serverAddr)
	}
	return NewHTTPSRaw(
		dns.NewTransportAdapterWithRemoteOptions(C.DNSTypeHTTPS, tag, options.RemoteDNSServerOptions),
		logger,
		transportDialer,
		&destinationURL,
		headers,
		serverAddr,
		tlsConfig,
	), nil
}

func NewHTTPSRaw(
	adapter dns.TransportAdapter,
	logger log.ContextLogger,
	dialer N.Dialer,
	destination *url.URL,
	headers http.Header,
	serverAddr M.Socksaddr,
	tlsConfig sTLS.Config,
) *HTTPSTransport {
	if tlsConfig != nil {
		dialer = sTLS.NewDialer(dialer, tlsConfig)
	}
	fallback := new(atomic.Bool)
	plainHTTP := destination.Scheme == "http"
	if plainHTTP {
		// plain HTTP DoH used by Tailscale
		fallback.Store(true)
	}
	transport := &HTTPSTransport{
		TransportAdapter: adapter,
		logger:           logger,
		dialer:           dialer,
		destination:      destination,
		headers:          headers,
		serverAddr:       serverAddr,
		fallback:         fallback,
		plainHTTP:        plainHTTP,
		asyncSem:         make(chan struct{}, maxAsyncConcurrency),
		transport:        NewHTTPSTransportWrapper(dialer, serverAddr, fallback, plainHTTP),
	}
	transport.keepIdle.Store(true)
	return transport
}

func (t *HTTPSTransport) Start(stage adapter.StartStage, scope *adapter.Scope) error {
	if stage != adapter.StartStateStart {
		return nil
	}
	scope.Add(func() error {
		t.Close()
		return nil
	})
	return dialer.InitializeDetour(t.dialer)
}

func (t *HTTPSTransport) Close() error {
	t.transportAccess.Lock()
	defer t.transportAccess.Unlock()
	if t.transport != nil {
		t.transport.Close()
	}
	return nil
}

func (t *HTTPSTransport) Reset() {
	t.transportAccess.Lock()
	defer t.transportAccess.Unlock()
	t.resetTransportLocked()
}

func (t *HTTPSTransport) SetKeepIdleConnections(keep bool) {
	t.keepIdle.Store(keep)
	if !keep {
		t.CloseIdleConnections()
	}
}

func (t *HTTPSTransport) CloseIdleConnections() {
	t.transportAccess.Lock()
	defer t.transportAccess.Unlock()
	t.transport.CloseIdleConnections()
}

func (t *HTTPSTransport) resetTransportLocked() {
	oldTransport := t.transport
	t.transport = NewHTTPSTransportWrapper(t.dialer, t.serverAddr, t.fallback, t.plainHTTP)
	t.transportResetAt = time.Now()
	t.consecutiveTimeouts.Store(0)
	if oldTransport != nil {
		oldTransport.Close()
	}
}

func (t *HTTPSTransport) Exchange(ctx context.Context, message *mDNS.Msg) (*mDNS.Msg, error) {
	startAt := time.Now()
	response, err := t.exchange(ctx, message)
	if !t.keepIdle.Load() {
		t.CloseIdleConnections()
	}
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			count := t.consecutiveTimeouts.Add(1)
			if count >= maxConsecutiveTimeouts {
				t.transportAccess.Lock()
				// 防惊群检查：确保同一批并发超时请求只会触发一次重置
				if !t.transportResetAt.After(startAt) {
					t.logger.WarnContext(ctx, "doh transport reset after ", count, " consecutive timeouts to ", t.serverAddr)
					t.resetTransportLocked()
				}
				t.transportAccess.Unlock()
			} else {
				t.logger.DebugContext(ctx, "doh request timeout (", count, "/", maxConsecutiveTimeouts, ") to ", t.serverAddr)
			}
		}
		return nil, err
	}
	// 只要有一次请求成功，说明底层连接健康，立即清零连续超时计数
	t.consecutiveTimeouts.Store(0)
	return response, nil
}

// ExchangeAsync 使用有界信号量控制并发度，避免极端情况下 Goroutine 泄漏或爆炸
func (t *HTTPSTransport) ExchangeAsync(ctx context.Context, message *mDNS.Msg, callback func(response *mDNS.Msg, err error)) {
	go func() {
		select {
		case t.asyncSem <- struct{}{}:
			defer func() { <-t.asyncSem }()
			callback(t.Exchange(ctx, message))
		case <-ctx.Done():
			callback(nil, ctx.Err())
		}
	}()
}

func (t *HTTPSTransport) exchange(ctx context.Context, message *mDNS.Msg) (*mDNS.Msg, error) {
	exMessage := message.Copy()
	exMessage.Id = 0
	exMessage.Compress = true
	requestBuffer := buf.NewSize(1 + message.Len())
	rawMessage, err := exMessage.PackBuffer(requestBuffer.FreeBytes())
	if err != nil {
		requestBuffer.Release()
		return nil, err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, t.destination.String(), bytes.NewReader(rawMessage))
	if err != nil {
		requestBuffer.Release()
		return nil, err
	}
	request.Header = t.headers.Clone()
	request.Header.Set("Content-Type", MimeType)
	request.Header.Set("Accept", MimeType)

	t.transportAccess.Lock()
	currentTransport := t.transport
	t.transportAccess.Unlock()

	response, err := currentTransport.RoundTrip(request)
	requestBuffer.Release()
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		return nil, E.New("unexpected status: ", response.Status)
	}

	// 兼容性 Content-Type 校验（忽略参数如 "; charset=utf-8" 及大小写差异）
	if contentType := response.Header.Get("Content-Type"); contentType != "" {
		if !isValidDNSContentType(contentType) {
			return nil, E.New("unexpected content-type: ", contentType)
		}
	}

	var responseMessage mDNS.Msg
	if response.ContentLength > 0 {
		if response.ContentLength > maxDNSMessageSize {
			return nil, E.New("response too large: ", response.ContentLength)
		}
		responseBuffer := buf.NewSize(int(response.ContentLength))
		defer responseBuffer.Release()
		_, err = responseBuffer.ReadFullFrom(response.Body, int(response.ContentLength))
		if err != nil {
			return nil, err
		}
		err = responseMessage.Unpack(responseBuffer.Bytes())
	} else {
		// 限制最大读取字节数，防止恶意 Chunked 响应耗尽内存
		rawMessage, err = io.ReadAll(io.LimitReader(response.Body, maxDNSMessageSize+1))
		if err != nil {
			return nil, err
		}
		if len(rawMessage) > maxDNSMessageSize {
			return nil, E.New("response body exceeds maximum DNS message size")
		}
		err = responseMessage.Unpack(rawMessage)
	}
	if err != nil {
		return nil, err
	}
	// 恢复原始 DNS 请求 ID，确保上层依赖 ID 匹配的调用方正常工作
	responseMessage.Id = message.Id
	return &responseMessage, nil
}

// isValidDNSContentType 零内存分配（Zero-Allocation）校验 Media-Type
func isValidDNSContentType(contentType string) bool {
	mediaType, _, _ := strings.Cut(contentType, ";")
	mediaType = strings.TrimSpace(mediaType)
	return strings.EqualFold(mediaType, MimeType)
}

// ============================================================================
// HTTPSTransportWrapper: 负责 H2/H1 无损降级、定时恢复探测与严格连接生命周期管理
// ============================================================================

type HTTPSTransportWrapper struct {
	dialer            N.Dialer
	serverAddr        M.Socksaddr
	fallback          *atomic.Bool
	plainHTTP         bool
	fallbackAtNano    atomic.Int64 // 记录降级发生的时间戳（用于定时恢复探测）

	access            sync.Mutex
	closed            bool
	closeCtx          context.Context
	closeCancel       context.CancelFunc
	transport         *http2.Transport
	fallbackTransport *http.Transport

	// Stash 机制：当 H2 拨号握手完成后发现 ALPN 是 http/1.1 时，
	// 暂存该连接直接移交给 H1 Transport 使用，避免关闭连接再重新握手的开销。
	stashedConnAccess sync.Mutex
	stashedConn       net.Conn
}

func NewHTTPSTransportWrapper(dialer N.Dialer, serverAddr M.Socksaddr, fallback *atomic.Bool, plainHTTP bool) *HTTPSTransportWrapper {
	closeCtx, closeCancel := context.WithCancel(context.Background())
	w := &HTTPSTransportWrapper{
		dialer:      dialer,
		serverAddr:  serverAddr,
		fallback:    fallback,
		plainHTTP:   plainHTTP,
		closeCtx:    closeCtx,
		closeCancel: closeCancel,
	}
	if fallback.Load() && !plainHTTP {
		w.fallbackAtNano.Store(time.Now().UnixNano())
	}
	return w
}

func (w *HTTPSTransportWrapper) RoundTrip(request *http.Request) (*http.Response, error) {
	if w.fallback.Load() {
		// Fallback 自动恢复机制：如果不是强制明文 HTTP，且距离上次降级已超过冷却时间，
		// 则通过 CAS 尝试切回 HTTP/2 进行探测。
		if !w.plainHTTP && w.shouldAttemptRecovery() {
			if w.fallback.CompareAndSwap(true, false) {
				return w.roundTripH2(request)
			}
		}
		return w.roundTripFallback(request)
	}
	return w.roundTripH2(request)
}

func (w *HTTPSTransportWrapper) shouldAttemptRecovery() bool {
	lastNano := w.fallbackAtNano.Load()
	if lastNano == 0 {
		return false
	}
	return time.Since(time.Unix(0, lastNano)) >= fallbackRecoveryInterval
}

func (w *HTTPSTransportWrapper) markFallback() {
	w.fallbackAtNano.Store(time.Now().UnixNano())
	w.fallback.Store(true)
}

func (w *HTTPSTransportWrapper) roundTripH2(request *http.Request) (*http.Response, error) {
	w.access.Lock()
	if w.closed {
		w.access.Unlock()
		return nil, net.ErrClosed
	}
	transport := w.transport
	if transport == nil {
		transport = &http2.Transport{
			DialTLSContext: func(ctx context.Context, network, addr string, cfg *tls.Config) (net.Conn, error) {
				conn, err := w.dialContext(ctx)
				if err != nil {
					return nil, err
				}
				// 检查 TLS ALPN 协商结果
				if tlsConn, isTLS := common.Cast[sTLS.Conn](conn); isTLS {
					state := tlsConn.ConnectionState()
					if state.NegotiatedProtocol != http2.NextProtoTLS {
						// 服务端不支持 h2，标记降级并将已建立的 TLS 连接暂存移交给 H1 复用
						w.markFallback()
						w.stashConn(conn)
						return nil, errFallback
					}
				}
				return conn, nil
			},
			ReadIdleTimeout: 30 * time.Second,
			PingTimeout:     15 * time.Second,
		}
		w.transport = transport
	}
	w.access.Unlock()

	response, err := transport.RoundTrip(request)
	if err != nil {
		// 捕获降级信号，无缝切换到 HTTP/1.1 并复用刚才暂存的连接完成本次请求
		if errors.Is(err, errFallback) {
			return w.roundTripFallback(request)
		}
		return nil, err
	}
	return response, nil
}

func (w *HTTPSTransportWrapper) roundTripFallback(request *http.Request) (*http.Response, error) {
	w.access.Lock()
	if w.closed {
		w.access.Unlock()
		return nil, net.ErrClosed
	}
	fallbackTransport := w.fallbackTransport
	if fallbackTransport == nil {
		dialFunc := func(ctx context.Context, network, addr string) (net.Conn, error) {
			// 优先消费从 H2 降级移交过来的已握手连接，实现 0-RTT 无损降级
			if stashed := w.popStashedConn(); stashed != nil {
				return stashed, nil
			}
			return w.dialContext(ctx)
		}
		fallbackTransport = &http.Transport{
			DialContext:           dialFunc,
			DialTLSContext:        dialFunc,
			ForceAttemptHTTP2:     false,
			MaxIdleConns:          10,
			MaxIdleConnsPerHost:   10,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
		}
		w.fallbackTransport = fallbackTransport
	}
	w.access.Unlock()
	return fallbackTransport.RoundTrip(request)
}

// dialContext 绑定了 Wrapper 自身的 closeCtx，确保调用 Close() 时能立即中断正在进行的拨号
func (w *HTTPSTransportWrapper) dialContext(ctx context.Context) (net.Conn, error) {
	select {
	case <-w.closeCtx.Done():
		return nil, net.ErrClosed
	default:
	}

	dialCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	stop := context.AfterFunc(w.closeCtx, cancel)
	defer stop()

	conn, err := w.dialer.DialContext(dialCtx, N.NetworkTCP, w.serverAddr)
	if err != nil {
		return nil, err
	}

	// 双重检查：如果在拨号刚完成的瞬间 Wrapper 被关闭，立即清理连接防止泄漏
	select {
	case <-w.closeCtx.Done():
		conn.Close()
		return nil, net.ErrClosed
	default:
		return conn, nil
	}
}

func (w *HTTPSTransportWrapper) stashConn(conn net.Conn) {
	w.stashedConnAccess.Lock()
	defer w.stashedConnAccess.Unlock()
	select {
	case <-w.closeCtx.Done():
		conn.Close()
		return
	default:
	}
	if w.stashedConn != nil {
		w.stashedConn.Close()
	}
	w.stashedConn = conn
}

func (w *HTTPSTransportWrapper) popStashedConn() net.Conn {
	w.stashedConnAccess.Lock()
	defer w.stashedConnAccess.Unlock()
	conn := w.stashedConn
	w.stashedConn = nil
	return conn
}

func (w *HTTPSTransportWrapper) clearStashedConn() {
	if conn := w.popStashedConn(); conn != nil {
		conn.Close()
	}
}

func (w *HTTPSTransportWrapper) CloseIdleConnections() {
	w.clearStashedConn()
	w.access.Lock()
	h2 := w.transport
	h1 := w.fallbackTransport
	w.access.Unlock()

	if h2 != nil {
		h2.CloseIdleConnections()
	}
	if h1 != nil {
		h1.CloseIdleConnections()
	}
}

func (w *HTTPSTransportWrapper) Close() {
	// 1. 触发取消信号，立即中断所有在途的 dialContext 握手
	w.closeCancel()
	// 2. 清理暂存的降级连接
	w.clearStashedConn()

	// 3. 锁定并剥离底层 Transport 引用
	w.access.Lock()
	if w.closed {
		w.access.Unlock()
		return
	}
	w.closed = true
	h2 := w.transport
	h1 := w.fallbackTransport
	w.transport = nil
	w.fallbackTransport = nil
	w.access.Unlock()

	// 4. 在锁外关闭连接池，避免死锁
	if h2 != nil {
		h2.CloseIdleConnections()
	}
	if h1 != nil {
		h1.CloseIdleConnections()
	}
}
