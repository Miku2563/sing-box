package transport

import (
	"context"
	"errors"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"golang.org/x/net/http2"
)

const (
	// HTTP/2 空闲健康检查与 Ping 超时配置
	h2ReadIdleTimeout = 30 * time.Second
	h2PingTimeout     = 15 * time.Second

	// HTTP/1.1 连接池配置
	h1MaxIdleConns        = 10
	h1MaxIdleConnsPerHost = 10
	h1IdleConnTimeout     = 90 * time.Second

	// 从 HTTP/1.1 尝试自动恢复到 HTTP/2 的冷却间隔
	fallbackRecoveryInterval = 5 * time.Minute
)

var errFallback = E.New("fallback to HTTP/1.1")

type HTTPSTransportWrapper struct {
	dialer         N.Dialer
	serverAddr     M.Socksaddr
	http2Transport *http2.Transport
	httpTransport  *http.Transport
	fallback       *atomic.Bool
	permanentH1    bool         // 标记是否为初始强制 H1（如 Tailscale 明文 HTTP DoH）
	fallbackAtNano atomic.Int64 // 记录触发 ALPN 降级的时间戳

	closeCtx    context.Context
	closeCancel context.CancelFunc

	connAccess  sync.Mutex
	connections map[*httpsTrackedConn]struct{}
	stashedConn net.Conn // 暂存从 H2 降级移交的已握手连接，实现 0-RTT 降级
	closed      bool
}

func NewHTTPSTransportWrapper(dialer N.Dialer, serverAddr M.Socksaddr, fallback *atomic.Bool) *HTTPSTransportWrapper {
	closeCtx, closeCancel := context.WithCancel(context.Background())
	wrapper := &HTTPSTransportWrapper{
		dialer:      dialer,
		serverAddr:  serverAddr,
		fallback:    fallback,
		permanentH1: fallback.Load(), // 如果初始化时已经是 true，说明是明文 HTTP
		closeCtx:    closeCtx,
		closeCancel: closeCancel,
		connections: make(map[*httpsTrackedConn]struct{}),
	}

	wrapper.http2Transport = &http2.Transport{
		DialTLSContext: func(ctx context.Context, _, _ string, _ *tls.STDConfig) (net.Conn, error) {
			resultConn, err := wrapper.dialContext(ctx)
			if err != nil {
				return nil, err
			}
			// 使用 common.Cast 兼容被中间件包装过的连接
			if tlsConn, isTLSConn := common.Cast[tls.Conn](resultConn); isTLSConn {
				state := tlsConn.ConnectionState()
				if state.NegotiatedProtocol != http2.NextProtoTLS {
					// 标记降级并记录时间
					wrapper.fallbackAtNano.Store(time.Now().UnixNano())
					fallback.Store(true)
					// 将已握手成功的连接暂存，直接移交给 httpTransport 复用，避免关闭重连
					wrapper.stashConn(resultConn)
					return nil, errFallback
				}
			}
			return wrapper.trackConn(resultConn)
		},
		ReadIdleTimeout: h2ReadIdleTimeout,
		PingTimeout:     h2PingTimeout,
	}

	h1DialContext := func(ctx context.Context, _, _ string) (net.Conn, error) {
		// 优先消费从 H2 降级移交过来的连接
		if stashed := wrapper.popStashedConn(); stashed != nil {
			return wrapper.trackConn(stashed)
		}
		resultConn, err := wrapper.dialContext(ctx)
		if err != nil {
			return nil, err
		}
		return wrapper.trackConn(resultConn)
	}

	wrapper.httpTransport = &http.Transport{
		DialContext:         h1DialContext,
		DialTLSContext:      h1DialContext,
		ForceAttemptHTTP2:   false,
		MaxIdleConns:        h1MaxIdleConns,
		MaxIdleConnsPerHost: h1MaxIdleConnsPerHost,
		IdleConnTimeout:     h1IdleConnTimeout,
	}

	return wrapper
}

func (h *HTTPSTransportWrapper) RoundTrip(request *http.Request) (*http.Response, error) {
	// 快速失败检查：如果 Wrapper 已关闭，直接拒绝请求
	select {
	case <-h.closeCtx.Done():
		return nil, net.ErrClosed
	default:
	}

	if h.fallback.Load() {
		// 自动恢复探测：若非明文 HTTP，且距离上次降级已超过冷却时间，尝试切回 H2
		if !h.permanentH1 && h.shouldAttemptRecovery() {
			if h.fallback.CompareAndSwap(true, false) {
				return h.roundTripH2(request)
			}
		}
		return h.httpTransport.RoundTrip(request)
	}
	return h.roundTripH2(request)
}

func (h *HTTPSTransportWrapper) roundTripH2(request *http.Request) (*http.Response, error) {
	response, err := h.http2Transport.RoundTrip(request)
	if err != nil {
		if errors.Is(err, errFallback) {
			// 修复 Body 复用隐患：http2Transport 失败时可能会关闭原始 request.Body，
			// 因此在降级重试前通过 GetBody 重置请求体。
			retryReq := request
			if request.GetBody != nil {
				if newBody, bodyErr := request.GetBody(); bodyErr == nil {
					retryReq = request.Clone(request.Context())
					retryReq.Body = newBody
				}
			}
			return h.httpTransport.RoundTrip(retryReq)
		}
		return nil, err
	}
	return response, nil
}

func (h *HTTPSTransportWrapper) shouldAttemptRecovery() bool {
	lastNano := h.fallbackAtNano.Load()
	if lastNano == 0 {
		return false
	}
	return time.Since(time.Unix(0, lastNano)) >= fallbackRecoveryInterval
}

// dialContext 将单次请求的 ctx 与 Wrapper 的 closeCtx 绑定，确保 Close() 能立即中断正在进行的握手
func (h *HTTPSTransportWrapper) dialContext(ctx context.Context) (net.Conn, error) {
	select {
	case <-h.closeCtx.Done():
		return nil, net.ErrClosed
	default:
	}

	dialCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	// 当 h.closeCtx 被取消时，自动触发 dialCtx 的 cancel()
	stop := context.AfterFunc(h.closeCtx, cancel)
	defer stop()

	return h.dialer.DialContext(dialCtx, N.NetworkTCP, h.serverAddr)
}

func (h *HTTPSTransportWrapper) stashConn(conn net.Conn) {
	h.connAccess.Lock()
	if h.closed {
		h.connAccess.Unlock()
		conn.Close()
		return
	}
	oldStashed := h.stashedConn
	h.stashedConn = conn
	h.connAccess.Unlock()

	if oldStashed != nil {
		oldStashed.Close()
	}
}

func (h *HTTPSTransportWrapper) popStashedConn() net.Conn {
	h.connAccess.Lock()
	defer h.connAccess.Unlock()
	conn := h.stashedConn
	h.stashedConn = nil
	return conn
}

func (h *HTTPSTransportWrapper) trackConn(conn net.Conn) (net.Conn, error) {
	trackedConn := &httpsTrackedConn{Conn: conn, wrapper: h}
	h.connAccess.Lock()
	if h.closed {
		h.connAccess.Unlock()
		conn.Close()
		return nil, net.ErrClosed
	}
	h.connections[trackedConn] = struct{}{}
	h.connAccess.Unlock()
	return trackedConn, nil
}

func (h *HTTPSTransportWrapper) Close() {
	// 1. 立即取消所有正在拨号/握手中的请求
	h.closeCancel()

	// 2. 取出所有活跃连接与暂存连接
	h.connAccess.Lock()
	if h.closed {
		h.connAccess.Unlock()
		return
	}
	h.closed = true
	stashed := h.stashedConn
	h.stashedConn = nil

	connections := make([]*httpsTrackedConn, 0, len(h.connections))
	for trackedConn := range h.connections {
		connections = append(connections, trackedConn)
	}
	h.connections = nil
	h.connAccess.Unlock()

	// 3. 在锁外安全关闭所有连接
	if stashed != nil {
		stashed.Close()
	}
	for _, trackedConn := range connections {
		trackedConn.Close()
	}
	h.CloseIdleConnections()
}

func (h *HTTPSTransportWrapper) CloseIdleConnections() {
	if stashed := h.popStashedConn(); stashed != nil {
		stashed.Close()
	}
	h.http2Transport.CloseIdleConnections()
	h.httpTransport.CloseIdleConnections()
}

type httpsTrackedConn struct {
	net.Conn
	wrapper   *HTTPSTransportWrapper
	closeOnce sync.Once
	closeErr  error
}

// Close 使用 sync.Once 保证幂等，防止 Wrapper.Close() 与 Transport 并发重复关闭底层 FD
func (c *httpsTrackedConn) Close() error {
	c.closeOnce.Do(func() {
		c.wrapper.connAccess.Lock()
		delete(c.wrapper.connections, c)
		c.wrapper.connAccess.Unlock()
		c.closeErr = c.Conn.Close()
	})
	return c.closeErr
}

// Upstream 实现 sing 的 common.WithUpstream 接口，确保底层连接特性（如 TLS 状态、系统 FD）不被遮蔽
func (c *httpsTrackedConn) Upstream() any {
	return c.Conn
}
