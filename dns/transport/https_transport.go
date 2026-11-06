package transport

import (
	"context"
	stdtls "crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-box/common/tls"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"golang.org/x/net/http2"
)

const (
	// 单次拨号（含 TLS 握手）的上限；上层 ctx 更短时以 ctx 为准
	wrapperDialTimeout = 15 * time.Second
	// 没有任何在途请求后，空闲连接最多保留的时间
	wrapperIdleTimeout = 60 * time.Second
	// h2 健康检查：读空闲超过该时间发 PING，PingTimeout 内无响应则关闭连接
	h2ReadIdleTimeout = 30 * time.Second
	h2PingTimeout     = 10 * time.Second

	h1MaxIdleConns        = 8
	h1MaxIdleConnsPerHost = 4
)

var (
	errFallback = E.New("fallback to HTTP/1.1")
	errUseHTTP2 = errors.New("switch back to HTTP/2")
	// errTransportClosed 表示请求落在了已被关闭的 wrapper 上。
	// DNS 查询幂等，调用方可以换新的 wrapper 安全重试。
	errTransportClosed = fmt.Errorf("dns over https: transport closed: %w", net.ErrClosed)
)

type dialMode int

const (
	dialHTTP2 dialMode = iota // https，期望 ALPN 协商为 h2
	dialHTTP1                 // https，期望 ALPN 不是 h2
	dialPlain                 // 明文 http，不检查 ALPN
)

// HTTPSTransportWrapper 同时持有 HTTP/2 与 HTTP/1.1 transport。
//
// 协议选择：
//   - fallback 是跨 wrapper 共享的"首选协议"提示（true = 先用 HTTP/1.1）。
//   - 每条新连接拨号完成后检查 ALPN 实际协商结果，与当前 transport 不匹配时
//     更新 fallback、丢弃该连接，并用另一个 transport 重试一次，两个方向都能自愈。
//   - scheme 为 http（如 Tailscale 的明文 DoH）固定走 HTTP/1.1，不做 ALPN 检查。
//
// 关闭语义：
//   - CloseIdleConnections：只关闭空闲连接。
//   - Shutdown(grace)：优雅关闭，等在途请求结束或宽限期到后再强制关闭。
//   - Close：立即关闭所有连接，包括在途请求占用的连接。
type HTTPSTransportWrapper struct {
	dialer         N.Dialer
	serverAddr     M.Socksaddr
	fallback       *atomic.Bool
	http2Transport *http2.Transport
	httpTransport  *http.Transport

	access      sync.Mutex
	connections map[*httpsTrackedConn]struct{}
	inflight    int
	closed      bool
	draining    bool
	idleTimer   *time.Timer
	drainTimer  *time.Timer
}

func NewHTTPSTransportWrapper(dialer N.Dialer, serverAddr M.Socksaddr, fallback *atomic.Bool) *HTTPSTransportWrapper {
	wrapper := &HTTPSTransportWrapper{
		dialer:      dialer,
		serverAddr:  serverAddr,
		fallback:    fallback,
		connections: make(map[*httpsTrackedConn]struct{}),
	}
	wrapper.http2Transport = &http2.Transport{
		DialTLSContext: func(ctx context.Context, _, _ string, _ *tls.STDConfig) (net.Conn, error) {
			return wrapper.dial(ctx, dialHTTP2)
		},
		DisableCompression: true,
		ReadIdleTimeout:    h2ReadIdleTimeout,
		PingTimeout:        h2PingTimeout,
	}
	wrapper.httpTransport = &http.Transport{
		// DialContext 只在 http 明文请求时使用
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return wrapper.dial(ctx, dialPlain)
		},
		// DialTLSContext 在 https 请求时使用（拨号器已内置 TLS）
		DialTLSContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return wrapper.dial(ctx, dialHTTP1)
		},
		// 非 nil 的空 map：明确禁止 http.Transport 自带的 h2 升级
		TLSNextProto:        make(map[string]func(string, *stdtls.Conn) http.RoundTripper),
		ForceAttemptHTTP2:   false,
		DisableCompression:  true,
		MaxIdleConns:        h1MaxIdleConns,
		MaxIdleConnsPerHost: h1MaxIdleConnsPerHost,
		IdleConnTimeout:     wrapperIdleTimeout,
	}
	return wrapper
}

// dial 始终连接到 serverAddr（忽略 URL 中的地址），并按模式校验 ALPN。
func (h *HTTPSTransportWrapper) dial(ctx context.Context, mode dialMode) (net.Conn, error) {
	if h.isClosed() {
		return nil, errTransportClosed
	}
	dialCtx, cancel := context.WithTimeout(ctx, wrapperDialTimeout)
	defer cancel()
	conn, err := h.dialer.DialContext(dialCtx, N.NetworkTCP, h.serverAddr)
	if err != nil {
		return nil, err
	}
	if mode != dialPlain {
		if tlsConn, isTLSConn := conn.(tls.Conn); isTLSConn {
			negotiatedHTTP2 := tlsConn.ConnectionState().NegotiatedProtocol == http2.NextProtoTLS
			if negotiatedHTTP2 != (mode == dialHTTP2) {
				_ = conn.Close()
				h.fallback.Store(!negotiatedHTTP2)
				if mode == dialHTTP2 {
					return nil, errFallback
				}
				return nil, errUseHTTP2
			}
		}
	}
	return h.trackConn(conn)
}

func (h *HTTPSTransportWrapper) RoundTrip(request *http.Request) (*http.Response, error) {
	if err := h.beginRequest(); err != nil {
		return nil, err
	}
	response, err := h.roundTrip(request)
	if err != nil {
		h.endRequest()
		// wrapper 被关闭导致的失败（且不是调用方自己取消/超时），统一返回可重试的错误
		if h.isClosed() && request.Context().Err() == nil && !errors.Is(err, errTransportClosed) {
			return nil, fmt.Errorf("%w (%v)", errTransportClosed, err)
		}
		return nil, err
	}
	// 响应体关闭时才算请求结束，用于空闲计时与优雅关闭
	response.Body = &httpsTrackedBody{ReadCloser: response.Body, onClose: h.endRequest}
	return response, nil
}

func (h *HTTPSTransportWrapper) roundTrip(request *http.Request) (*http.Response, error) {
	// 明文 http 固定走 HTTP/1.1
	if request.URL.Scheme != "https" {
		return h.httpTransport.RoundTrip(request)
	}
	useHTTP1 := h.fallback.Load()
	response, err := h.roundTripVia(request, useHTTP1)
	if err == nil {
		return response, nil
	}
	if (useHTTP1 && errors.Is(err, errUseHTTP2)) || (!useHTTP1 && errors.Is(err, errFallback)) {
		// 协商结果与预期不符：fallback 已在 dial 中更新，换另一个协议重试一次
		retry, cloneErr := cloneReplayable(request)
		if cloneErr != nil {
			return nil, err
		}
		return h.roundTripVia(retry, !useHTTP1)
	}
	return nil, err
}

func (h *HTTPSTransportWrapper) roundTripVia(request *http.Request, useHTTP1 bool) (*http.Response, error) {
	if useHTTP1 {
		return h.httpTransport.RoundTrip(request)
	}
	return h.http2Transport.RoundTrip(request)
}

// cloneReplayable 用 GetBody 重建请求体，不依赖第一次尝试后 Body 的状态。
func cloneReplayable(request *http.Request) (*http.Request, error) {
	clone := request.Clone(request.Context())
	if request.Body != nil && request.Body != http.NoBody {
		if request.GetBody == nil {
			return nil, errors.New("dns over https: request body is not replayable")
		}
		body, err := request.GetBody()
		if err != nil {
			return nil, err
		}
		clone.Body = body
	}
	return clone, nil
}

func (h *HTTPSTransportWrapper) isClosed() bool {
	h.access.Lock()
	defer h.access.Unlock()
	return h.closed
}

func (h *HTTPSTransportWrapper) beginRequest() error {
	h.access.Lock()
	defer h.access.Unlock()
	if h.closed {
		return errTransportClosed
	}
	h.inflight++
	if h.idleTimer != nil {
		h.idleTimer.Stop()
		h.idleTimer = nil
	}
	return nil
}

func (h *HTTPSTransportWrapper) endRequest() {
	h.access.Lock()
	h.inflight--
	if h.closed || h.inflight > 0 {
		h.access.Unlock()
		return
	}
	if h.draining {
		h.access.Unlock()
		h.Close()
		return
	}
	// 完全空闲：计时后清理空闲连接（h2 transport 自身没有空闲超时）
	h.idleTimer = time.AfterFunc(wrapperIdleTimeout, h.CloseIdleConnections)
	h.access.Unlock()
}

// CloseIdleConnections 只关闭空闲连接，不影响在途请求。
func (h *HTTPSTransportWrapper) CloseIdleConnections() {
	h.http2Transport.CloseIdleConnections()
	h.httpTransport.CloseIdleConnections()
}

// Shutdown 优雅关闭：立即清理空闲连接，在途请求全部结束或宽限期到后再强制关闭。
func (h *HTTPSTransportWrapper) Shutdown(grace time.Duration) {
	h.access.Lock()
	if h.closed || h.draining {
		h.access.Unlock()
		return
	}
	h.draining = true
	if h.idleTimer != nil {
		h.idleTimer.Stop()
		h.idleTimer = nil
	}
	if h.inflight == 0 {
		h.access.Unlock()
		h.Close()
		return
	}
	h.drainTimer = time.AfterFunc(grace, h.Close)
	h.access.Unlock()
	h.CloseIdleConnections()
}

// Close 立即关闭所有连接，包括被在途请求占用的连接。可重复调用。
func (h *HTTPSTransportWrapper) Close() {
	h.access.Lock()
	if h.closed {
		h.access.Unlock()
		return
	}
	h.closed = true
	if h.idleTimer != nil {
		h.idleTimer.Stop()
		h.idleTimer = nil
	}
	if h.drainTimer != nil {
		h.drainTimer.Stop()
		h.drainTimer = nil
	}
	connections := make([]*httpsTrackedConn, 0, len(h.connections))
	for trackedConn := range h.connections {
		connections = append(connections, trackedConn)
	}
	h.connections = nil
	h.access.Unlock()

	// 锁外关闭，避免与 httpsTrackedConn.Close 的加锁冲突
	for _, trackedConn := range connections {
		_ = trackedConn.Conn.Close()
	}
	h.CloseIdleConnections()
}

func (h *HTTPSTransportWrapper) trackConn(conn net.Conn) (net.Conn, error) {
	trackedConn := &httpsTrackedConn{Conn: conn, wrapper: h}
	h.access.Lock()
	if h.closed {
		h.access.Unlock()
		_ = conn.Close()
		return nil, errTransportClosed
	}
	h.connections[trackedConn] = struct{}{}
	h.access.Unlock()
	return trackedConn, nil
}

func (h *HTTPSTransportWrapper) untrackConn(conn *httpsTrackedConn) {
	h.access.Lock()
	if h.connections != nil {
		delete(h.connections, conn)
	}
	h.access.Unlock()
}

// httpsTrackedConn 登记所有已建立的连接，使 Close 能真正关闭在途连接。
type httpsTrackedConn struct {
	net.Conn
	wrapper *HTTPSTransportWrapper
	once    sync.Once
}

func (c *httpsTrackedConn) Close() error {
	c.once.Do(func() { c.wrapper.untrackConn(c) })
	return c.Conn.Close()
}

// httpsTrackedBody 在响应体关闭时通知 wrapper 请求已结束。
type httpsTrackedBody struct {
	io.ReadCloser
	once    sync.Once
	onClose func()
}

func (b *httpsTrackedBody) Close() error {
	err := b.ReadCloser.Close()
	b.once.Do(b.onClose)
	return err
}
