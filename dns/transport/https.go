package transport

import (
	"bytes"
	"context"
	"errors"
	"io"
	"mime"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/badhttp"
	"github.com/sagernet/sing-box/common/dialer"
	"github.com/sagernet/sing-box/common/tls"
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

	// DNS 报文理论上限
	maxDNSMessageSize = 65535
	// 非 200 响应最多排空的字节数，便于 HTTP/1.1 连接复用
	maxDrainSize = 4096

	// ExchangeAsync 同时在途的最大查询数，超过则快速失败
	maxAsyncInFlight = 1024

	// 超时自愈策略
	// - 复用连接上超时：连接大概率已失效，立即重置
	// - 新连接上超时：重置也无济于事，连续达到该次数才重置
	timeoutResetThreshold = 3
	// 两次重置的最小间隔，防止调用方超时设置过短导致反复重置
	resetCooldown = 5 * time.Second
	// 优雅重置时，旧 transport 上在途请求的最长等待时间
	drainGrace = 10 * time.Second
)

var ErrTooManyRequests = errors.New("dns over https: too many concurrent async queries")

var (
	_ adapter.DNSTransport         = (*HTTPSTransport)(nil)
	_ adapter.IdleConnectionKeeper = (*HTTPSTransport)(nil)
)

func RegisterHTTPS(registry *dns.TransportRegistry) {
	dns.RegisterTransport[option.RemoteHTTPSDNSServerOptions](registry, C.DNSTypeHTTPS, NewHTTPS)
}

type HTTPSTransport struct {
	dns.TransportAdapter
	logger         logger.ContextLogger
	dialer         N.Dialer
	destination    *url.URL
	destinationURL string
	headers        http.Header
	serverAddr     M.Socksaddr
	fallback       *atomic.Bool
	keepIdle       atomic.Bool

	transportAccess  sync.Mutex
	transport        *HTTPSTransportWrapper
	transportResetAt time.Time

	consecutiveTimeouts atomic.Int32
	asyncSlots          chan struct{}
}

func NewHTTPS(ctx context.Context, contextLogger log.ContextLogger, tag string, options option.RemoteHTTPSDNSServerOptions) (adapter.DNSTransport, error) {
	transportDialer, err := dns.NewRemoteDialer(ctx, options.RemoteDNSServerOptions)
	if err != nil {
		return nil, err
	}
	tlsOptions := common.PtrValueOrDefault(options.TLS)
	tlsOptions.Enabled = true
	tlsConfig, err := tls.NewClient(ctx, contextLogger, options.Server, tlsOptions)
	if err != nil {
		return nil, err
	}
	if len(tlsConfig.NextProtos()) == 0 {
		tlsConfig.SetNextProtos([]string{http2.NextProtoTLS, "http/1.1"})
	}

	headers := options.Headers.Build()
	host := headers.Get("Host")
	if host != "" {
		// Go 的 http 客户端忽略 Header 中的 Host，需要体现在 URL 中
		headers.Del("Host")
	} else if tlsConfig.ServerName() != "" {
		host = tlsConfig.ServerName()
	} else {
		host = options.Server
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
		contextLogger,
		transportDialer,
		&destinationURL,
		headers,
		serverAddr,
		tlsConfig,
	), nil
}

// NewHTTPSRaw 参数名避免遮蔽同名导入包。
func NewHTTPSRaw(
	transportAdapter dns.TransportAdapter,
	contextLogger log.ContextLogger,
	baseDialer N.Dialer,
	destination *url.URL,
	headers http.Header,
	serverAddr M.Socksaddr,
	tlsConfig tls.Config,
) *HTTPSTransport {
	if tlsConfig != nil {
		baseDialer = tls.NewDialer(baseDialer, tlsConfig)
	}
	fallback := new(atomic.Bool)
	if destination.Scheme == "http" {
		// plain HTTP DoH used by Tailscale
		fallback.Store(true)
	}
	transport := &HTTPSTransport{
		TransportAdapter: transportAdapter,
		logger:           contextLogger,
		dialer:           baseDialer,
		destination:      destination,
		destinationURL:   destination.String(),
		headers:          headers,
		serverAddr:       serverAddr,
		fallback:         fallback,
		transport:        NewHTTPSTransportWrapper(baseDialer, serverAddr, fallback),
		asyncSlots:       make(chan struct{}, maxAsyncInFlight),
	}
	transport.keepIdle.Store(true)
	return transport
}

func (t *HTTPSTransport) Start(stage adapter.StartStage, scope *adapter.Scope) error {
	if stage != adapter.StartStateStart {
		return nil
	}
	scope.Add(func() error {
		t.Reset()
		return nil
	})
	return dialer.InitializeDetour(t.dialer)
}

// Reset 硬重置：立即丢弃并关闭所有连接（包括在途请求）。
// 用于外部触发的场景（网络变化、关闭等），此时旧连接已无保留价值。
func (t *HTTPSTransport) Reset() {
	t.transportAccess.Lock()
	oldTransport := t.swapTransportLocked()
	t.transportAccess.Unlock()
	t.consecutiveTimeouts.Store(0)
	oldTransport.Close()
}

func (t *HTTPSTransport) SetKeepIdleConnections(keep bool) {
	t.keepIdle.Store(keep)
	if !keep {
		t.CloseIdleConnections()
	}
}

func (t *HTTPSTransport) CloseIdleConnections() {
	t.transportAccess.Lock()
	current := t.transport
	t.transportAccess.Unlock()
	current.CloseIdleConnections()
}

// swapTransportLocked 必须持有 transportAccess 调用，返回旧 transport，由调用方解锁后处理。
func (t *HTTPSTransport) swapTransportLocked() *HTTPSTransportWrapper {
	oldTransport := t.transport
	t.transport = NewHTTPSTransportWrapper(t.dialer, t.serverAddr, t.fallback)
	t.transportResetAt = time.Now()
	return oldTransport
}

func (t *HTTPSTransport) currentTransport() *HTTPSTransportWrapper {
	t.transportAccess.Lock()
	defer t.transportAccess.Unlock()
	return t.transport
}

func (t *HTTPSTransport) Exchange(ctx context.Context, message *mDNS.Msg) (*mDNS.Msg, error) {
	startAt := time.Now()
	trace := new(requestTrace)
	response, err := t.exchange(ctx, message, trace)
	if !t.keepIdle.Load() {
		t.CloseIdleConnections()
	}
	if err != nil {
		t.handleExchangeError(ctx, startAt, trace, err)
		return nil, err
	}
	if t.consecutiveTimeouts.Load() != 0 {
		t.consecutiveTimeouts.Store(0)
	}
	return response, nil
}

// ExchangeAsync 用信号量限制在途查询数量，超限时快速失败，避免 goroutine 无限增长。
func (t *HTTPSTransport) ExchangeAsync(ctx context.Context, message *mDNS.Msg, callback func(response *mDNS.Msg, err error)) {
	select {
	case t.asyncSlots <- struct{}{}:
	default:
		go callback(nil, ErrTooManyRequests)
		return
	}
	go func() {
		response, err := t.Exchange(ctx, message)
		<-t.asyncSlots // 先释放名额，再执行回调，避免回调耗时占用名额
		callback(response, err)
	}()
}

// handleExchangeError 超时自愈策略。
//
//  1. 只处理超时类错误，取消、EOF、状态码错误等不触发。
//  2. 请求落在"复用连接"上超时：连接大概率已半死，立即重置。
//  3. 请求落在"新连接"（或根本没拿到连接）上超时：服务端慢或不可达，
//     重置没有意义，仅在连续超时达到阈值后才重置。
//  4. 重置有冷却时间，并发请求同时超时只会重置一次。
//  5. 重置是"优雅"的：旧 transport 停止接收空闲连接，等在途请求结束或宽限期后才强制关闭。
func (t *HTTPSTransport) handleExchangeError(ctx context.Context, startAt time.Time, trace *requestTrace, err error) {
	if !isTimeout(err) {
		return
	}
	count := t.consecutiveTimeouts.Add(1)
	reusedConn := trace.reused.Load()
	if !reusedConn && count < timeoutResetThreshold {
		return
	}

	t.transportAccess.Lock()
	if t.transportResetAt.After(startAt) || time.Since(t.transportResetAt) < resetCooldown {
		t.transportAccess.Unlock()
		return
	}
	oldTransport := t.swapTransportLocked()
	t.transportAccess.Unlock()
	t.consecutiveTimeouts.Store(0)

	t.logger.DebugContext(ctx, "dns over https: transport reset after timeout (reused connection: ", reusedConn, ", consecutive timeouts: ", count, ")")
	oldTransport.Shutdown(drainGrace)
}

func isTimeout(err error) bool {
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, os.ErrDeadlineExceeded) {
		return true
	}
	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout()
}

// requestTrace 记录请求是否落在复用连接上。
type requestTrace struct {
	reused atomic.Bool
}

func (r *requestTrace) clientTrace() *httptrace.ClientTrace {
	return &httptrace.ClientTrace{
		GotConn: func(info httptrace.GotConnInfo) {
			r.reused.Store(info.Reused)
		},
	}
}

func (t *HTTPSTransport) exchange(ctx context.Context, message *mDNS.Msg, trace *requestTrace) (*mDNS.Msg, error) {
	// 必须深拷贝：Pack 可能修改共享的 OPT RR，浅拷贝会污染调用方报文
	exMessage := message.Copy()
	exMessage.Id = 0 // RFC 8484：使用 ID 0 以利于 HTTP 缓存
	exMessage.Compress = true

	// 直接 Pack 得到独立切片，不使用对象池：
	// 请求体的生命周期由 HTTP 层决定，独立内存可彻底避免"提前归还缓冲区"的数据竞争，
	// 同时让重试时可以反复使用同一份 payload。
	payload, err := exMessage.Pack()
	if err != nil {
		return nil, err
	}

	response, err := t.roundTrip(ctx, payload, trace)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, maxDrainSize))
		return nil, E.New("unexpected status: ", response.Status)
	}
	return t.readResponse(ctx, response)
}

func (t *HTTPSTransport) roundTrip(ctx context.Context, payload []byte, trace *requestTrace) (*http.Response, error) {
	requestContext := httptrace.WithClientTrace(ctx, trace.clientTrace())
	for attempt := 0; ; attempt++ {
		request, err := http.NewRequestWithContext(requestContext, http.MethodPost, t.destinationURL, bytes.NewReader(payload))
		if err != nil {
			return nil, err
		}
		request.Header = t.headers.Clone()
		request.Header.Set("Content-Type", MimeType)
		request.Header.Set("Accept", MimeType)

		response, err := t.currentTransport().RoundTrip(request)
		// 请求刚好撞上 transport 被替换并关闭：请求尚未发出，重新取新的 transport 重试一次
		if err != nil && attempt == 0 && errors.Is(err, errTransportClosed) {
			continue
		}
		return response, err
	}
}

func (t *HTTPSTransport) readResponse(ctx context.Context, response *http.Response) (*mDNS.Msg, error) {
	if response.ContentLength > maxDNSMessageSize {
		return nil, E.New("response too large: ", response.ContentLength)
	}

	var (
		responseMessage mDNS.Msg
		unpackErr       error
	)
	if response.ContentLength > 0 {
		responseBuffer := buf.NewSize(int(response.ContentLength))
		defer responseBuffer.Release()
		_, err := responseBuffer.ReadFullFrom(response.Body, int(response.ContentLength))
		if err != nil {
			return nil, err
		}
		unpackErr = responseMessage.Unpack(responseBuffer.Bytes())
	} else {
		// 未知长度：多读 1 字节用于检测超限
		body, err := io.ReadAll(io.LimitReader(response.Body, maxDNSMessageSize+1))
		if err != nil {
			return nil, err
		}
		if len(body) > maxDNSMessageSize {
			return nil, E.New("response too large")
		}
		if len(body) == 0 {
			return nil, E.New("empty response")
		}
		unpackErr = responseMessage.Unpack(body)
	}

	// Content-Type 采用"宽松接受 + 失败时诊断"策略：
	// 报文能正常解析就接受（兼容不规范的服务端）；
	// 解析失败且类型不对，则在错误里带上类型，便于识别中间设备返回的 HTML 等。
	contentType := response.Header.Get("Content-Type")
	typeOK := isDNSContentType(contentType)
	if unpackErr != nil {
		if !typeOK {
			return nil, E.Cause(unpackErr, "unexpected content type ", contentType)
		}
		return nil, unpackErr
	}
	if !typeOK {
		t.logger.DebugContext(ctx, "dns over https: non-standard content type: ", contentType)
	}
	return &responseMessage, nil
}

// isDNSContentType 缺失视为合法；有值则按 media type 比较，忽略参数与大小写。
func isDNSContentType(contentType string) bool {
	if contentType == "" {
		return true
	}
	mediaType, _, err := mime.ParseMediaType(contentType)
	if err != nil {
		return false
	}
	return mediaType == MimeType
}
