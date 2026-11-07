package uot

import (
	"context"
	"net"
	"net/netip"
	"time"

	"github.com/sagernet/sing-box/adapter"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/uot"
)

// uotHandshakeTimeout 限制 UoT 握手请求的读取时间,防止客户端只建立连接而不发送数据。
const uotHandshakeTimeout = 10 * time.Second

var _ adapter.ConnectionRouterEx = (*Router)(nil)

type Router struct {
	router adapter.ConnectionRouterEx
	logger logger.ContextLogger
}

func NewRouter(router adapter.ConnectionRouterEx, logger logger.ContextLogger) *Router {
	return &Router{
		router: router,
		logger: logger,
	}
}

func (r *Router) RouteConnection(ctx context.Context, conn net.Conn, metadata adapter.InboundContext) error {
	if !isUoTDestination(metadata.Destination) {
		return r.router.RouteConnection(ctx, conn, metadata)
	}
	packetConn, newMetadata, err := r.upgrade(ctx, conn, metadata)
	if err != nil {
		return err
	}
	return r.router.RoutePacketConnection(ctx, packetConn, newMetadata)
}

func (r *Router) RoutePacketConnection(ctx context.Context, conn N.PacketConn, metadata adapter.InboundContext) error {
	return r.router.RoutePacketConnection(ctx, conn, metadata)
}

func (r *Router) RouteConnectionEx(ctx context.Context, conn net.Conn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	if !isUoTDestination(metadata.Destination) {
		r.router.RouteConnectionEx(ctx, conn, metadata, onClose)
		return
	}
	packetConn, newMetadata, err := r.upgrade(ctx, conn, metadata)
	if err != nil {
		r.logger.ErrorContext(ctx, "process connection from ", metadata.Source, ": ", err)
		N.CloseOnHandshakeFailure(conn, onClose, err)
		return
	}
	r.router.RoutePacketConnectionEx(ctx, packetConn, newMetadata, onClose)
}

func (r *Router) RoutePacketConnectionEx(ctx context.Context, conn N.PacketConn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	r.router.RoutePacketConnectionEx(ctx, conn, metadata, onClose)
}

// upgrade 将 UoT 连接包装为 PacketConn,并根据握手结果修改路由元数据。
// 调用方需保证 metadata.Destination 是 UoT 魔术地址。
func (r *Router) upgrade(ctx context.Context, conn net.Conn, metadata adapter.InboundContext) (N.PacketConn, adapter.InboundContext, error) {
	if metadata.Destination.Fqdn == uot.LegacyMagicAddress {
		// 旧版协议没有握手请求,目标地址由后续数据包决定。
		r.logger.DebugContext(ctx, "inbound legacy UoT connection from ", metadata.Source)
		metadata.Domain = metadata.Destination.Fqdn
		metadata.Destination = M.Socksaddr{Addr: netip.IPv4Unspecified()}
		return uot.NewConn(conn, uot.Request{}), metadata, nil
	}

	request, err := readUoTRequest(conn)
	if err != nil {
		return nil, metadata, E.Cause(err, "read UoT request")
	}

	if request.IsConnect {
		r.logger.InfoContext(ctx, "inbound UoT connect connection from ", metadata.Source, " to ", request.Destination)
	} else {
		r.logger.InfoContext(ctx, "inbound UoT connection from ", metadata.Source, " to ", request.Destination)
	}
	metadata.Domain = metadata.Destination.Fqdn
	metadata.Destination = request.Destination
	return uot.NewConn(conn, *request), metadata, nil
}

// readUoTRequest 在限定时间内读取握手请求,成功后清除 deadline,
// 避免影响后续的数据传输。
func readUoTRequest(conn net.Conn) (*uot.Request, error) {
	// 并非所有连接类型都支持 deadline,这里忽略设置失败;
	// 若设置失败,握手仍可完成,只是失去超时保护。
	_ = conn.SetReadDeadline(time.Now().Add(uotHandshakeTimeout))

	request, err := uot.ReadRequest(conn)
	if err != nil {
		return nil, err
	}

	_ = conn.SetReadDeadline(time.Time{})
	return request, nil
}

func isUoTDestination(destination M.Socksaddr) bool {
	return destination.Fqdn == uot.MagicAddress || destination.Fqdn == uot.LegacyMagicAddress
}
