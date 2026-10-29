package mieru

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/inbound"
	"github.com/sagernet/sing-box/common/uot"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/buf"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	mierucommon "github.com/enfein/mieru/v3/apis/common"
	mieruconstant "github.com/enfein/mieru/v3/apis/constant"
	mierumodel "github.com/enfein/mieru/v3/apis/model"
	mierutp "github.com/enfein/mieru/v3/apis/trafficpattern"
	"github.com/enfein/mieru/v3/pkg/appctl/appctlcommon"
	mierupb "github.com/enfein/mieru/v3/pkg/appctl/appctlpb"
	mieruutil "github.com/enfein/mieru/v3/pkg/common"
	mierulog "github.com/enfein/mieru/v3/pkg/log"
	mieruprotocol "github.com/enfein/mieru/v3/pkg/protocol"
	"google.golang.org/protobuf/proto"
)

const TypeMieru = "mieru"

type InboundOptions struct {
	option.ListenOptions
	Users          []User `json:"users,omitempty"`
	Transport      string `json:"transport,omitempty"`
	TrafficPattern string `json:"traffic_pattern,omitempty"`
}

type User struct {
	Name     string `json:"name,omitempty"`
	Password string `json:"password,omitempty"`
}

var silenceLog sync.Once

func RegisterInbound(registry *inbound.Registry) {
	inbound.Register[InboundOptions](registry, TypeMieru, NewInbound)
}

type Inbound struct {
	inbound.Adapter
	ctx       context.Context
	router    adapter.ConnectionRouterEx
	logger    log.ContextLogger
	listen    option.ListenOptions
	mux       *mieruprotocol.Mux
	closed    chan struct{}
	closeOnce sync.Once
}

func NewInbound(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options InboundOptions) (adapter.Inbound, error) {
	silenceLog.Do(func() { mierulog.SetFormatter(&mierulog.NilFormatter{}) })
	if options.ListenPort == 0 {
		return nil, E.New("listen_port must be set")
	}
	var transport *mierupb.TransportProtocol
	switch strings.ToUpper(options.Transport) {
	case "", "TCP":
		transport = mierupb.TransportProtocol_TCP.Enum()
	case "UDP":
		transport = mierupb.TransportProtocol_UDP.Enum()
	default:
		return nil, E.New("transport must be TCP or UDP")
	}
	pattern, err := mierutp.Decode(options.TrafficPattern)
	if err != nil {
		return nil, fmt.Errorf("decode traffic pattern: %w", err)
	}
	patternConfig, err := mierutp.NewConfig(pattern)
	if err != nil {
		return nil, err
	}
	listenIP := ""
	if options.Listen != nil {
		if addr := options.Listen.Build(netip.Addr{}); addr.IsValid() && !addr.IsUnspecified() {
			listenIP = addr.String()
		}
	}
	endpoints, err := appctlcommon.AddrPortToUnderlayProperties(listenIP, []*mierupb.PortBinding{{
		Port:     proto.Int32(int32(options.ListenPort)),
		Protocol: transport,
	}}, mieruutil.DefaultMTU)
	if err != nil {
		return nil, err
	}
	h := &Inbound{
		Adapter: inbound.NewAdapter(TypeMieru, tag),
		ctx:     ctx,
		router:  uot.NewRouter(router, logger),
		logger:  logger,
		listen:  options.ListenOptions,
		mux:     mieruprotocol.NewMux(false),
		closed:  make(chan struct{}),
	}
	h.mux.SetTrafficPattern(patternConfig).
		SetServerUserHintIsMandatory(false).
		SetServerTCPIdleTimeout(0).
		SetEndpoints(endpoints)
	if err := h.UpdateUsers(options.Users); err != nil {
		return nil, err
	}
	return h, nil
}

func (h *Inbound) UpdateUsers(users []User) error {
	list := make([]*mierupb.User, 0, len(users))
	for _, u := range users {
		pb := &mierupb.User{Name: proto.String(u.Name), Password: proto.String(u.Password)}
		if err := appctlcommon.ValidateServerConfigSingleUser(pb); err != nil {
			return fmt.Errorf("mieru user %q: %w", u.Name, err)
		}
		list = append(list, pb)
	}
	if len(list) == 0 {
		list = append(list, placeholderUser())
	}
	h.mux.SetServerUsers(appctlcommon.UserListToMap(list))
	return nil
}

func placeholderUser() *mierupb.User {
	b := make([]byte, 16)
	rand.Read(b)
	return &mierupb.User{Name: proto.String("_" + hex.EncodeToString(b[:8])), Password: proto.String(hex.EncodeToString(b[8:]))}
}

func (h *Inbound) Start(stage adapter.StartStage, scope *adapter.Scope) error {
	if stage != adapter.StartStateStart {
		return nil
	}
	if err := h.mux.Start(); err != nil {
		return fmt.Errorf("start mieru server: %w", err)
	}
	scope.Add(h.close)
	go h.acceptLoop()
	return nil
}

func (h *Inbound) close() error {
	h.closeOnce.Do(func() { close(h.closed) })
	return h.mux.Close()
}

func (h *Inbound) acceptLoop() {
	for {
		conn, err := h.mux.Accept()
		if err != nil {
			select {
			case <-h.closed:
				return
			default:
			}
			if err == io.EOF || err == io.ErrClosedPipe {
				return
			}
			h.logger.Debug("accept mieru connection: ", err)
			continue
		}
		go h.serve(conn)
	}
}

func (h *Inbound) serve(conn net.Conn) {
	mieruutil.SetReadTimeout(conn, 10*time.Second)
	request := &mierumodel.Request{}
	err := request.ReadFromSocks5(conn)
	mieruutil.SetReadTimeout(conn, 0)
	if err != nil {
		conn.Close()
		h.logger.Debug("read mieru request: ", err)
		return
	}
	h.handleConnection(conn, request)
}

func (h *Inbound) handleConnection(conn net.Conn, request *mierumodel.Request) {
	ctx := log.ContextWithNewID(h.ctx)
	resp := &mierumodel.Response{
		Reply:    mieruconstant.Socks5ReplySuccess,
		BindAddr: mierumodel.AddrSpec{IP: net.IPv4zero},
	}
	if err := resp.WriteToSocks5(conn); err != nil {
		conn.Close()
		h.logger.DebugContext(ctx, "write mieru response: ", err)
		return
	}

	var metadata adapter.InboundContext
	metadata.Inbound = h.Tag()
	metadata.InboundType = h.Type()
	metadata.InboundDetour = h.listen.Detour
	metadata.UDPDisableDomainUnmapping = h.listen.UDPDisableDomainUnmapping
	if remoteAddr := conn.RemoteAddr(); remoteAddr != nil {
		metadata.Source = M.SocksaddrFromNet(remoteAddr)
	}
	metadata.Destination = socksaddr(request.DstAddr)
	if userCtx, ok := conn.(mierucommon.UserContext); ok {
		metadata.User = userCtx.UserName()
	}

	switch request.Command {
	case mieruconstant.Socks5ConnectCmd:
		h.logger.InfoContext(ctx, "[", metadata.User, "] inbound TCP connection from ", metadata.Source, " to ", metadata.Destination)
		h.router.RouteConnectionEx(ctx, conn, metadata, nil)
	case mieruconstant.Socks5UDPAssociateCmd:
		h.logger.InfoContext(ctx, "[", metadata.User, "] inbound UDP connection from ", metadata.Source, " to ", metadata.Destination)
		packetConn := &mieruPacketConn{PacketConn: mierucommon.NewPacketOverStreamTunnel(conn)}
		h.router.RoutePacketConnectionEx(ctx, packetConn, metadata, nil)
	default:
		conn.Close()
		h.logger.WarnContext(ctx, "unsupported mieru command: ", request.Command)
	}
}

func socksaddr(addr mierumodel.AddrSpec) M.Socksaddr {
	if addr.FQDN != "" {
		return M.Socksaddr{Fqdn: addr.FQDN, Port: uint16(addr.Port)}
	}
	if addr.IP != nil {
		ip, _ := netip.AddrFromSlice(addr.IP)
		return M.Socksaddr{Addr: ip.Unmap(), Port: uint16(addr.Port)}
	}
	return M.Socksaddr{}
}

type mieruPacketConn struct {
	net.PacketConn
}

var _ N.PacketConn = (*mieruPacketConn)(nil)

func (c *mieruPacketConn) ReadPacket(buffer *buf.Buffer) (M.Socksaddr, error) {
	n, _, err := c.PacketConn.ReadFrom(buffer.FreeBytes())
	if err != nil {
		return M.Socksaddr{}, err
	}
	buffer.Truncate(n)
	if buffer.Len() < 3 {
		return M.Socksaddr{}, io.ErrShortBuffer
	}
	buffer.Advance(3)
	var addr mierumodel.AddrSpec
	if err := addr.ReadFromSocks5(buffer); err != nil {
		return M.Socksaddr{}, err
	}
	return socksaddr(addr), nil
}

func (c *mieruPacketConn) WritePacket(buffer *buf.Buffer, destination M.Socksaddr) error {
	defer buffer.Release()
	header := buf.NewSize(3 + M.MaxSocksaddrLength)
	defer header.Release()
	common.Must(header.WriteZeroN(3))
	var addr mierumodel.AddrSpec
	if destination.IsFqdn() {
		addr.FQDN = destination.Fqdn
	} else {
		addr.IP = destination.Addr.AsSlice()
	}
	addr.Port = int(destination.Port)
	if err := addr.WriteToSocks5(header); err != nil {
		return err
	}
	packet := buf.NewSize(header.Len() + buffer.Len())
	defer packet.Release()
	common.Must1(packet.Write(header.Bytes()))
	common.Must1(packet.Write(buffer.Bytes()))
	_, err := c.PacketConn.WriteTo(packet.Bytes(), nil)
	return err
}
