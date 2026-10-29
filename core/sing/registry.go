package sing

import (
	"context"

	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/adapter/inbound"
	"github.com/sagernet/sing-box/include"

	"github.com/KilluaAoki/XNode/core/sing/protocol/anytls"
	"github.com/KilluaAoki/XNode/core/sing/protocol/http"
	"github.com/KilluaAoki/XNode/core/sing/protocol/mieru"
	"github.com/KilluaAoki/XNode/core/sing/protocol/naive"
	"github.com/KilluaAoki/XNode/core/sing/protocol/socks"
	"github.com/KilluaAoki/XNode/core/sing/protocol/trojan"
	"github.com/KilluaAoki/XNode/core/sing/protocol/vless"
	"github.com/KilluaAoki/XNode/core/sing/protocol/vmess"
)

func inboundRegistry() *inbound.Registry {
	registry := include.InboundRegistry()
	socks.RegisterInbound(registry)
	http.RegisterInbound(registry)
	vmess.RegisterInbound(registry)
	trojan.RegisterInbound(registry)
	naive.RegisterInbound(registry)
	vless.RegisterInbound(registry)
	anytls.RegisterInbound(registry)
	mieru.RegisterInbound(registry)
	registerQUICInbounds(registry)
	return registry
}

func boxContext(ctx context.Context) context.Context {
	return box.Context(ctx, inboundRegistry(), include.OutboundRegistry(), include.EndpointRegistry(), include.DNSTransportRegistry(), include.ServiceRegistry(), include.CertificateProviderRegistry())
}
