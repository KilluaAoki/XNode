//go:build with_quic

package sing

import (
	"github.com/sagernet/sing-box/adapter/inbound"

	"github.com/KilluaAoki/XNode/core/sing/protocol/hysteria"
	"github.com/KilluaAoki/XNode/core/sing/protocol/hysteria2"
	"github.com/KilluaAoki/XNode/core/sing/protocol/tuic"
)

func registerQUICInbounds(registry *inbound.Registry) {
	hysteria.RegisterInbound(registry)
	hysteria2.RegisterInbound(registry)
	tuic.RegisterInbound(registry)
}
