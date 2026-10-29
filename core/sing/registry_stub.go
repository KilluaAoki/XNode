//go:build !with_quic

package sing

import "github.com/sagernet/sing-box/adapter/inbound"

func registerQUICInbounds(*inbound.Registry) {}
