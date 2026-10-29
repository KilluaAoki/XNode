package sing

import (
	"encoding/base64"
	"fmt"
	"strconv"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/auth"

	"github.com/KilluaAoki/XNode/core"
	"github.com/KilluaAoki/XNode/core/sing/protocol"
	"github.com/KilluaAoki/XNode/core/sing/protocol/mieru"
)

// inboundUsers returns the typed user list of nc's inbound, matching what
// buildInbound writes into the config. User-only changes apply it directly
// instead of rebuilding and reparsing the whole configuration.
func inboundUsers(nc *core.NodeSpec, users []core.UserSpec) (any, error) {
	switch nc.Protocol {
	case "shadowsocks":
		list := make([]option.ShadowsocksUser, len(users))
		for i, u := range users {
			list[i] = option.ShadowsocksUser{Name: u.UUID, Password: ssUserPassword(nc.Cipher, u.UUID)}
		}
		return list, nil
	case "vmess":
		list := make([]option.VMessUser, len(users))
		for i, u := range users {
			list[i] = option.VMessUser{Name: u.UUID, UUID: u.UUID}
		}
		return list, nil
	case "vless":
		list := make([]option.VLESSUser, len(users))
		for i, u := range users {
			list[i] = option.VLESSUser{Name: u.UUID, UUID: u.UUID, Flow: nc.Flow}
		}
		return list, nil
	case "trojan":
		list := make([]option.TrojanUser, len(users))
		for i, u := range users {
			list[i] = option.TrojanUser{Name: u.UUID, Password: u.UUID}
		}
		return list, nil
	case "hysteria":
		if nc.Version == 2 {
			list := make([]option.Hysteria2User, len(users))
			for i, u := range users {
				list[i] = option.Hysteria2User{Name: u.UUID, Password: u.UUID}
			}
			return list, nil
		}
		list := make([]option.HysteriaUser, len(users))
		for i, u := range users {
			list[i] = option.HysteriaUser{Name: u.UUID, AuthString: u.UUID}
		}
		return list, nil
	case "tuic":
		list := make([]option.TUICUser, len(users))
		for i, u := range users {
			list[i] = option.TUICUser{Name: u.UUID, UUID: u.UUID, Password: u.UUID}
		}
		return list, nil
	case "anytls":
		list := make([]option.AnyTLSUser, len(users))
		for i, u := range users {
			list[i] = option.AnyTLSUser{Name: u.UUID, Password: u.UUID}
		}
		return list, nil
	case "naive":
		list := make([]auth.User, len(users))
		for i, u := range users {
			list[i] = auth.User{Username: strconv.Itoa(u.ID), Password: u.UUID}
		}
		return list, nil
	case "socks", "http":
		list := make([]auth.User, len(users))
		for i, u := range users {
			list[i] = auth.User{Username: u.UUID, Password: u.UUID}
		}
		return list, nil
	case "mieru":
		list := make([]mieru.User, len(users))
		for i, u := range users {
			list[i] = mieru.User{Name: u.UUID, Password: u.UUID}
		}
		return list, nil
	}
	return nil, fmt.Errorf("protocol %q has no user list", nc.Protocol)
}

// ssUserPassword returns the shadowsocks password of a user. 2022 methods
// take a base64 key of the method's size built from the UUID.
func ssUserPassword(cipher, uuid string) string {
	m, ok := ss2022Methods[cipher]
	if !ok {
		return uuid
	}
	raw := make([]byte, m.size)
	copy(raw, uuid)
	return base64.StdEncoding.EncodeToString(raw)
}

// optionUsers extracts the user list from parsed inbound options.
func optionUsers(options any) (any, error) {
	switch o := options.(type) {
	case *option.VMessInboundOptions:
		return o.Users, nil
	case *option.VLESSInboundOptions:
		return o.Users, nil
	case *option.TrojanInboundOptions:
		return o.Users, nil
	case *option.HysteriaInboundOptions:
		return o.Users, nil
	case *option.Hysteria2InboundOptions:
		return o.Users, nil
	case *option.TUICInboundOptions:
		return o.Users, nil
	case *option.AnyTLSInboundOptions:
		return o.Users, nil
	case *mieru.InboundOptions:
		return o.Users, nil
	case *option.NaiveInboundOptions:
		return o.Users, nil
	case *option.SocksInboundOptions:
		return o.Users, nil
	case *option.HTTPMixedInboundOptions:
		return o.Users, nil
	case *option.ShadowsocksInboundOptions:
		return o.Users, nil
	}
	return nil, fmt.Errorf("%T has no user list", options)
}

// applyUsers replaces the users of a running inbound.
func applyUsers(in adapter.Inbound, users any) error {
	switch list := users.(type) {
	case []option.VMessUser:
		return updateUsers(in, list)
	case []option.VLESSUser:
		return updateUsers(in, list)
	case []option.TrojanUser:
		return updateUsers(in, list)
	case []option.HysteriaUser:
		return updateUsers(in, list)
	case []option.Hysteria2User:
		return updateUsers(in, list)
	case []option.TUICUser:
		return updateUsers(in, list)
	case []option.AnyTLSUser:
		return updateUsers(in, list)
	case []mieru.User:
		return updateUsers(in, list)
	case []auth.User:
		return updateUsers(in, list)
	case []option.ShadowsocksUser:
		m, ok := in.(adapter.ManagedSSMServer)
		if !ok {
			return fmt.Errorf("%s does not support user updates", in.Type())
		}
		names := make([]string, len(list))
		passwords := make([]string, len(list))
		for i, u := range list {
			names[i], passwords[i] = u.Name, u.Password
		}
		return m.UpdateUsers(names, passwords)
	}
	return fmt.Errorf("%s does not support user updates", in.Type())
}

func updateUsers[T any](in adapter.Inbound, users []T) error {
	u, ok := in.(protocol.UserUpdater[T])
	if !ok {
		return fmt.Errorf("%s does not support user updates", in.Type())
	}
	return u.UpdateUsers(users)
}
