//go:build with_quic

package sing

import (
	"context"
	"encoding/json"
	"reflect"
	"testing"

	"github.com/sagernet/sing-box/option"
	singJSON "github.com/sagernet/sing/common/json"

	"github.com/KilluaAoki/XNode/api/panel"
	"github.com/KilluaAoki/XNode/conf"
	"github.com/KilluaAoki/XNode/core"
)

// The direct user push must hand the inbound the same users the full config
// path parses out of the generated JSON.
func TestInboundUsersMatchConfig(t *testing.T) {
	cases := []panel.NodeConfig{
		{Protocol: "vmess"},
		{Protocol: "vless"},
		{Protocol: "vless", Flow: "xtls-rprx-vision"},
		{Protocol: "trojan"},
		{Protocol: "shadowsocks", Cipher: "aes-128-gcm"},
		{Protocol: "shadowsocks", Cipher: "2022-blake3-aes-128-gcm", ServerKey: "AAAAAAAAAAAAAAAAAAAAAA=="},
		{Protocol: "shadowsocks", Cipher: "2022-blake3-aes-256-gcm", ServerKey: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="},
		{Protocol: "hysteria", Version: 1, UpMbps: 100, DownMbps: 100},
		{Protocol: "hysteria", Version: 2},
		{Protocol: "tuic"},
		{Protocol: "anytls"},
		{Protocol: "naive"},
		{Protocol: "socks"},
		{Protocol: "http"},
		{Protocol: "mieru", Transport: "TCP"},
	}
	users := reloadUsers(1, 2, 3)
	for _, nc := range cases {
		t.Run(nc.Protocol+nc.Cipher+nc.Flow, func(t *testing.T) {
			nc.ServerPort = 10000
			spec := core.NodeSpecFromPanel(&nc)

			data, err := json.Marshal(buildConfig(conf.KernelConfig{LogLevel: "error"}, spec, users, core.TLSCert{}))
			if err != nil {
				t.Fatal(err)
			}
			opts, err := singJSON.UnmarshalExtendedContext[option.Options](boxContext(context.Background()), data)
			if err != nil {
				t.Fatal(err)
			}
			want, err := optionUsers(opts.Inbounds[0].Options)
			if err != nil {
				t.Fatal(err)
			}
			got, err := inboundUsers(spec, users)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("users differ:\n got %#v\nwant %#v", got, want)
			}
		})
	}
}
