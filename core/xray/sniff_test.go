package xray

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/KilluaAoki/XNode/api/panel"
	"github.com/KilluaAoki/XNode/conf"
	"github.com/KilluaAoki/XNode/core"
	"github.com/xtls/xray-core/infra/conf/serial"
)

func TestBuildConfig_SniffingFollowsDomainRules(t *testing.T) {
	base := panel.NodeConfig{Protocol: "shadowsocks", ServerPort: 111, Cipher: "aes-128-gcm"}

	plain := base
	plain.Routes = []panel.RouteRule{{ID: 1, Match: []string{"10.0.0.0/8", "geoip:cn"}, Action: "block"}}
	cfg := buildConfig(conf.KernelConfig{}, testNodeSpec(&plain), testUsers, core.TLSCert{})
	if _, ok := cfg["inbounds"].([]M)[0]["sniffing"]; ok {
		t.Fatal("sniffing should stay off without domain rules")
	}

	withDomain := base
	withDomain.Routes = []panel.RouteRule{{ID: 1, Match: []string{"*.example.com"}, Action: "block"}}
	cfg = buildConfig(conf.KernelConfig{}, testNodeSpec(&withDomain), testUsers, core.TLSCert{})
	sniffing, ok := cfg["inbounds"].([]M)[0]["sniffing"].(M)
	if !ok || sniffing["routeOnly"] != true || sniffing["enabled"] != true {
		t.Fatalf("sniffing = %v", cfg["inbounds"].([]M)[0]["sniffing"])
	}

	data, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := serial.LoadJSONConfig(bytes.NewReader(data)); err != nil {
		t.Fatalf("LoadJSONConfig() error = %v", err)
	}

	raw := conf.KernelConfig{CustomRoute: []map[string]any{{"protocol": []string{"bittorrent"}, "outboundTag": "block"}}}
	cfg = buildConfig(raw, testNodeSpec(&base), testUsers, core.TLSCert{})
	if _, ok := cfg["inbounds"].([]M)[0]["sniffing"]; !ok {
		t.Fatal("protocol rule should enable sniffing")
	}
}
