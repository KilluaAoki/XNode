package xray

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"testing"

	"github.com/xtls/xray-core/infra/conf/serial"

	"github.com/KilluaAoki/XNode/api/panel"
	"github.com/KilluaAoki/XNode/core"
)

func testRealityKey() string {
	return base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32))
}

var testSeed = base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{2}, 32))

func loadXrayConfig(t *testing.T, cfg M) {
	t.Helper()
	data, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := serial.LoadJSONConfig(bytes.NewReader(data)); err != nil {
		t.Fatalf("xray rejected config: %v", err)
	}
}

func TestBuildConfig_RealityV2nodeFields(t *testing.T) {
	nc := panel.NodeConfig{
		Protocol:   "vless",
		ServerPort: 443,
		TLS:        2,
		TLSSettings: map[string]interface{}{
			"private_key":  testRealityKey(),
			"short_ids":    []interface{}{"ab", "cdef"},
			"short_id":     "ignored",
			"server_names": []interface{}{"a.example.com", "b.example.com", "a.example.com"},
			"dest":         "a.example.com:443",
			"xver":         "1",
			"mldsa65Seed":  testSeed,
		},
	}
	cfg := buildConfig(testKernelCfg, testNodeSpec(&nc), testUsers, core.TLSCert{})
	reality := cfg["inbounds"].([]M)[0]["streamSettings"].(M)["realitySettings"].(M)

	if ids := reality["shortIds"].([]string); len(ids) != 2 || ids[0] != "ab" || ids[1] != "cdef" {
		t.Errorf("shortIds = %v", ids)
	}
	if names := reality["serverNames"].([]string); len(names) != 2 || names[1] != "b.example.com" {
		t.Errorf("serverNames = %v", names)
	}
	if reality["xver"] != 1 {
		t.Errorf("xver = %v", reality["xver"])
	}
	if reality["mldsa65Seed"] != testSeed {
		t.Errorf("mldsa65Seed = %v", reality["mldsa65Seed"])
	}
	loadXrayConfig(t, cfg)
}

func TestBuildConfig_TLSRejectUnknownSNIAndTrustedXFF(t *testing.T) {
	nc := panel.NodeConfig{
		Protocol:             "vless",
		ServerPort:           443,
		TLS:                  1,
		Network:              "ws",
		TLSSettings:          map[string]interface{}{"server_name": "a.example.com", "reject_unknown_sni": "1"},
		TrustedXForwardedFor: []string{"CF-Connecting-IP"},
	}
	cfg := buildConfig(testKernelCfg, testNodeSpec(&nc), testUsers, core.TLSCert{})
	ss := cfg["inbounds"].([]M)[0]["streamSettings"].(M)
	if ss["tlsSettings"].(M)["rejectUnknownSni"] != true {
		t.Errorf("tlsSettings = %v", ss["tlsSettings"])
	}
	xff, _ := ss["sockopt"].(M)["trustedXForwardedFor"].([]string)
	if len(xff) != 1 || xff[0] != "CF-Connecting-IP" {
		t.Errorf("sockopt = %v", ss["sockopt"])
	}
	loadXrayConfig(t, cfg)
}

func TestBuildConfig_HysteriaIgnoreClientBandwidth(t *testing.T) {
	nc := panel.NodeConfig{
		Protocol: "hysteria", Version: 2, ServerPort: 443, UpMbps: 100, DownMbps: 100,
		IgnoreClientBandwidth: true,
	}
	cfg := buildConfig(testKernelCfg, testNodeSpec(&nc), testUsers, core.TLSCert{})
	if _, ok := cfg["inbounds"].([]M)[0]["streamSettings"].(M)["finalMask"]; ok {
		t.Error("finalMask.quicParams should be omitted when ignore_client_bandwidth is set")
	}
}

func TestBuildConfig_PanelRouteOutbounds(t *testing.T) {
	nc := panel.NodeConfig{
		Protocol:   "vmess",
		ServerPort: 10086,
		Routes: []panel.RouteRule{
			{ID: 1, Match: []string{"keyword:netflix", "openai.com"}, Action: "route",
				ActionValue: `{"tag":"warp","protocol":"socks","settings":{"servers":[{"address":"127.0.0.1","port":40000}]}}`},
			{ID: 2, Match: []string{"1.1.1.0/24", "not-an-ip"}, Action: "route_ip", ActionValue: "warp"},
			{ID: 3, Action: "default_out", ActionValue: `{"tag":"out2","protocol":"freedom"}`},
			{ID: 4, Action: "default_out", ActionValue: "direct"},
			{ID: 5, Match: []string{"x.com"}, Action: "route", ActionValue: `{"tag":"bad"}`},
			{ID: 6, Match: []string{"y.com"}, Action: "route", ActionValue: `{"tag":"block","protocol":"freedom"}`},
		},
	}
	cfg := buildConfig(testKernelCfg, testNodeSpec(&nc), testUsers, core.TLSCert{})

	outbounds := cfg["outbounds"].([]M)
	byTag := map[string]M{}
	for _, ob := range outbounds {
		tag, _ := ob["tag"].(string)
		if _, dup := byTag[tag]; dup {
			t.Fatalf("duplicate outbound %q", tag)
		}
		byTag[tag] = ob
	}
	if byTag["warp"]["protocol"] != "socks" || byTag["out2"]["protocol"] != "freedom" {
		t.Fatalf("outbounds = %v", outbounds)
	}
	if byTag["block"]["protocol"] != "blackhole" {
		t.Errorf("existing block outbound replaced: %v", byTag["block"])
	}
	if _, ok := byTag["bad"]; ok {
		t.Error("outbound without protocol should be skipped")
	}

	rules := cfg["routing"].(M)["rules"].([]M)
	var domainRule, ipRule M
	for _, r := range rules {
		if r["outboundTag"] != "warp" {
			continue
		}
		if _, ok := r["domain"]; ok {
			domainRule = r
		}
		if _, ok := r["ip"]; ok {
			ipRule = r
		}
	}
	if domainRule == nil || ipRule == nil {
		t.Fatalf("missing warp rules: %v", rules)
	}
	if ips := ipRule["ip"].([]string); len(ips) != 1 || ips[0] != "1.1.1.0/24" {
		t.Errorf("route_ip ips = %v", ips)
	}
	last := rules[len(rules)-1]
	if last["outboundTag"] != "out2" || last["network"] != "tcp,udp" {
		t.Errorf("last rule = %v, want default_out to out2", last)
	}
	loadXrayConfig(t, cfg)
}
