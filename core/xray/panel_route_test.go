package xray

import (
	"bytes"
	"encoding/json"
	"testing"

	xrayCore "github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/infra/conf/serial"

	"github.com/KilluaAoki/XNode/api/panel"
	"github.com/KilluaAoki/XNode/core"
)

func TestCompilePanelRouteRule_Actions(t *testing.T) {
	routes := testRouteRules([]panel.RouteRule{
		{ID: 1, Match: []string{"example.com"}, Action: "dns", ActionValue: "1.1.1.1"},
		{ID: 2, Match: []string{"example.com"}, Action: "unknown"},
		{ID: 3, Match: []string{"example.com"}, Action: "proxy"},
		{ID: 4, Match: []string{"protocol:bittorrent", "regexp:^ads\\.", "keyword:track", "full:a.com", "geosite:cn", "*.b.com"}, Action: "block"},
		{ID: 5, Match: []string{"25", "465-587"}, Action: "block_port"},
		{ID: 6, Match: []string{"1.2.3.4", "geoip:private"}, Action: "block_ip"},
		{ID: 7, Match: []string{"bittorrent"}, Action: "protocol"},
		{ID: 8, Match: []string{"c.com"}, Action: "proxy", ActionValue: "warp"},
	})

	for _, i := range []int{0, 1, 2} {
		if got := compilePanelRouteRule(routes[i]); got != nil {
			t.Errorf("route %d: got %v, want no rules", i+1, got)
		}
	}

	got := compilePanelRouteRule(routes[3])
	if len(got) != 2 {
		t.Fatalf("route 4 rules: got %v", got)
	}
	domains := got[0]["domain"].([]string)
	wantDomains := []string{"full:a.com", "domain:b.com", "keyword:track", "regexp:^ads\\.", "geosite:cn"}
	if len(domains) != len(wantDomains) {
		t.Fatalf("domains = %v, want %v", domains, wantDomains)
	}
	for i := range wantDomains {
		if domains[i] != wantDomains[i] {
			t.Errorf("domains[%d] = %s, want %s", i, domains[i], wantDomains[i])
		}
	}
	if p := got[1]["protocol"].([]string); len(p) != 1 || p[0] != "bittorrent" {
		t.Errorf("protocol = %v", p)
	}

	if got := compilePanelRouteRule(routes[4]); len(got) != 1 || got[0]["port"] != "25,465-587" {
		t.Errorf("block_port rules: got %v", got)
	}
	if got := compilePanelRouteRule(routes[5]); len(got) != 1 || len(got[0]["ip"].([]string)) != 2 {
		t.Errorf("block_ip rules: got %v", got)
	}
	if got := compilePanelRouteRule(routes[6]); len(got) != 1 || got[0]["outboundTag"] != "block" {
		t.Errorf("protocol rules: got %v", got)
	}
	if got := compilePanelRouteRule(routes[7]); len(got) != 1 || got[0]["outboundTag"] != "warp" {
		t.Errorf("proxy rules: got %v", got)
	}
}

func TestBuildConfig_PanelDNS(t *testing.T) {
	nc := panel.NodeConfig{
		Protocol:   "vmess",
		ServerPort: 10086,
		Routes: []panel.RouteRule{
			{ID: 1, Match: []string{"keyword:google", "example.org"}, Action: "dns", ActionValue: "8.8.8.8:53"},
			{ID: 2, Match: []string{"full:a.com"}, Action: "dns", ActionValue: "8.8.8.8:53"},
			{ID: 3, Match: []string{"b.com"}, Action: "dns", ActionValue: "https://dns.google/dns-query"},
			{ID: 4, Match: []string{"c.com"}, Action: "dns"},
		},
	}
	cfg := buildConfig(testKernelCfg, testNodeSpec(&nc), testUsers, core.TLSCert{})

	servers := cfg["dns"].(M)["servers"].([]any)
	if len(servers) != 3 || servers[0] != "localhost" {
		t.Fatalf("dns servers = %v", servers)
	}
	first := servers[1].(M)
	if first["address"] != "8.8.8.8" || first["port"] != 53 || first["skipFallback"] != true {
		t.Errorf("first server = %v", first)
	}
	if d := first["domains"].([]string); len(d) != 3 || d[2] != "full:a.com" {
		t.Errorf("first server domains = %v", d)
	}
	if addr := servers[2].(M)["address"]; addr != "https://dns.google/dns-query" {
		t.Errorf("doh address = %v", addr)
	}

	direct := cfg["outbounds"].([]M)[0]
	if direct["tag"] != "direct" || direct["streamSettings"].(M)["sockopt"].(M)["domainStrategy"] != "UseIPv4v6" {
		t.Errorf("direct outbound = %v", direct)
	}
	for _, r := range cfg["routing"].(M)["rules"].([]M) {
		if r["outboundTag"] != "block" && r["outboundTag"] != "direct" {
			t.Errorf("unexpected routing rule %v", r)
		}
	}

	data, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	pb, err := serial.LoadJSONConfig(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("xray rejected config: %v", err)
	}
	inst, err := xrayCore.New(pb)
	if err != nil {
		t.Fatalf("create xray instance: %v", err)
	}
	inst.Close()
}

func TestBuildConfig_NoPanelDNSKeepsSystemResolver(t *testing.T) {
	nc := panel.NodeConfig{Protocol: "vmess", ServerPort: 10086}
	cfg := buildConfig(testKernelCfg, testNodeSpec(&nc), testUsers, core.TLSCert{})
	if _, ok := cfg["dns"]; ok {
		t.Error("dns block should be absent without panel dns routes")
	}
	if _, ok := cfg["outbounds"].([]M)[0]["streamSettings"]; ok {
		t.Error("direct outbound should keep the default AsIs strategy")
	}
}

func TestBuildConfig_Hysteria2Obfs(t *testing.T) {
	nc := panel.NodeConfig{
		Protocol: "hysteria", Version: 2, ServerPort: 443, UpMbps: 100,
		Obfs: "salamander", ObfsPassword: "secret",
	}
	cfg := buildConfig(testKernelCfg, testNodeSpec(&nc), testUsers, core.TLSCert{})
	ss := cfg["inbounds"].([]M)[0]["streamSettings"].(M)
	mask := ss["finalMask"].(M)
	udp := mask["udp"].([]M)
	if len(udp) != 1 || udp[0]["type"] != "salamander" || udp[0]["settings"].(M)["password"] != "secret" {
		t.Errorf("udp mask = %v", udp)
	}
	if _, ok := mask["quicParams"]; !ok {
		t.Error("quicParams should be kept alongside obfs")
	}

	data, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := serial.LoadJSONConfig(bytes.NewReader(data)); err != nil {
		t.Fatalf("xray rejected config: %v", err)
	}
}
