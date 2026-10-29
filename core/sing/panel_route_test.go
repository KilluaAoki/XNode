package sing

import (
	"context"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/sagernet/sing-box/common/srs"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	singJSON "github.com/sagernet/sing/common/json"

	"github.com/KilluaAoki/XNode/api/panel"
	"github.com/KilluaAoki/XNode/conf"
	"github.com/KilluaAoki/XNode/core"
	"github.com/KilluaAoki/XNode/core/geodata"
)

func writeTestRuleSet(t *testing.T, dir, tag string) {
	t.Helper()
	path := geodata.RuleSetPath(dir, tag)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	ruleSet := option.PlainRuleSet{Rules: []option.HeadlessRule{{
		Type:           C.RuleTypeDefault,
		DefaultOptions: option.DefaultHeadlessRule{DomainSuffix: []string{"example.com"}},
	}}}
	if err := srs.Write(f, ruleSet, C.RuleSetVersionCurrent); err != nil {
		t.Fatal(err)
	}
}

func TestCompilePanelRouteRule_Actions(t *testing.T) {
	routes := testRouteRules([]panel.RouteRule{
		{ID: 1, Match: []string{"example.com"}, Action: "dns", ActionValue: "1.1.1.1"},
		{ID: 2, Match: []string{"example.com"}, Action: "unknown"},
		{ID: 3, Match: []string{"example.com"}, Action: "proxy"},
		{ID: 4, Match: []string{"protocol:bittorrent", "regexp:^ads\\.", "keyword:track", "full:a.com"}, Action: "block"},
		{ID: 5, Match: []string{"25", "465-587"}, Action: "block_port"},
		{ID: 6, Match: []string{"1.2.3.4", "not-an-ip"}, Action: "block_ip"},
		{ID: 7, Match: []string{"geosite:cn"}, Action: "direct"},
	})

	for _, id := range []int{0, 1, 2, 6} {
		if got := compilePanelRouteRule(routes[id], nil); got != nil {
			t.Errorf("route %d: got %v, want no rules", id+1, got)
		}
	}

	got := compilePanelRouteRule(routes[3], nil)
	want := map[string]bool{"domain": true, "domain_keyword": true, "domain_regex": true, "protocol": true}
	if len(got) != len(want) {
		t.Fatalf("route 4 rules: got %v", got)
	}
	for _, r := range got {
		assertMapValue(t, r, "outbound", "block")
		found := false
		for k := range want {
			if _, ok := r[k]; ok {
				found = true
			}
		}
		if !found {
			t.Errorf("unexpected rule %v", r)
		}
	}

	ports := compilePanelRouteRule(routes[4], nil)
	if len(ports) != 1 || len(ports[0]["port"].([]int)) != 1 || ports[0]["port_range"].([]string)[0] != "465:587" {
		t.Errorf("block_port rules: got %v", ports)
	}

	ips := compilePanelRouteRule(routes[5], nil)
	if len(ips) != 1 || ips[0]["ip_cidr"].([]string)[0] != "1.2.3.4/32" {
		t.Errorf("block_ip rules: got %v", ips)
	}
}

func TestSingboxDNSServer(t *testing.T) {
	cases := []struct {
		in   string
		want M
	}{
		{"1.1.1.1", M{"type": "udp", "server": "1.1.1.1"}},
		{"8.8.8.8:5353", M{"type": "udp", "server": "8.8.8.8", "server_port": 5353}},
		{"2606:4700:4700::1111", M{"type": "udp", "server": "2606:4700:4700::1111"}},
		{"tcp://1.1.1.1", M{"type": "tcp", "server": "1.1.1.1"}},
		{"tls://dns.google", M{"type": "tls", "server": "dns.google", "domain_resolver": "local"}},
		{"https://dns.google/dns-query", M{"type": "https", "server": "dns.google", "path": "/dns-query", "domain_resolver": "local"}},
	}
	for _, tc := range cases {
		got, err := singboxDNSServer(tc.in, "dns-1")
		if err != nil {
			t.Fatalf("%s: %v", tc.in, err)
		}
		tc.want["tag"] = "dns-1"
		if len(got) != len(tc.want) {
			t.Errorf("%s: got %v, want %v", tc.in, got, tc.want)
			continue
		}
		for k, v := range tc.want {
			if got[k] != v {
				t.Errorf("%s: %s = %v, want %v", tc.in, k, got[k], v)
			}
		}
	}

	if got, err := singboxDNSServer("localhost", "dns-1"); got != nil || err != nil {
		t.Errorf("localhost: got %v, %v", got, err)
	}
	if _, err := singboxDNSServer("ftp://1.1.1.1", "dns-1"); err == nil {
		t.Error("unsupported scheme should fail")
	}
}

func TestBuildConfig_PanelDNSAndRuleSets(t *testing.T) {
	dir := t.TempDir()
	writeTestRuleSet(t, dir, "geosite-cn")

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	l.Close()

	nc := panel.NodeConfig{
		Protocol:   "shadowsocks",
		ServerPort: port,
		Cipher:     "aes-128-gcm",
		Routes: []panel.RouteRule{
			{ID: 1, Match: []string{"geosite:cn", "example.org"}, Action: "dns", ActionValue: "223.5.5.5"},
			{ID: 2, Match: []string{"google.com"}, Action: "dns", ActionValue: "https://dns.google/dns-query"},
			{ID: 3, Match: []string{"geosite:cn"}, Action: "direct"},
			{ID: 4, Match: []string{"geosite:missing"}, Action: "block"},
		},
	}
	spec := testNodeSpec(&nc)
	spec.ListenIP = "127.0.0.1"
	kcfg := conf.KernelConfig{LogLevel: "error", GeoDataDir: dir}
	cfg := buildConfig(kcfg, spec, testUsers, core.TLSCert{})

	if listen := cfg["inbounds"].([]M)[0]["listen"]; listen != "127.0.0.1" {
		t.Errorf("listen = %v, want 127.0.0.1", listen)
	}
	if _, ok := cfg["experimental"]; ok {
		t.Error("experimental cache_file should not be generated")
	}

	dns := cfg["dns"].(M)
	assertMapValue(t, dns, "final", "local")
	if servers := dns["servers"].([]M); len(servers) != 3 {
		t.Fatalf("dns servers: got %v", servers)
	}
	if rules := dns["rules"].([]M); len(rules) != 3 {
		t.Fatalf("dns rules: got %v", rules)
	}

	route := cfg["route"].(M)
	defs := route["rule_set"].([]M)
	if len(defs) != 1 || defs[0]["tag"] != "geosite-cn" {
		t.Fatalf("rule_set: got %v", defs)
	}
	for _, r := range route["rules"].([]M) {
		if r["outbound"] == "dns-out" {
			t.Fatalf("unexpected dns-out rule %v", r)
		}
	}

	data, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := singJSON.UnmarshalExtendedContext[option.Options](boxContext(context.Background()), data); err != nil {
		t.Fatalf("parse options: %v", err)
	}

	// Drop the missing rule-set route so Start does not try to download it.
	spec.Routes = spec.Routes[:3]
	s := New(kcfg)
	if err := s.Start(spec, testUsers, core.TLSCert{}); err != nil {
		t.Fatalf("start sing-box: %v", err)
	}
	s.Stop()
}

func TestBuildConfig_PanelRouteOutbounds(t *testing.T) {
	nc := panel.NodeConfig{
		Protocol:   "shadowsocks",
		ServerPort: 10086,
		Cipher:     "aes-128-gcm",
		Routes: []panel.RouteRule{
			{ID: 1, Match: []string{"openai.com"}, Action: "route",
				ActionValue: `{"tag":"warp","type":"socks","server":"127.0.0.1","server_port":40000}`},
			{ID: 2, Match: []string{"1.1.1.0/24"}, Action: "route_ip", ActionValue: "warp"},
			{ID: 3, Action: "default_out", ActionValue: `{"tag":"out2","type":"direct"}`},
			{ID: 4, Match: []string{"x.com"}, Action: "route", ActionValue: `{"tag":"xr","protocol":"freedom"}`},
		},
	}
	cfg := buildConfig(conf.KernelConfig{LogLevel: "error"}, testNodeSpec(&nc), testUsers, core.TLSCert{})

	tags := map[string]string{}
	for _, ob := range cfg["outbounds"].([]M) {
		tag, _ := ob["tag"].(string)
		typ, _ := ob["type"].(string)
		tags[tag] = typ
	}
	if tags["warp"] != "socks" || tags["out2"] != "direct" {
		t.Fatalf("outbounds = %v", tags)
	}
	if _, ok := tags["xr"]; ok {
		t.Error("xray-style outbound should be rejected")
	}

	route := cfg["route"].(M)
	assertMapValue(t, route, "final", "out2")
	var domain, ip bool
	for _, r := range route["rules"].([]M) {
		if r["outbound"] == "warp" {
			_, d := r["domain_suffix"]
			_, i := r["ip_cidr"]
			domain, ip = domain || d, ip || i
		}
		if r["outbound"] == "xr" {
			t.Errorf("rule for rejected outbound: %v", r)
		}
	}
	if !domain || !ip {
		t.Errorf("warp rules missing: %v", route["rules"])
	}

	data, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := singJSON.UnmarshalExtendedContext[option.Options](boxContext(context.Background()), data); err != nil {
		t.Fatalf("parse options: %v", err)
	}
}

func TestBuildInbound_V2nodeFlags(t *testing.T) {
	cert := core.TLSCert{CertPEM: []byte("CERT"), KeyPEM: []byte("KEY")}
	hy2 := buildInbound(testNodeSpec(&panel.NodeConfig{
		Protocol: "hysteria", Version: 2, ServerPort: 444, IgnoreClientBandwidth: true,
	}), testUsers, cert)
	assertMapValue(t, hy2, "ignore_client_bandwidth", true)

	tuic := buildInbound(testNodeSpec(&panel.NodeConfig{
		Protocol: "tuic", ServerPort: 555, ZeroRTTHandshake: true,
	}), testUsers, cert)
	assertMapValue(t, tuic, "zero_rtt_handshake", true)
}

func TestBuildInbound_RealityServerNames(t *testing.T) {
	nc := &panel.NodeConfig{
		Protocol:   "vless",
		ServerPort: 443,
		TLS:        2,
		TLSSettings: map[string]interface{}{
			"private_key":  "pk",
			"short_ids":    []interface{}{"ab", "cd"},
			"server_names": []interface{}{"a.example.com", "b.example.com"},
			"dest":         "1.2.3.4:8443",
		},
	}
	tls := buildInbound(testNodeSpec(nc), testUsers, core.TLSCert{})["tls"].(M)
	assertMapValue(t, tls, "server_name", "a.example.com")
	reality := tls["reality"].(M)
	if ids := reality["short_id"].([]string); len(ids) != 2 {
		t.Errorf("short_id = %v", ids)
	}
	handshake := reality["handshake"].(M)
	assertMapValue(t, handshake, "server", "1.2.3.4")
	assertMapValue(t, handshake, "server_port", 8443)
}
