package sing

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/KilluaAoki/XNode/api/panel"
	"github.com/KilluaAoki/XNode/conf"
	"github.com/KilluaAoki/XNode/core"
	"github.com/sagernet/sing-box/option"
	singJSON "github.com/sagernet/sing/common/json"
)

func TestBuildConfig_SniffRuleFollowsDomainRules(t *testing.T) {
	base := panel.NodeConfig{Protocol: "shadowsocks", ServerPort: 111, Cipher: "aes-128-gcm"}

	cfg := buildConfig(conf.KernelConfig{}, testNodeSpec(&base), testUsers, core.TLSCert{})
	if rules := cfg["route"].(M)["rules"].([]M); rules[0]["action"] == "sniff" {
		t.Fatal("sniff rule should be absent without domain rules")
	}

	withDomain := base
	withDomain.Routes = []panel.RouteRule{{ID: 1, Match: []string{"*.example.com"}, Action: "block"}}
	kcfg := conf.KernelConfig{CustomRoute: []map[string]any{{"ip_cidr": []string{"1.1.1.1/32"}, "outbound": "block"}}}
	cfg = buildConfig(kcfg, testNodeSpec(&withDomain), testUsers, core.TLSCert{})
	rules := cfg["route"].(M)["rules"].([]M)
	if rules[0]["action"] != "sniff" || len(rules[0]) != 1 {
		t.Fatalf("first rule = %v, want sniff", rules[0])
	}

	data, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := singJSON.UnmarshalExtendedContext[option.Options](boxContext(context.Background()), data); err != nil {
		t.Fatalf("parse options: %v", err)
	}
}
