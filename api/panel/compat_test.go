package panel

import (
	"encoding/json"
	"testing"
)

func TestNodeConfigUnmarshalWeakTypes(t *testing.T) {
	raw := `{
		"protocol": "hysteria", "server_port": "443", "version": 2,
		"networkSettings": {"path": "/ws"},
		"obfs": "salamander", "obfs-password": "secret",
		"ignore_client_bandwidth": true, "zero_rtt_handshake": true,
		"trusted_x_forwarded_for": ["CF-Connecting-IP"],
		"cert_config": {"cert_mode": "dns", "domain": "a.example.com", "dns_provider": "cloudflare", "dns_env": {"CF_DNS_API_TOKEN": "abc"}},
		"base_config": {"push_interval": "60", "pull_interval": 30}
	}`
	var nc NodeConfig
	if err := json.Unmarshal([]byte(raw), &nc); err != nil {
		t.Fatalf("json.Unmarshal: %v", err)
	}
	if nc.ServerPort != 443 || nc.Version != 2 {
		t.Errorf("server_port = %d, version = %d", nc.ServerPort, nc.Version)
	}
	if nc.NetworkSettings["path"] != "/ws" {
		t.Errorf("networkSettings = %v", nc.NetworkSettings)
	}
	if nc.ObfsPassword != "secret" {
		t.Errorf("obfs password = %q", nc.ObfsPassword)
	}
	if !nc.IgnoreClientBandwidth || !nc.ZeroRTTHandshake {
		t.Errorf("flags = %v %v", nc.IgnoreClientBandwidth, nc.ZeroRTTHandshake)
	}
	if len(nc.TrustedXForwardedFor) != 1 {
		t.Errorf("trusted_x_forwarded_for = %v", nc.TrustedXForwardedFor)
	}
	if cc := nc.CertConfig; cc == nil || cc.CertMode != "dns" || cc.DNSEnv["CF_DNS_API_TOKEN"] != "abc" {
		t.Errorf("cert_config = %+v", cc)
	}
	if nc.BaseConfig.PushInterval != 60 || nc.BaseConfig.PullInterval != 30 {
		t.Errorf("base_config = %+v", nc.BaseConfig)
	}
}
