package panel

import (
	"encoding/json"
	"testing"
)

func decodeTestNodeConfig(t *testing.T, raw string) NodeConfig {
	t.Helper()
	var m map[string]interface{}
	if err := json.Unmarshal([]byte(raw), &m); err != nil {
		t.Fatal(err)
	}
	var nc NodeConfig
	if err := decodeWeakRaw(m, &nc); err != nil {
		t.Fatalf("decode: %v", err)
	}
	var viaJSON NodeConfig
	if err := json.Unmarshal([]byte(raw), &viaJSON); err != nil {
		t.Fatalf("json.Unmarshal: %v", err)
	}
	if viaJSON.Decryption != nc.Decryption || viaJSON.ObfsPassword != nc.ObfsPassword {
		t.Errorf("json.Unmarshal and decodeWeakRaw disagree: %+v vs %+v", viaJSON, nc)
	}
	return nc
}

func TestCompat_V2nodeAliases(t *testing.T) {
	nc := decodeTestNodeConfig(t, `{
		"protocol": "hysteria", "server_port": "443", "version": 2,
		"network_settings": {"path": "/ws"},
		"obfs": "salamander", "obfs_password": "secret",
		"ignore_client_bandwidth": true, "zero_rtt_handshake": true,
		"trusted_x_forwarded_for": ["CF-Connecting-IP"],
		"base_config": {"node_report_min_traffic": "10", "device_online_min_traffic": 5}
	}`)
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
	if nc.BaseConfig.NodeReportMinTraffic != 10 || nc.BaseConfig.DeviceOnlineMinTraffic != 5 {
		t.Errorf("base_config = %+v", nc.BaseConfig)
	}
}

func TestCompat_NativeFieldsWin(t *testing.T) {
	nc := decodeTestNodeConfig(t, `{
		"protocol": "vless", "decryption": "native",
		"encryption": "mlkem768x25519plus",
		"encryption_settings": {"mode": "native", "ticket": "600s", "private_key": "pk"},
		"obfs-password": "native", "obfs_password": "alias"
	}`)
	if nc.Decryption != "native" || nc.ObfsPassword != "native" {
		t.Errorf("decryption = %q, obfs password = %q", nc.Decryption, nc.ObfsPassword)
	}
}

func TestCompat_VLESSEncryption(t *testing.T) {
	cases := map[string]string{
		`{"protocol":"vless","encryption":"mlkem768x25519plus","encryption_settings":{"mode":"native","ticket":"600s","server_padding":"100-111-1111","private_key":"pk"}}`: "mlkem768x25519plus.native.600s.100-111-1111.pk",
		`{"protocol":"vless","encryption":"mlkem768x25519plus","encryption_settings":{"mode":"xorpub","ticket":"0s","private_key":"pk"}}`:                                   "mlkem768x25519plus.xorpub.0s.pk",
		`{"protocol":"vless","encryption":"mlkem768x25519plus","encryption_settings":{"mode":"native"}}`:                                                                    "",
		`{"protocol":"vless","encryption":"none"}`: "",
	}
	for raw, want := range cases {
		if got := decodeTestNodeConfig(t, raw).Decryption; got != want {
			t.Errorf("%s: decryption = %q, want %q", raw, got, want)
		}
	}
}

func TestCompat_CertFromTLSSettings(t *testing.T) {
	nc := decodeTestNodeConfig(t, `{
		"protocol": "trojan", "tls": 1,
		"tls_settings": {"server_names": ["a.example.com"], "cert_mode": "dns", "provider": "cloudflare", "dns_env": "CF_DNS_API_TOKEN=abc, EXTRA=1"}
	}`)
	cc := nc.CertConfig
	if cc == nil || cc.CertMode != "dns" || cc.Domain != "a.example.com" || cc.DNSProvider != "cloudflare" {
		t.Fatalf("cert_config = %+v", cc)
	}
	if cc.DNSEnv["CF_DNS_API_TOKEN"] != "abc" || cc.DNSEnv["EXTRA"] != "1" {
		t.Errorf("dns_env = %v", cc.DNSEnv)
	}

	nc = decodeTestNodeConfig(t, `{
		"protocol": "trojan", "tls": "1", "server_name": "b.example.com",
		"tls_settings": {"cert_mode": "remote", "tls_cert": "CERT", "tls_key": "KEY"}
	}`)
	if cc := nc.CertConfig; cc == nil || cc.CertMode != "content" || cc.Domain != "b.example.com" || cc.CertContent != "CERT" || cc.KeyContent != "KEY" {
		t.Errorf("remote cert_config = %+v", cc)
	}

	for _, raw := range []string{
		`{"protocol":"trojan","tls":1,"tls_settings":{"cert_mode":"none"}}`,
		`{"protocol":"trojan","tls":2,"tls_settings":{"cert_mode":"self"}}`,
		`{"protocol":"trojan","tls":1,"tls_settings":{"cert_mode":"file"}}`,
	} {
		if cc := decodeTestNodeConfig(t, raw).CertConfig; cc != nil {
			t.Errorf("%s: cert_config = %+v, want nil", raw, cc)
		}
	}

	nc = decodeTestNodeConfig(t, `{
		"protocol": "trojan", "tls": 1,
		"cert_config": {"mode": "remote", "cert_content": "C", "key_content": "K"},
		"tls_settings": {"cert_mode": "self"}
	}`)
	if cc := nc.CertConfig; cc == nil || cc.CertMode != "content" || cc.CertContent != "C" {
		t.Errorf("explicit cert_config = %+v", cc)
	}
}
