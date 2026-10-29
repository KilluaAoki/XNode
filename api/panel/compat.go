package panel

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strconv"
	"strings"

	"github.com/KilluaAoki/XNode/common/nlog"
)

// UnmarshalJSON decodes a node config the same way as the panel HTTP and
// WebSocket paths, so v2board-style field names are accepted everywhere.
func (nc *NodeConfig) UnmarshalJSON(data []byte) error {
	var raw map[string]interface{}
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	*nc = NodeConfig{}
	return decodeWeakRaw(raw, nc)
}

// compatDecodeHook rewrites v2board/v2node field names and shapes into the
// ones NodeConfig and CertConfig expect before mapstructure decodes them.
func compatDecodeHook(f, t reflect.Type, v interface{}) (interface{}, error) {
	m, ok := v.(map[string]interface{})
	if !ok || f.Kind() != reflect.Map {
		return v, nil
	}
	for t.Kind() == reflect.Ptr {
		t = t.Elem()
	}
	switch t {
	case reflect.TypeOf(NodeConfig{}):
		return normalizeNodeConfigMap(m), nil
	case reflect.TypeOf(CertConfig{}):
		return normalizeCertConfigMap(m), nil
	}
	return v, nil
}

func normalizeNodeConfigMap(in map[string]interface{}) map[string]interface{} {
	m := make(map[string]interface{}, len(in)+2)
	for k, v := range in {
		m[k] = v
	}
	aliasKey(m, "network_settings", "networkSettings")
	aliasKey(m, "obfs_password", "obfs-password")

	if isEmptyValue(m["decryption"]) {
		if dec := vlessDecryption(m["encryption"], m["encryption_settings"]); dec != "" {
			m["decryption"] = dec
		}
	}
	if isEmptyValue(m["cert_config"]) {
		if cc := certConfigFromTLSSettings(m); cc != nil {
			m["cert_config"] = cc
		}
	}
	return m
}

func normalizeCertConfigMap(in map[string]interface{}) map[string]interface{} {
	m := make(map[string]interface{}, len(in))
	for k, v := range in {
		m[k] = v
	}
	aliasKey(m, "mode", "cert_mode")
	if mode := strings.ToLower(rawString(m["cert_mode"])); mode == "remote" {
		m["cert_mode"] = "content"
	}
	return m
}

func aliasKey(m map[string]interface{}, from, to string) {
	if isEmptyValue(m[to]) && !isEmptyValue(m[from]) {
		m[to] = m[from]
	}
}

func isEmptyValue(v interface{}) bool {
	switch t := v.(type) {
	case nil:
		return true
	case string:
		return strings.TrimSpace(t) == ""
	case map[string]interface{}:
		return len(t) == 0
	case []interface{}:
		return len(t) == 0
	}
	return false
}

func rawString(v interface{}) string {
	if v == nil {
		return ""
	}
	return strings.TrimSpace(fmt.Sprint(v))
}

// vlessDecryption builds the xray VLESS decryption string from v2node's
// encryption + encryption_settings fields.
func vlessDecryption(encryption, settings interface{}) string {
	method := strings.ToLower(rawString(encryption))
	switch method {
	case "", "none":
		return ""
	case "mlkem768x25519plus":
	default:
		nlog.Core().Warn("panel: unsupported vless encryption, ignored", "encryption", method)
		return ""
	}
	es, _ := settings.(map[string]interface{})
	privateKey := rawString(es["private_key"])
	if privateKey == "" {
		nlog.Core().Warn("panel: vless encryption_settings.private_key is empty, encryption ignored")
		return ""
	}
	parts := []string{method, rawString(es["mode"]), rawString(es["ticket"])}
	if padding := rawString(es["server_padding"]); padding != "" {
		parts = append(parts, padding)
	}
	parts = append(parts, privateKey)
	return strings.Join(parts, ".")
}

// certConfigFromTLSSettings maps v2node's tls_settings.cert_mode family to a
// cert_config block. It only applies to TLS nodes without cert_config.
func certConfigFromTLSSettings(m map[string]interface{}) map[string]interface{} {
	if tls, _ := strconv.Atoi(rawString(m["tls"])); tls != 1 {
		return nil
	}
	ts, ok := m["tls_settings"].(map[string]interface{})
	if !ok {
		return nil
	}
	mode := strings.ToLower(rawString(ts["cert_mode"]))
	domain := firstServerName(ts["server_names"], ts["server_name"], m["server_name"])

	switch mode {
	case "", "none":
		return nil
	case "remote", "content":
		cert, key := rawString(ts["tls_cert"]), rawString(ts["tls_key"])
		if cert == "" || key == "" {
			nlog.Core().Warn("panel: tls_settings cert_mode remote has no tls_cert/tls_key, ignored")
			return nil
		}
		return map[string]interface{}{"cert_mode": "content", "domain": domain, "cert_content": cert, "key_content": key}
	case "file":
		certFile, keyFile := rawString(ts["cert_file"]), rawString(ts["key_file"])
		if certFile == "" || keyFile == "" {
			return nil
		}
		return map[string]interface{}{"cert_mode": "file", "domain": domain, "cert_file": certFile, "key_file": keyFile}
	case "self", "http":
		return map[string]interface{}{"cert_mode": mode, "domain": domain}
	case "dns":
		return map[string]interface{}{
			"cert_mode":    "dns",
			"domain":       domain,
			"dns_provider": rawString(ts["provider"]),
			"dns_env":      parseDNSEnv(ts["dns_env"]),
		}
	default:
		nlog.Core().Warn("panel: unsupported tls_settings.cert_mode, ignored", "cert_mode", mode)
		return nil
	}
}

func firstServerName(values ...interface{}) string {
	for _, v := range values {
		switch t := v.(type) {
		case []interface{}:
			for _, item := range t {
				if s := rawString(item); s != "" {
					return s
				}
			}
		default:
			for _, s := range strings.Split(rawString(t), ",") {
				if s = strings.TrimSpace(s); s != "" {
					return s
				}
			}
		}
	}
	return ""
}

// parseDNSEnv accepts "KEY=value,KEY2=value2" or an object.
func parseDNSEnv(v interface{}) map[string]interface{} {
	env := map[string]interface{}{}
	switch t := v.(type) {
	case map[string]interface{}:
		for k, val := range t {
			env[k] = rawString(val)
		}
	case string:
		for _, pair := range strings.Split(t, ",") {
			if k, val, ok := strings.Cut(strings.TrimSpace(pair), "="); ok && strings.TrimSpace(k) != "" {
				env[strings.TrimSpace(k)] = strings.TrimSpace(val)
			}
		}
	}
	return env
}
