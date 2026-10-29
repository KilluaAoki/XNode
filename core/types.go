package core

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/KilluaAoki/XNode/conf"
)

type NodeSpec struct {
	Protocol        string
	ListenIP        string
	ServerPort      int
	Network         string
	NetworkSettings map[string]any
	Routes          []RouteRule

	KernelType       string
	KernelLogLevel   string
	CustomOutbounds  []OutboundConfig
	CustomRoutes     []map[string]any
	CustomRouteRules []CustomRouteRule
	CertConfig       *conf.CertConfig
	AutoTLS          bool
	Domain           string

	Cipher    string
	Plugin    string
	PluginOpt string
	ServerKey string

	TLS         int
	Flow        string
	Decryption  string
	TLSSettings map[string]any

	Host       string
	ServerName string

	Version      int
	UpMbps       int
	DownMbps     int
	Obfs         string
	ObfsPassword string

	CongestionControl string
	PaddingScheme     string
	Transport         string
	TrafficPattern    string

	Multiplex           *MultiplexConfig
	AcceptProxyProtocol bool

	TrustedXForwardedFor  []string
	ZeroRTTHandshake      bool
	IgnoreClientBandwidth bool

	// Panel base_config traffic thresholds in KB.
	NodeReportMinTraffic   int
	DeviceOnlineMinTraffic int
	// Panel base_config push/pull intervals in seconds; 0 when unset.
	PushInterval int
	PullInterval int
}

type OutboundConfig struct {
	Tag      string
	Protocol string
	Settings map[string]any
	ProxyTag string
}

type RouteRule struct {
	ID          int
	Match       []string
	Action      string
	ActionValue string
}

type MultiplexConfig struct {
	Enabled        bool
	Protocol       string
	MaxConnections int
	MinStreams     int
	MaxStreams     int
	Padding        bool
	Brutal         *BrutalConfig
}

type BrutalConfig struct {
	Enabled  bool
	UpMbps   int
	DownMbps int
}

type UserSpec struct {
	ID          int
	UUID        string
	SpeedLimit  int
	DeviceLimit int
}

func (n *NodeSpec) GetProxyProtocol() bool {
	if n == nil {
		return false
	}
	if n.AcceptProxyProtocol {
		return true
	}
	if n.NetworkSettings != nil {
		if v, ok := n.NetworkSettings["acceptProxyProtocol"]; ok {
			if b, ok := v.(bool); ok {
				return b
			}
		}
	}
	return false
}

func cloneAnyMap(src map[string]any) map[string]any {
	if len(src) == 0 {
		return nil
	}
	out := make(map[string]any, len(src))
	for k, v := range src {
		out[k] = v
	}
	return out
}

func cloneMapSlice(src []map[string]any) []map[string]any {
	if len(src) == 0 {
		return nil
	}
	out := make([]map[string]any, 0, len(src))
	for _, item := range src {
		out = append(out, cloneAnyMap(item))
	}
	return out
}

func cloneStringSlice(src []string) []string {
	if len(src) == 0 {
		return nil
	}
	out := make([]string, len(src))
	copy(out, src)
	return out
}

func SettingString(settings map[string]any, key string) string {
	v, ok := settings[key]
	if !ok || v == nil {
		return ""
	}
	return strings.TrimSpace(fmt.Sprint(v))
}

func SettingPort(settings map[string]any, key string) int {
	p, err := strconv.Atoi(SettingString(settings, key))
	if err != nil || p <= 0 || p > 65535 {
		return 0
	}
	return p
}

func RealityShortIDs(v any) []string {
	var raw []string
	switch t := v.(type) {
	case nil:
	case string:
		for _, part := range strings.Split(t, ",") {
			if strings.TrimSpace(part) != "" || !strings.Contains(t, ",") {
				raw = append(raw, part)
			}
		}
	case []string:
		raw = t
	case []any:
		for _, item := range t {
			if item != nil {
				raw = append(raw, fmt.Sprint(item))
			}
		}
	default:
		raw = []string{fmt.Sprint(t)}
	}
	ids := make([]string, 0, len(raw))
	seen := make(map[string]bool, len(raw))
	for _, id := range raw {
		id = strings.TrimSpace(id)
		if !seen[id] {
			seen[id] = true
			ids = append(ids, id)
		}
	}
	if len(ids) == 0 {
		return []string{""}
	}
	return ids
}

// RealityShortIDList prefers tls_settings.short_ids and falls back to short_id.
func RealityShortIDList(settings map[string]any) []string {
	if ids := RealityShortIDs(settings["short_ids"]); len(ids) > 1 || ids[0] != "" {
		return ids
	}
	return RealityShortIDs(settings["short_id"])
}

// RealityServerNames prefers tls_settings.server_names and falls back to
// server_name. Empty and duplicate names are dropped.
func RealityServerNames(settings map[string]any) []string {
	names := settingStrings(settings["server_names"])
	if len(names) == 0 {
		names = settingStrings(settings["server_name"])
	}
	return names
}

// SettingBool reads a panel flag sent as a bool, number or string ("1", "true").
func SettingBool(settings map[string]any, key string) bool {
	switch v := settings[key].(type) {
	case bool:
		return v
	case nil:
		return false
	default:
		s := strings.ToLower(SettingString(settings, key))
		return s == "1" || s == "true" || s == "yes" || s == "on"
	}
}

func settingStrings(v any) []string {
	var raw []string
	switch t := v.(type) {
	case nil:
	case string:
		raw = strings.Split(t, ",")
	case []string:
		raw = t
	case []any:
		for _, item := range t {
			if item != nil {
				raw = append(raw, fmt.Sprint(item))
			}
		}
	default:
		raw = []string{fmt.Sprint(t)}
	}
	out := make([]string, 0, len(raw))
	seen := make(map[string]bool, len(raw))
	for _, s := range raw {
		s = strings.TrimSpace(s)
		if s != "" && !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}
