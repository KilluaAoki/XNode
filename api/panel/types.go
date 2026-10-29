package panel

import (
	"encoding/json"
	"fmt"
	"strings"
)

type StringOrArray string

func (s *StringOrArray) UnmarshalJSON(data []byte) error {
	var str string
	if err := json.Unmarshal(data, &str); err == nil {
		*s = StringOrArray(str)
		return nil
	}
	var arr []string
	if err := json.Unmarshal(data, &arr); err == nil {
		*s = StringOrArray(strings.Join(arr, "\n"))
		return nil
	}
	return fmt.Errorf("StringOrArray: expected string or []string, got %s", string(data))
}

type HandshakeResponse struct {
	WebSocket WSConfig `json:"websocket"`
	Settings  Settings `json:"settings"`
}

func (h *HandshakeResponse) UnmarshalJSON(data []byte) error {
	type Alias HandshakeResponse
	aux := &struct {
		Settings json.RawMessage `json:"settings"`
		*Alias
	}{
		Alias: (*Alias)(h),
	}
	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}
	if len(aux.Settings) > 0 && string(aux.Settings) != "[]" {
		if err := json.Unmarshal(aux.Settings, &h.Settings); err != nil {
			return err
		}
	}
	return nil
}

type WSConfig struct {
	Enabled bool   `json:"enabled"`
	WSURL   string `json:"ws_url,omitempty"`
}

type Settings struct {
	PushInterval int `json:"push_interval"`
	PullInterval int `json:"pull_interval"`
}

type MachineNode struct {
	ID   int    `json:"id"`
	Type string `json:"type"`
	Name string `json:"name"`
}

type MachineNodesResponse struct {
	Nodes      []MachineNode     `json:"nodes"`
	BaseConfig MachineBaseConfig `json:"base_config"`
}

type MachineBaseConfig struct {
	PushInterval int `json:"push_interval"`
	PullInterval int `json:"pull_interval"`
}

type NodeConfig struct {
	NodeID          int                    `json:"node_id,omitempty"`
	Protocol        string                 `json:"protocol"`
	ListenIP        string                 `json:"listen_ip"`
	ServerPort      int                    `json:"server_port"`
	Network         string                 `json:"network"`
	NetworkSettings map[string]interface{} `json:"networkSettings"`
	BaseConfig      BaseConfig             `json:"base_config"`
	Routes          []RouteRule            `json:"routes"`

	KernelType       string            `json:"kernel_type,omitempty"`
	KernelLogLevel   string            `json:"kernel_log_level,omitempty"`
	CustomOutbounds  []OutboundConfig  `json:"custom_outbounds,omitempty"`
	CustomRoutes     []map[string]any  `json:"custom_routes,omitempty"`
	CustomRouteRules []CustomRouteRule `json:"custom_route_rules,omitempty"`

	CertConfig *CertConfig `json:"cert_config,omitempty"`
	AutoTLS    bool        `json:"auto_tls,omitempty"`
	Domain     string      `json:"domain,omitempty"`

	Cipher    string `json:"cipher,omitempty"`
	Plugin    string `json:"plugin,omitempty"`
	PluginOpt string `json:"plugin_opts,omitempty"`
	ServerKey string `json:"server_key,omitempty"`

	TLS         int                    `json:"tls,omitempty"`
	Flow        string                 `json:"flow,omitempty"`
	Decryption  string                 `json:"decryption,omitempty"`
	TLSSettings map[string]interface{} `json:"tls_settings,omitempty"`

	Host       string `json:"host,omitempty"`
	ServerName string `json:"server_name,omitempty"`

	Version      int    `json:"version,omitempty"`
	UpMbps       int    `json:"up_mbps,omitempty"`
	DownMbps     int    `json:"down_mbps,omitempty"`
	Obfs         string `json:"obfs,omitempty"`
	ObfsPassword string `json:"obfs-password,omitempty"`

	CongestionControl string `json:"congestion_control,omitempty"`

	PaddingScheme StringOrArray `json:"padding_scheme,omitempty"`

	Transport      string `json:"transport,omitempty"`
	TrafficPattern string `json:"traffic_pattern,omitempty"`

	Multiplex *MultiplexConfig `json:"multiplex,omitempty"`

	AcceptProxyProtocol bool `json:"accept_proxy_protocol,omitempty"`

	TrustedXForwardedFor  []string `json:"trusted_x_forwarded_for,omitempty"`
	ZeroRTTHandshake      bool     `json:"zero_rtt_handshake,omitempty"`
	IgnoreClientBandwidth bool     `json:"ignore_client_bandwidth,omitempty"`
}

func (nc *NodeConfig) GetProxyProtocol() bool {
	if nc.AcceptProxyProtocol {
		return true
	}
	if nc.NetworkSettings != nil {
		if v, ok := nc.NetworkSettings["acceptProxyProtocol"]; ok {
			if b, ok := v.(bool); ok {
				return b
			}
		}
	}
	return false
}

type MultiplexConfig struct {
	Enabled        bool          `json:"enabled"`
	Protocol       string        `json:"protocol"`
	MaxConnections int           `json:"max_connections"`
	MinStreams     int           `json:"min_streams"`
	MaxStreams     int           `json:"max_streams"`
	Padding        bool          `json:"padding"`
	Brutal         *BrutalConfig `json:"brutal,omitempty"`
}

type BrutalConfig struct {
	Enabled  bool `json:"enabled"`
	UpMbps   int  `json:"up_mbps"`
	DownMbps int  `json:"down_mbps"`
}

type CertConfig struct {
	CertMode    string            `json:"cert_mode"`
	Domain      string            `json:"domain"`
	Email       string            `json:"email"`
	DNSProvider string            `json:"dns_provider"`
	DNSEnv      map[string]string `json:"dns_env"`
	HTTPPort    int               `json:"http_port"`
	CertFile    string            `json:"cert_file"`
	KeyFile     string            `json:"key_file"`
	CertContent string            `json:"cert_content"`
	KeyContent  string            `json:"key_content"`
}

func (c *CertConfig) UnmarshalJSON(data []byte) error {
	type plain CertConfig
	var raw struct {
		plain
		ModeFallback string `json:"mode"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	*c = CertConfig(raw.plain)
	if c.CertMode == "" && raw.ModeFallback != "" {
		c.CertMode = raw.ModeFallback
	}
	if strings.EqualFold(strings.TrimSpace(c.CertMode), "remote") {
		c.CertMode = "content"
	}
	return nil
}

type OutboundConfig struct {
	Tag      string         `json:"tag"`
	Protocol string         `json:"protocol"`
	Settings map[string]any `json:"settings,omitempty"`
	ProxyTag string         `json:"proxy_tag,omitempty"`
}

type BaseConfig struct {
	PushInterval int `json:"push_interval"`
	PullInterval int `json:"pull_interval"`

	// Thresholds in KB, sent by v2board-style panels.
	DeviceOnlineMinTraffic int `json:"device_online_min_traffic,omitempty"`
	NodeReportMinTraffic   int `json:"node_report_min_traffic,omitempty"`
}

type RouteRule struct {
	ID          int      `json:"id"`
	Match       []string `json:"match"`
	Action      string   `json:"action"`
	ActionValue string   `json:"action_value,omitempty"`
}

type CustomRouteRule struct {
	Name     string      `json:"name,omitempty"`
	Disabled bool        `json:"disabled,omitempty"`
	Match    RouteMatch  `json:"match,omitempty"`
	Action   RouteAction `json:"action"`
}

type RouteMatch struct {
	Domains        []string `json:"domains,omitempty"`
	DomainSuffixes []string `json:"domain_suffixes,omitempty"`
	IPCIDRs        []string `json:"ip_cidrs,omitempty"`
	Ports          []string `json:"ports,omitempty"`
	Networks       []string `json:"networks,omitempty"`
	SourceCIDRs    []string `json:"source_cidrs,omitempty"`
	SourcePorts    []string `json:"source_ports,omitempty"`
}

type RouteAction struct {
	Type   string `json:"type"`
	Target string `json:"target,omitempty"`
}

type User struct {
	ID          int    `json:"id"`
	UUID        string `json:"uuid"`
	SpeedLimit  int    `json:"speed_limit"`
	DeviceLimit int    `json:"device_limit"`
}

type UsersResponse struct {
	Users []User `json:"users"`
}
