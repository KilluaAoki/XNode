package conf

import (
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/KilluaAoki/XNode/common/nlog"
	"golang.org/x/term"
	"gopkg.in/yaml.v3"
)

type Config struct {
	InstanceID string            `yaml:"-"`
	Panel      PanelConfig       `yaml:"panel"`
	Node       NodeConfig        `yaml:"node"`
	Kernel     KernelConfig      `yaml:"kernel"`
	Cert       CertConfig        `yaml:"cert"`
	Log        LogConfig         `yaml:"log"`
	Standalone *StandaloneConfig `yaml:"standalone,omitempty"`
	HealthPort int               `yaml:"health_port"`
	Nodes      []NodeEntry       `yaml:"nodes,omitempty"`

	Machine *MachineConfig `yaml:"machine,omitempty"`
}

type MachineConfig struct {
	MachineID int    `yaml:"machine_id"`
	Token     string `yaml:"token"`
	TokenEnv  string `yaml:"token_env,omitempty"`
}

type NodeEntry struct {
	NodeID   int             `yaml:"node_id"`
	NodeType string          `yaml:"node_type,omitempty"`
	Kernel   *KernelOverride `yaml:"kernel,omitempty"`
	Cert     *CertConfig     `yaml:"cert,omitempty"`
}

type KernelOverride struct {
	ConfigDir    string `yaml:"config_dir,omitempty"`
	GeoDataDir   string `yaml:"geo_data_dir,omitempty"`
	LogLevel     string `yaml:"log_level,omitempty"`
	CustomConfig string `yaml:"custom_config,omitempty"`
}

type PanelConfig struct {
	URL      string `yaml:"url"`
	Token    string `yaml:"token"`
	TokenEnv string `yaml:"token_env,omitempty"`
	// NodeID and NodeType identify the node of a config returned by
	// ExpandNodes. In the file they are the legacy single-node form, which
	// loading moves into Nodes.
	NodeID    int    `yaml:"node_id,omitempty"`
	NodeType  string `yaml:"node_type,omitempty"`
	MachineID int    `yaml:"-"`
	// Timeout is the panel HTTP request timeout in seconds.
	Timeout int `yaml:"timeout,omitempty"`
}

type NodeConfig struct {
	PushInterval       int `yaml:"push_interval"`
	PullInterval       int `yaml:"pull_interval"`
	ReportMinTrafficKB int `yaml:"report_min_traffic_kb"`
	// SpeedLimit (Mbps) and DeviceLimit cap every user on the node; the
	// smaller non-zero value of the node and the user limit applies.
	SpeedLimit  int `yaml:"speed_limit,omitempty"`
	DeviceLimit int `yaml:"device_limit,omitempty"`
}

type KernelConfig struct {
	Type      string `yaml:"type"`
	ConfigDir string `yaml:"config_dir"`
	LogLevel  string `yaml:"log_level"`

	GeoDataDir string `yaml:"geo_data_dir"`

	CustomConfig string `yaml:"custom_config"`

	// XrayPolicy overrides xray connection timeouts; unset fields keep the
	// xray defaults.
	XrayPolicy *XrayPolicy `yaml:"xray_policy,omitempty"`
}

// XrayPolicy maps to the xray level-0 policy. Timeouts are in seconds,
// BufferSize in KB.
type XrayPolicy struct {
	Handshake    *int `yaml:"handshake,omitempty"`
	ConnIdle     *int `yaml:"conn_idle,omitempty"`
	UplinkOnly   *int `yaml:"uplink_only,omitempty"`
	DownlinkOnly *int `yaml:"downlink_only,omitempty"`
	BufferSize   *int `yaml:"buffer_size,omitempty"`
}

type CertConfig struct {
	AutoTLS  bool   `yaml:"auto_tls"`
	Domain   string `yaml:"domain"`
	Email    string `yaml:"email"`
	CertFile string `yaml:"cert_file"`
	KeyFile  string `yaml:"key_file"`
	CertDir  string `yaml:"cert_dir"`
	HTTPPort int    `yaml:"http_port"`

	ACMEStorageDir string `yaml:"acme_storage_dir"`

	CertMode string `yaml:"cert_mode"`

	DNSProvider string `yaml:"dns_provider"`

	DNSEnv map[string]string `yaml:"dns_env"`

	CertContent string `yaml:"cert_content,omitempty"`
	KeyContent  string `yaml:"key_content,omitempty"`
}

type LogConfig struct {
	Level  string `yaml:"level"`
	Output string `yaml:"output"`
}

type RootConfig struct {
	Instances []Config `yaml:"instances,omitempty"`
	Config    `yaml:",inline"`
}

func LoadRoot(path string) (*RootConfig, error) {
	rc := &RootConfig{}

	data, err := os.ReadFile(path)
	if err == nil {
		if err := yaml.Unmarshal(data, rc); err != nil {
			return nil, fmt.Errorf("parse config: %w", err)
		}
		if len(rc.Instances) == 0 {
			legacy := &Config{}
			if err := yaml.Unmarshal(data, legacy); err != nil {
				return nil, fmt.Errorf("parse legacy config: %w", err)
			}
			rc.Config = *legacy
		}
	} else if !os.IsNotExist(err) {
		return nil, fmt.Errorf("read config file: %w", err)
	}

	if len(rc.Instances) > 0 {
		for i := range rc.Instances {
			rc.Instances[i].inheritFrom(&rc.Config)
		}
	}

	baseDir := configBaseDir(path)

	rc.MigrateLegacyNodes()
	rc.applyEnvOverrides()
	rc.resolveEnvRefs()

	if err := rc.assignInstanceIDs(); err != nil {
		return nil, err
	}

	rc.setDefaultsFrom(baseDir)

	if err := rc.validateRoot(); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}

	return rc, nil
}

func (rc *RootConfig) applyEnvOverrides() {
	if len(rc.Instances) == 0 {
		rc.Config.applyEnvOverrides()
		return
	}
	for i := range rc.Instances {
		rc.Instances[i].applyEnvOverrides()
	}
}

func (rc *RootConfig) resolveEnvRefs() {
	if len(rc.Instances) == 0 {
		rc.Config.resolveEnvRefs()
		return
	}
	for i := range rc.Instances {
		rc.Instances[i].resolveEnvRefs()
	}
}

func (rc *RootConfig) setDefaultsFrom(baseDir string) {
	if len(rc.Instances) == 0 {
		rc.Config.setDefaultsFrom(baseDir)
		return
	}
	for i := range rc.Instances {
		instBase := baseDir
		if len(rc.Instances) > 1 && rc.Instances[i].Kernel.ConfigDir == "" {
			instBase = filepath.Join(baseDir, rc.Instances[i].InstanceID)
		}
		rc.Instances[i].setDefaultsFrom(instBase)
	}
}

func (rc *RootConfig) assignInstanceIDs() error {
	for i := range rc.Instances {
		if rc.Instances[i].InstanceID != "" {
			continue
		}
		id, err := rc.Instances[i].AutoInstanceID()
		if err != nil {
			return fmt.Errorf("instances[%d]: %w", i, err)
		}
		rc.Instances[i].InstanceID = id
	}
	return nil
}

func configBaseDir(configPath string) string {
	abs, err := filepath.Abs(configPath)
	if err != nil {
		return filepath.Dir(configPath)
	}
	return filepath.Dir(abs)
}

func (rc *RootConfig) validateRoot() error {
	if len(rc.Instances) == 0 {
		return rc.Config.validate()
	}
	seen := map[string]struct{}{}
	for i := range rc.Instances {
		id := rc.Instances[i].InstanceID
		if err := rc.Instances[i].validate(); err != nil {
			return fmt.Errorf("instances[%d]: %w", i, err)
		}
		if _, ok := seen[id]; ok {
			return fmt.Errorf("instances[%d]: duplicate instance id %q", i, id)
		}
		seen[id] = struct{}{}
	}
	return nil
}

func (rc *RootConfig) NormalizeInstances() ([]*Config, error) {
	if len(rc.Instances) == 0 {
		id, err := rc.Config.AutoInstanceID()
		if err != nil {
			return nil, err
		}
		rc.Config.InstanceID = id
		return []*Config{&rc.Config}, nil
	}
	out := make([]*Config, 0, len(rc.Instances))
	for i := range rc.Instances {
		cfg := rc.Instances[i]
		if cfg.InstanceID == "" {
			id, err := cfg.AutoInstanceID()
			if err != nil {
				return nil, err
			}
			cfg.InstanceID = id
		}
		out = append(out, &cfg)
	}
	return out, nil
}

func Load(path string) (*Config, error) {
	cfg := &Config{}

	data, err := os.ReadFile(path)
	if err == nil {
		if err := yaml.Unmarshal(data, cfg); err != nil {
			return nil, fmt.Errorf("parse config: %w", err)
		}
	} else if !os.IsNotExist(err) {
		return nil, fmt.Errorf("read config file: %w", err)
	}

	baseDir := configBaseDir(path)

	cfg.migrateLegacyNode()
	cfg.applyEnvOverrides()
	cfg.resolveEnvRefs()
	cfg.setDefaultsFrom(baseDir)

	if err := cfg.validate(); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}

	return cfg, nil
}

func envFirst(names ...string) string {
	for _, n := range names {
		if v := os.Getenv(n); v != "" {
			return v
		}
	}
	return ""
}

func (c *Config) applyEnvOverrides() {
	if v := envFirst("apiHost", "API_HOST"); v != "" {
		c.Panel.URL = v
	}
	if v := envFirst("apiKey", "API_KEY"); v != "" {
		c.Panel.Token = v
	}
	if v := envFirst("kernel", "KERNEL_TYPE"); v != "" {
		c.Kernel.Type = v
	}
	if v := envFirst("certFile", "CERT_FILE"); v != "" {
		c.Cert.CertFile = v
	}
	if v := envFirst("keyFile", "KEY_FILE"); v != "" {
		c.Cert.KeyFile = v
	}
	if v := envFirst("domain", "DOMAIN"); v != "" {
		c.Cert.Domain = v
		c.Cert.AutoTLS = true
	}
	if v := envFirst("logLevel", "LOG_LEVEL"); v != "" {
		c.Log.Level = v
	}
	if v := envFirst("MACHINE_ID"); v != "" {
		if id, err := strconv.Atoi(v); err == nil {
			if c.Machine == nil {
				c.Machine = &MachineConfig{}
			}
			c.Machine.MachineID = id
		}
	}
	if v := envFirst("MACHINE_TOKEN"); v != "" {
		if c.Machine == nil {
			c.Machine = &MachineConfig{}
		}
		c.Machine.Token = v
	}
	if v := envFirst("nodeID", "NODE_ID"); v != "" {
		if id, err := strconv.Atoi(v); err == nil {
			c.overrideSingleNode(func(n *NodeEntry) { n.NodeID = id })
		}
	}
	if v := envFirst("nodeType", "NODE_TYPE"); v != "" {
		c.overrideSingleNode(func(n *NodeEntry) { n.NodeType = v })
	}
}

// overrideSingleNode applies an environment override to the only node,
// creating it if needed. Multi-node, machine and standalone configs keep
// their file settings.
func (c *Config) overrideSingleNode(set func(*NodeEntry)) {
	if len(c.Nodes) > 1 || c.IsMachineMode() || c.IsStandalone() {
		return
	}
	if len(c.Nodes) == 0 {
		c.Nodes = []NodeEntry{{}}
	}
	set(&c.Nodes[0])
}

func (c *Config) resolveEnvRefs() {
	if c.Panel.Token == "" && c.Panel.TokenEnv != "" {
		c.Panel.Token = os.Getenv(c.Panel.TokenEnv)
	}
	if c.Machine != nil && c.Machine.Token == "" && c.Machine.TokenEnv != "" {
		c.Machine.Token = os.Getenv(c.Machine.TokenEnv)
	}
}

func (c *Config) inheritFrom(parent *Config) {
	if c.Log.Level == "" {
		c.Log.Level = parent.Log.Level
	}
	if c.Log.Output == "" {
		c.Log.Output = parent.Log.Output
	}
	if c.Node.PushInterval == 0 {
		c.Node.PushInterval = parent.Node.PushInterval
	}
	if c.Node.PullInterval == 0 {
		c.Node.PullInterval = parent.Node.PullInterval
	}
	if c.Node.ReportMinTrafficKB == 0 {
		c.Node.ReportMinTrafficKB = parent.Node.ReportMinTrafficKB
	}
	if c.Node.SpeedLimit == 0 {
		c.Node.SpeedLimit = parent.Node.SpeedLimit
	}
	if c.Node.DeviceLimit == 0 {
		c.Node.DeviceLimit = parent.Node.DeviceLimit
	}
	if c.Kernel.Type == "" {
		c.Kernel.Type = parent.Kernel.Type
	}
	if c.Kernel.LogLevel == "" {
		c.Kernel.LogLevel = parent.Kernel.LogLevel
	}
	if c.Kernel.GeoDataDir == "" {
		c.Kernel.GeoDataDir = parent.Kernel.GeoDataDir
	}
	if c.Kernel.CustomConfig == "" {
		c.Kernel.CustomConfig = parent.Kernel.CustomConfig
	}
	if c.Kernel.XrayPolicy == nil {
		c.Kernel.XrayPolicy = parent.Kernel.XrayPolicy
	}
	if c.Cert.CertMode == "" {
		c.Cert.CertMode = parent.Cert.CertMode
	}
	if c.Cert.Domain == "" {
		c.Cert.Domain = parent.Cert.Domain
	}
	if c.Cert.Email == "" {
		c.Cert.Email = parent.Cert.Email
	}
	if c.Cert.CertFile == "" {
		c.Cert.CertFile = parent.Cert.CertFile
	}
	if c.Cert.KeyFile == "" {
		c.Cert.KeyFile = parent.Cert.KeyFile
	}
	if c.Cert.DNSProvider == "" {
		c.Cert.DNSProvider = parent.Cert.DNSProvider
	}
	if len(c.Cert.DNSEnv) == 0 {
		c.Cert.DNSEnv = parent.Cert.DNSEnv
	}
	if c.Cert.HTTPPort == 0 {
		c.Cert.HTTPPort = parent.Cert.HTTPPort
	}
	if c.Cert.CertContent == "" {
		c.Cert.CertContent = parent.Cert.CertContent
	}
	if c.Cert.KeyContent == "" {
		c.Cert.KeyContent = parent.Cert.KeyContent
	}
	childHasCertConfig := c.Cert.CertMode != "" || c.Cert.CertFile != "" || c.Cert.CertContent != ""
	if !childHasCertConfig && !c.Cert.AutoTLS && parent.Cert.AutoTLS {
		c.Cert.AutoTLS = parent.Cert.AutoTLS
	}
}

func (c *Config) setDefaultsFrom(baseDir string) {
	if c.Kernel.Type == "" {
		c.Kernel.Type = "singbox"
	}
	if c.Kernel.ConfigDir == "" {
		c.Kernel.ConfigDir = baseDir
	}
	if c.Kernel.GeoDataDir == "" {
		c.Kernel.GeoDataDir = c.Kernel.ConfigDir
	}
	if c.Kernel.LogLevel == "" {
		c.Kernel.LogLevel = "warn"
	}
	if c.Log.Level == "" {
		c.Log.Level = "info"
	}
	if c.Log.Output == "" {
		c.Log.Output = "stdout"
	}
	if c.Cert.CertDir == "" {
		c.Cert.CertDir = filepath.Join(c.Kernel.ConfigDir, "certs")
	}
	if c.Cert.ACMEStorageDir == "" {
		c.Cert.ACMEStorageDir = filepath.Join(c.Kernel.ConfigDir, "acme")
	}
	if c.Cert.HTTPPort == 0 {
		c.Cert.HTTPPort = 80
	}
}

func (c *Config) IsMachineMode() bool {
	return c.Machine != nil && c.Machine.MachineID > 0
}

func (c *Config) AutoInstanceID() (string, error) {
	mode := "node"
	target := "0"
	baseURL := strings.TrimSpace(c.Panel.URL)
	if c.IsStandalone() {
		mode = "standalone"
		target = "local"
		baseURL = "standalone"
	} else if c.IsMachineMode() {
		mode = "machine"
		target = strconv.Itoa(c.Machine.MachineID)
	} else if len(c.Nodes) > 0 {
		ids := make([]string, len(c.Nodes))
		for i, n := range c.Nodes {
			ids[i] = strconv.Itoa(n.NodeID)
		}
		sort.Strings(ids)
		target = strings.Join(ids, ",")
	} else {
		target = strconv.Itoa(c.Panel.NodeID)
	}
	normalized, slug, err := normalizeBaseURL(baseURL)
	if err != nil {
		return "", err
	}
	key := normalized + "|" + mode + "|" + target
	sum := sha1.Sum([]byte(key))
	short := hex.EncodeToString(sum[:])[:6]
	return fmt.Sprintf("%s-%s-%s-%s", slug, mode, target, short), nil
}

func normalizeBaseURL(raw string) (string, string, error) {
	if raw == "standalone" {
		return raw, raw, nil
	}
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return "", "", fmt.Errorf("invalid panel.url %q: %w", raw, err)
	}
	if u.Scheme == "" || u.Host == "" {
		return "", "", fmt.Errorf("invalid panel.url %q", raw)
	}
	u.Scheme = strings.ToLower(u.Scheme)
	u.Host = strings.ToLower(u.Host)
	u.RawQuery = ""
	u.Fragment = ""
	pathPart := strings.TrimSuffix(u.EscapedPath(), "/")
	normalized := u.Scheme + "://" + u.Host
	if pathPart != "" && pathPart != "/" {
		normalized += pathPart
	}
	slugBase := u.Host
	if pathPart != "" && pathPart != "/" {
		slugBase += "-" + strings.Trim(pathPart, "/")
	}
	slugBase = strings.ToLower(slugBase)
	var b strings.Builder
	lastDash := false
	for _, r := range slugBase {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
			lastDash = false
			continue
		}
		if !lastDash {
			b.WriteByte('-')
			lastDash = true
		}
	}
	slug := strings.Trim(b.String(), "-")
	if slug == "" {
		slug = "panel"
	}
	if len(slug) > 48 {
		slug = strings.Trim(slug[:48], "-")
	}
	return normalized, slug, nil
}

func (c *Config) validate() error {
	if c.IsStandalone() {
		if err := c.validateStandalone(); err != nil {
			return err
		}
	} else if c.IsMachineMode() {
		if c.Panel.URL == "" {
			return fmt.Errorf("panel.url is required")
		}
		if c.Machine.Token == "" {
			return fmt.Errorf("machine.token is required")
		}
		if len(c.Nodes) > 0 {
			return fmt.Errorf("machine mode and nodes: are mutually exclusive")
		}
	} else {
		if c.Panel.URL == "" {
			return fmt.Errorf("panel.url is required")
		}
		if c.Panel.Token == "" {
			return fmt.Errorf("panel.token is required")
		}
		if len(c.Nodes) == 0 {
			return fmt.Errorf("nodes must list at least one node")
		}
		for i, n := range c.Nodes {
			if n.NodeID <= 0 {
				return fmt.Errorf("nodes[%d].node_id must be positive", i)
			}
		}
	}
	switch c.Kernel.Type {
	case "singbox", "xray":
	default:
		return fmt.Errorf("kernel.type must be 'singbox' or 'xray', got '%s'", c.Kernel.Type)
	}
	if c.Cert.AutoTLS && c.Cert.Domain == "" {
		return fmt.Errorf("cert.domain is required when cert.auto_tls is enabled")
	}
	if c.Node.PushInterval < 0 {
		return fmt.Errorf("node.push_interval must not be negative")
	}
	if c.Node.PullInterval < 0 {
		return fmt.Errorf("node.pull_interval must not be negative")
	}
	if c.Node.ReportMinTrafficKB < 0 {
		return fmt.Errorf("node.report_min_traffic_kb must not be negative")
	}
	if c.Node.SpeedLimit < 0 {
		return fmt.Errorf("node.speed_limit must not be negative")
	}
	if c.Node.DeviceLimit < 0 {
		return fmt.Errorf("node.device_limit must not be negative")
	}
	if p := c.Kernel.XrayPolicy; p != nil {
		for name, v := range map[string]*int{
			"handshake": p.Handshake, "conn_idle": p.ConnIdle, "uplink_only": p.UplinkOnly,
			"downlink_only": p.DownlinkOnly, "buffer_size": p.BufferSize,
		} {
			if v != nil && *v < 0 {
				return fmt.Errorf("kernel.xray_policy.%s must not be negative", name)
			}
		}
	}
	if c.Panel.Timeout < 0 {
		return fmt.Errorf("panel.timeout must not be negative")
	}
	return nil
}

func (c *Config) ExpandNodes() []*Config {
	if len(c.Nodes) == 0 {
		return []*Config{c}
	}

	result := make([]*Config, 0, len(c.Nodes))
	for _, entry := range c.Nodes {
		nodeCfg := *c
		nodeCfg.Nodes = nil
		nodeCfg.Panel.NodeID = entry.NodeID
		nodeCfg.Panel.NodeType = entry.NodeType

		if entry.Kernel != nil {
			if entry.Kernel.ConfigDir != "" {
				nodeCfg.Kernel.ConfigDir = entry.Kernel.ConfigDir
				if nodeCfg.Kernel.GeoDataDir == c.Kernel.ConfigDir {
					nodeCfg.Kernel.GeoDataDir = entry.Kernel.ConfigDir
				}
			}
			if entry.Kernel.GeoDataDir != "" {
				nodeCfg.Kernel.GeoDataDir = entry.Kernel.GeoDataDir
			}
			if entry.Kernel.LogLevel != "" {
				nodeCfg.Kernel.LogLevel = entry.Kernel.LogLevel
			}
			if entry.Kernel.CustomConfig != "" {
				nodeCfg.Kernel.CustomConfig = entry.Kernel.CustomConfig
			}
		} else {
			nodeCfg.Kernel.ConfigDir = fmt.Sprintf("%s/node-%d", c.Kernel.ConfigDir, entry.NodeID)
		}

		if entry.Cert != nil {
			nodeCfg.Cert = *entry.Cert
		}
		if nodeCfg.Cert.CertDir == "" {
			nodeCfg.Cert.CertDir = filepath.Join(nodeCfg.Kernel.ConfigDir, "certs")
		}
		if nodeCfg.Cert.ACMEStorageDir == "" {
			nodeCfg.Cert.ACMEStorageDir = c.Cert.ACMEStorageDir
		}

		result = append(result, &nodeCfg)
	}
	return result
}

func (c *Config) ExpandMachineNode(nodeID int, nodeType string) *Config {
	nodeCfg := *c
	nodeCfg.Nodes = nil
	nodeCfg.Panel.NodeID = nodeID
	nodeCfg.Panel.NodeType = nodeType
	nodeCfg.Panel.Token = c.Machine.Token
	nodeCfg.Panel.MachineID = c.Machine.MachineID

	nodeCfg.Kernel.ConfigDir = fmt.Sprintf("%s/node-%d", c.Kernel.ConfigDir, nodeID)
	nodeCfg.Cert.CertDir = filepath.Join(nodeCfg.Kernel.ConfigDir, "certs")

	return &nodeCfg
}

func InitLogger(cfg LogConfig) {
	var minLevel slog.Level
	switch cfg.Level {
	case "debug":
		minLevel = slog.LevelDebug
	case "warn":
		minLevel = slog.LevelWarn
	case "error":
		minLevel = slog.LevelError
	default:
		minLevel = slog.LevelInfo
	}

	var w io.Writer
	useColor := false
	switch cfg.Output {
	case "stdout", "":
		w = os.Stdout
		useColor = term.IsTerminal(int(os.Stdout.Fd()))
	case "stderr":
		w = os.Stderr
		useColor = term.IsTerminal(int(os.Stderr.Fd()))
	default:
		dir := filepath.Dir(cfg.Output)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			fmt.Fprintf(os.Stderr, "failed to create log dir, falling back to stdout: %v\n", err)
			w = os.Stdout
			useColor = term.IsTerminal(int(os.Stdout.Fd()))
		} else {
			f, err := os.OpenFile(cfg.Output, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
			if err != nil {
				fmt.Fprintf(os.Stderr, "failed to open log file, falling back to stdout: %v\n", err)
				w = os.Stdout
				useColor = term.IsTerminal(int(os.Stdout.Fd()))
			} else {
				w = f
				useColor = false
			}
		}
	}

	nlog.Init(w, minLevel, useColor)
	slog.SetDefault(slog.New(slog.DiscardHandler))
}

func ValidateStartupLayout(instances []*Config) error {
	healthPorts := make(map[int]string)
	configDirs := make(map[string]string)
	nodeBindings := make(map[string]string)
	for _, instance := range instances {
		if instance == nil {
			continue
		}
		owner := instance.InstanceID
		if instance.HealthPort > 0 {
			if other, ok := healthPorts[instance.HealthPort]; ok {
				return fmt.Errorf("health_port %d is used by both %s and %s", instance.HealthPort, other, owner)
			}
			healthPorts[instance.HealthPort] = owner
		}
		if dir := strings.TrimSpace(instance.Kernel.ConfigDir); dir != "" {
			if other, ok := configDirs[dir]; ok && other != owner {
				return fmt.Errorf("kernel config_dir %q is shared by %s and %s", dir, other, owner)
			}
			configDirs[dir] = owner
		}
		if instance.IsMachineMode() {
			if path := strings.TrimSpace(instance.Kernel.CustomConfig); path != "" {
				if _, err := os.Stat(path); err != nil {
					return fmt.Errorf("kernel.custom_config %q for %s: %w", path, owner, err)
				}
			}
			continue
		}
		for _, node := range instance.ExpandNodes() {
			binding := fmt.Sprintf("%s/%d", strings.TrimSpace(node.Panel.URL), node.Panel.NodeID)
			if other, ok := nodeBindings[binding]; ok {
				return fmt.Errorf("node binding %s is declared by both %s and %s", binding, other, owner)
			}
			nodeBindings[binding] = owner
			if path := strings.TrimSpace(node.Kernel.CustomConfig); path != "" {
				if _, err := os.Stat(path); err != nil {
					return fmt.Errorf("kernel.custom_config %q for %s: %w", path, owner, err)
				}
			}
		}
	}
	return nil
}
