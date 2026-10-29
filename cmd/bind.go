package cmd

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/KilluaAoki/XNode/conf"
	"gopkg.in/yaml.v3"
)

type fileRootConfig struct {
	Log       *fileLogConfig    `yaml:"log,omitempty"`
	Kernel    *fileKernelConfig `yaml:"kernel,omitempty"`
	Node      *fileNodeConfig   `yaml:"node,omitempty"`
	Cert      *conf.CertConfig  `yaml:"cert,omitempty"`
	Instances []fileInstance    `yaml:"instances,omitempty"`
}

type fileInstance struct {
	ID         string             `yaml:"id,omitempty"`
	Panel      filePanelConfig    `yaml:"panel"`
	Node       *fileNodeConfig    `yaml:"node,omitempty"`
	Kernel     fileKernelConfig   `yaml:"kernel"`
	Log        fileLogConfig      `yaml:"log"`
	HealthPort int                `yaml:"health_port,omitempty"`
	Machine    *fileMachineConfig `yaml:"machine,omitempty"`
	Standalone map[string]any     `yaml:"standalone,omitempty"`
	Cert       *conf.CertConfig   `yaml:"cert,omitempty"`
	Nodes      []conf.NodeEntry   `yaml:"nodes,omitempty"`
}

type filePanelConfig struct {
	URL      string `yaml:"url"`
	TokenEnv string `yaml:"token_env,omitempty"`
}

type fileMachineConfig struct {
	MachineID int    `yaml:"machine_id"`
	TokenEnv  string `yaml:"token_env,omitempty"`
}

type fileNodeConfig struct {
	PushInterval       int `yaml:"push_interval,omitempty"`
	PullInterval       int `yaml:"pull_interval,omitempty"`
	ReportMinTrafficKB int `yaml:"report_min_traffic_kb,omitempty"`
}

type fileKernelConfig struct {
	Type         string `yaml:"type"`
	ConfigDir    string `yaml:"config_dir"`
	LogLevel     string `yaml:"log_level,omitempty"`
	GeoDataDir   string `yaml:"geo_data_dir,omitempty"`
	CustomConfig string `yaml:"custom_config,omitempty"`
}

type fileLogConfig struct {
	Level  string `yaml:"level,omitempty"`
	Output string `yaml:"output,omitempty"`
}

type instanceSummary struct {
	ID         string `json:"id"`
	PanelURL   string `json:"panel_url"`
	Mode       string `json:"mode"`
	NodeID     *int   `json:"node_id"`
	MachineID  *int   `json:"machine_id"`
	HealthPort int    `json:"health_port"`
}

type installMeta struct {
	ConfigMode       string            `json:"config_mode"`
	Version          string            `json:"version"`
	LatestInstanceID string            `json:"latest_instance_id"`
	InstanceCount    int               `json:"instance_count"`
	Instances        []instanceSummary `json:"instances"`
	UpdatedAt        string            `json:"updated_at"`
}

func loadInstallMeta(path string) (*installMeta, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	meta := &installMeta{}
	if err := json.Unmarshal(data, meta); err != nil {
		return nil, fmt.Errorf("parse install meta: %w", err)
	}
	return meta, nil
}

func parseRemoveNodeArgs(args []string) (string, int, error) {
	var panel string
	var nodeID int
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--panel", "-a", "--api":
			if i+1 >= len(args) {
				return "", 0, errors.New("missing value for --panel")
			}
			panel = args[i+1]
			i++
		case "--node-id", "-n":
			if i+1 >= len(args) {
				return "", 0, errors.New("missing value for --node-id")
			}
			var err error
			nodeID, err = parsePositiveInt(args[i+1], "node-id")
			if err != nil {
				return "", 0, err
			}
			i++
		default:
			return "", 0, fmt.Errorf("unknown remove-node arg: %s", args[i])
		}
	}
	if strings.TrimSpace(panel) == "" || nodeID <= 0 {
		return "", 0, errors.New("usage: xnode bind remove-node --panel URL --node-id ID")
	}
	return strings.TrimSpace(panel), nodeID, nil
}

func parseRemoveMachineArgs(args []string) (string, int, error) {
	var panel string
	var machineID int
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--panel", "-a", "--api":
			if i+1 >= len(args) {
				return "", 0, errors.New("missing value for --panel")
			}
			panel = args[i+1]
			i++
		case "--machine-id":
			if i+1 >= len(args) {
				return "", 0, errors.New("missing value for --machine-id")
			}
			var err error
			machineID, err = parsePositiveInt(args[i+1], "machine-id")
			if err != nil {
				return "", 0, err
			}
			i++
		default:
			return "", 0, fmt.Errorf("unknown remove-machine arg: %s", args[i])
		}
	}
	if strings.TrimSpace(panel) == "" || machineID <= 0 {
		return "", 0, errors.New("usage: xnode bind remove-machine --panel URL --machine-id ID")
	}
	return strings.TrimSpace(panel), machineID, nil
}

func parsePositiveInt(raw string, field string) (int, error) {
	var value int
	_, err := fmt.Sscanf(raw, "%d", &value)
	if err != nil || value <= 0 {
		return 0, fmt.Errorf("invalid %s: %s", field, raw)
	}
	return value, nil
}

func removeBinding(panelURL string, nodeID int, machineID int, instanceID string) error {
	root, err := loadWritableRootConfig(defaultConfigPath)
	if err != nil {
		return err
	}
	instances := normalizeRootInstances(root)
	if len(instances) == 0 {
		return errors.New("no instances configured")
	}

	kept := make([]conf.Config, 0, len(instances))
	removed := make([]conf.Config, 0, 1)
	trimmed := 0
	for _, inst := range instances {
		var matched bool
		if instanceID != "" {
			id, _ := inst.AutoInstanceID()
			matched = id == instanceID || inst.InstanceID == instanceID
		} else {
			matched = strings.TrimSpace(inst.Panel.URL) == strings.TrimSpace(panelURL)
			if nodeID > 0 {
				idx := nodeIndex(inst.Nodes, nodeID)
				matched = matched && !inst.IsMachineMode() && idx >= 0
				// Drop just the node when the instance serves others too,
				// pinning the ID so its directories and credentials stay put.
				if matched && len(inst.Nodes) > 1 {
					if inst.InstanceID == "" {
						inst.InstanceID, _ = inst.AutoInstanceID()
					}
					inst.Nodes = append(inst.Nodes[:idx:idx], inst.Nodes[idx+1:]...)
					kept = append(kept, inst)
					trimmed++
					continue
				}
			}
			if machineID > 0 {
				matched = matched && inst.IsMachineMode() && inst.Machine != nil && inst.Machine.MachineID == machineID
			}
		}
		if matched {
			removed = append(removed, inst)
			continue
		}
		kept = append(kept, inst)
	}
	if len(removed) == 0 && trimmed == 0 {
		if instanceID != "" {
			return fmt.Errorf("binding not found: id=%s", instanceID)
		}
		if nodeID > 0 {
			return fmt.Errorf("binding not found: panel=%s node_id=%d", panelURL, nodeID)
		}
		return fmt.Errorf("binding not found: panel=%s machine_id=%d", panelURL, machineID)
	}
	if len(kept) == 0 {
		root.Instances = nil
		if err := writeRootConfig(defaultConfigPath, root); err != nil {
			return err
		}
		if err := pruneCredentialKeys(defaultCredentialsPath, removed); err != nil {
			return err
		}
		if err := writeInstallMeta(defaultMetaPath, root); err != nil {
			return err
		}
		detectServiceManager().stop()
		fmt.Printf(tr("removed %d binding(s)\n", "已删除 %d 个节点\n"), len(removed))
		fmt.Println(tr("All bindings removed. Service stopped.", "所有节点已删除，服务已停止。"))
		fmt.Println(tr("Use 'xnode install' to add a new binding, or 'xnode uninstall' to fully uninstall.", "使用 xnode install 添加新节点，或使用 xnode uninstall 完全卸载。"))
		return nil
	}

	root.Instances = kept
	if err := writeRootConfig(defaultConfigPath, root); err != nil {
		return err
	}
	if err := pruneCredentialKeys(defaultCredentialsPath, removed); err != nil {
		return err
	}
	if err := writeInstallMeta(defaultMetaPath, root); err != nil {
		return err
	}
	if err := detectServiceManager().restart(); err != nil {
		return err
	}
	fmt.Printf(tr("removed %d binding(s)\n", "已删除 %d 个节点\n"), len(removed)+trimmed)
	return nil
}

func nodeIndex(nodes []conf.NodeEntry, nodeID int) int {
	for i, n := range nodes {
		if n.NodeID == nodeID {
			return i
		}
	}
	return -1
}

func firstNodeID(inst *conf.Config) int {
	if len(inst.Nodes) == 0 {
		return 0
	}
	return inst.Nodes[0].NodeID
}

func loadWritableRootConfig(path string) (*conf.RootConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config file: %w", err)
	}
	rc := &conf.RootConfig{}
	if err := yaml.Unmarshal(data, rc); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	if len(rc.Instances) == 0 {
		legacy := &conf.Config{}
		if err := yaml.Unmarshal(data, legacy); err != nil {
			return nil, fmt.Errorf("parse legacy config: %w", err)
		}
		rc.Config = *legacy
	}
	rc.MigrateLegacyNodes()
	return rc, nil
}

func normalizeRootInstances(root *conf.RootConfig) []conf.Config {
	if len(root.Instances) > 0 {
		return append([]conf.Config(nil), root.Instances...)
	}
	if root.Config.Panel.URL != "" {
		return []conf.Config{root.Config}
	}
	return nil
}

func writeRootConfig(path string, root *conf.RootConfig) error {
	instances := root.Instances
	if len(instances) == 0 && root.Config.Panel.URL != "" {
		instances = []conf.Config{root.Config}
	}
	out := fileRootConfig{Instances: make([]fileInstance, 0, len(instances))}

	p := &root.Config
	if p.Log.Level != "" || p.Log.Output != "" {
		out.Log = &fileLogConfig{Level: p.Log.Level, Output: p.Log.Output}
	}
	if p.Kernel.Type != "" || p.Kernel.LogLevel != "" {
		out.Kernel = &fileKernelConfig{Type: p.Kernel.Type, LogLevel: p.Kernel.LogLevel}
	}
	if p.Node != (conf.NodeConfig{}) {
		out.Node = &fileNodeConfig{
			PushInterval:       p.Node.PushInterval,
			PullInterval:       p.Node.PullInterval,
			ReportMinTrafficKB: p.Node.ReportMinTrafficKB,
		}
	}
	if p.Cert.CertMode != "" || p.Cert.Domain != "" || p.Cert.CertFile != "" || p.Cert.AutoTLS {
		out.Cert = &p.Cert
	}

	for _, inst := range instances {
		fi := fileInstance{
			ID: inst.InstanceID,
			Panel: filePanelConfig{
				URL:      inst.Panel.URL,
				TokenEnv: inst.Panel.TokenEnv,
			},
			Kernel: fileKernelConfig{
				Type:         inst.Kernel.Type,
				ConfigDir:    inst.Kernel.ConfigDir,
				LogLevel:     inst.Kernel.LogLevel,
				GeoDataDir:   inst.Kernel.GeoDataDir,
				CustomConfig: inst.Kernel.CustomConfig,
			},
			Log: fileLogConfig{
				Level:  inst.Log.Level,
				Output: inst.Log.Output,
			},
			HealthPort: inst.HealthPort,
		}
		if !inst.IsMachineMode() && inst.Node != (conf.NodeConfig{}) {
			fi.Node = &fileNodeConfig{
				PushInterval:       inst.Node.PushInterval,
				PullInterval:       inst.Node.PullInterval,
				ReportMinTrafficKB: inst.Node.ReportMinTrafficKB,
			}
		}
		if inst.IsMachineMode() && inst.Machine != nil {
			fi.Machine = &fileMachineConfig{
				MachineID: inst.Machine.MachineID,
				TokenEnv:  inst.Machine.TokenEnv,
			}
		}
		if inst.Cert.CertMode != "" || inst.Cert.Domain != "" || inst.Cert.CertFile != "" || inst.Cert.AutoTLS {
			fi.Cert = &inst.Cert
		}
		if !inst.IsMachineMode() {
			fi.Nodes = inst.Nodes
		}
		out.Instances = append(out.Instances, fi)
	}
	data, err := yaml.Marshal(&out)
	if err != nil {
		return fmt.Errorf("marshal config: %w", err)
	}
	return os.WriteFile(path, data, 0o600)
}

func pruneCredentialKeys(path string, removed []conf.Config) error {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("read credentials: %w", err)
	}
	removeKeys := map[string]struct{}{}
	for _, inst := range removed {
		if env := strings.TrimSpace(inst.Panel.TokenEnv); env != "" {
			removeKeys[env] = struct{}{}
		}
		if inst.Machine != nil {
			if env := strings.TrimSpace(inst.Machine.TokenEnv); env != "" {
				removeKeys[env] = struct{}{}
			}
		}
	}
	lines := strings.Split(string(data), "\n")
	kept := make([]string, 0, len(lines))
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		key := trimmed
		if idx := strings.Index(trimmed, "="); idx >= 0 {
			key = trimmed[:idx]
		}
		if _, ok := removeKeys[key]; ok {
			continue
		}
		kept = append(kept, line)
	}
	output := strings.Join(kept, "\n")
	if output != "" {
		output += "\n"
	}
	return os.WriteFile(path, []byte(output), 0o600)
}

func writeInstallMeta(path string, root *conf.RootConfig) error {
	ver := "unknown"
	if meta, err := loadInstallMeta(path); err == nil && strings.TrimSpace(meta.Version) != "" {
		ver = meta.Version
	}
	return writeInstallMetaVersioned(path, root, ver, "")
}

func instanceMode(inst conf.Config) string {
	if inst.IsMachineMode() {
		return "machine"
	}
	return "node"
}

func intPtr(v int) *int {
	if v <= 0 {
		return nil
	}
	vv := v
	return &vv
}

func latestInstanceID(instances []*conf.Config) string {
	if len(instances) > 0 {
		id, _ := instances[len(instances)-1].AutoInstanceID()
		return id
	}
	return ""
}

func machineIDPtr(cfg *conf.Config) *int {
	if cfg.Machine == nil || cfg.Machine.MachineID <= 0 {
		return nil
	}
	vv := cfg.Machine.MachineID
	return &vv
}

func mergeCredentials(srcPath, dstPath, key, value string) error {
	entries := make(map[string]string)
	var order []string
	if srcPath != "" {
		data, err := os.ReadFile(srcPath)
		if err == nil {
			for _, raw := range strings.Split(string(data), "\n") {
				line := strings.TrimSpace(raw)
				if line == "" || strings.HasPrefix(line, "#") || !strings.Contains(line, "=") {
					continue
				}
				k, v, _ := strings.Cut(line, "=")
				if _, exists := entries[k]; !exists {
					order = append(order, k)
				}
				entries[k] = v
			}
		}
	}
	if _, exists := entries[key]; !exists {
		order = append(order, key)
	}
	entries[key] = value

	var buf strings.Builder
	for _, k := range order {
		fmt.Fprintf(&buf, "%s=%s\n", k, entries[k])
	}
	return os.WriteFile(dstPath, []byte(buf.String()), 0o600)
}

func writeInstallMetaVersioned(path string, root *conf.RootConfig, ver, latestID string) error {
	if ver == "" {
		ver = "unknown"
	}
	instances := normalizeRootInstances(root)
	items := make([]instanceSummary, 0, len(instances))
	for _, inst := range instances {
		id, err := inst.AutoInstanceID()
		if err != nil {
			return err
		}
		if latestID == "" {
			latestID = id
		}
		item := instanceSummary{
			ID:         id,
			PanelURL:   inst.Panel.URL,
			Mode:       instanceMode(inst),
			NodeID:     intPtr(firstNodeID(&inst)),
			MachineID:  machineIDPtr(&inst),
			HealthPort: inst.HealthPort,
		}
		if item.Mode == "machine" {
			item.NodeID = nil
		}
		items = append(items, item)
	}
	meta := installMeta{
		ConfigMode:       "instances",
		Version:          ver,
		LatestInstanceID: latestID,
		InstanceCount:    len(items),
		Instances:        items,
		UpdatedAt:        time.Now().UTC().Format("2006-01-02T15:04:05Z"),
	}
	data, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal install meta: %w", err)
	}
	data = append(data, '\n')
	return os.WriteFile(path, data, 0o644)
}

type bindOptions struct {
	mode       string
	panelURL   string
	token      string
	nodeID     int
	nodeType   string
	machineID  int
	kernel     string
	healthPort int
}

func (o *bindOptions) register(fs *flag.FlagSet) {
	for _, n := range []string{"panel", "panel-url", "api", "a"} {
		fs.StringVar(&o.panelURL, n, "", "panel URL")
	}
	for _, n := range []string{"token", "t"} {
		fs.StringVar(&o.token, n, "", "panel token")
	}
	for _, n := range []string{"node-id", "n"} {
		fs.IntVar(&o.nodeID, n, 0, "node ID")
	}
	for _, n := range []string{"node-type", "T"} {
		fs.StringVar(&o.nodeType, n, "", "node type")
	}
	fs.IntVar(&o.machineID, "machine-id", 0, "machine ID")
	for _, n := range []string{"kernel", "k"} {
		fs.StringVar(&o.kernel, n, "singbox", "kernel: singbox or xray")
	}
	fs.StringVar(&o.mode, "mode", "", "node or machine")
	fs.IntVar(&o.healthPort, "health-port", defaultHealthPort, "local health port, 0 disables")
}

func (o *bindOptions) normalize() error {
	o.panelURL = strings.TrimRight(strings.TrimSpace(o.panelURL), "/")
	o.token = strings.TrimSpace(o.token)
	o.nodeType = canonicalNodeType(o.nodeType)
	switch strings.ToLower(strings.TrimSpace(o.kernel)) {
	case "", "singbox", "sing-box", "sing":
		o.kernel = "singbox"
	case "xray":
		o.kernel = "xray"
	default:
		return fmt.Errorf("kernel must be singbox or xray, got %q", o.kernel)
	}
	if o.mode == "" {
		o.mode = "node"
		if o.machineID > 0 {
			o.mode = "machine"
		}
	}
	switch {
	case o.mode != "node" && o.mode != "machine":
		return fmt.Errorf("mode must be node or machine, got %q", o.mode)
	case o.panelURL == "":
		return errors.New("--panel is required")
	case o.token == "":
		return errors.New("--token is required")
	case o.mode == "node" && o.nodeID <= 0:
		return errors.New("--node-id is required for node mode")
	case o.mode == "machine" && o.machineID <= 0:
		return errors.New("--machine-id is required for machine mode")
	case o.healthPort < 0 || o.healthPort > 65535:
		return fmt.Errorf("invalid --health-port: %d", o.healthPort)
	}
	return nil
}

func bindInstance(o bindOptions) (string, error) {
	inst := conf.Config{
		Panel:      conf.PanelConfig{URL: o.panelURL},
		Kernel:     conf.KernelConfig{Type: o.kernel, LogLevel: "warn"},
		Log:        conf.LogConfig{Level: "info", Output: "stdout"},
		HealthPort: o.healthPort,
	}
	if o.mode == "machine" {
		inst.Machine = &conf.MachineConfig{MachineID: o.machineID}
	} else {
		inst.Nodes = []conf.NodeEntry{{NodeID: o.nodeID, NodeType: o.nodeType}}
	}
	instanceID, err := inst.AutoInstanceID()
	if err != nil {
		return "", fmt.Errorf("generate instance ID: %w", err)
	}
	inst.InstanceID = instanceID
	inst.Kernel.ConfigDir = filepath.Join(defaultInstallRoot, "instances", instanceID)

	envKey := "INSTANCE_" + strings.ToUpper(strings.ReplaceAll(instanceID, "-", "_"))
	if o.mode == "machine" {
		envKey += "_MACHINE_TOKEN"
		inst.Machine.TokenEnv = envKey
	} else {
		envKey += "_API_KEY"
		inst.Panel.TokenEnv = envKey
	}

	root := &conf.RootConfig{}
	if loaded, err := loadWritableRootConfig(defaultConfigPath); err == nil {
		root = loaded
	}
	instances := normalizeRootInstances(root)
	seen := make(map[string]bool, len(instances))
	merged := make([]conf.Config, 0, len(instances)+1)
	replaced := false
	for _, existing := range instances {
		if id, err := existing.AutoInstanceID(); err == nil && id != "" {
			existing.InstanceID = id
		}
		if existing.InstanceID != "" {
			if seen[existing.InstanceID] {
				continue
			}
			seen[existing.InstanceID] = true
		}
		if existing.InstanceID == instanceID {
			existing = inst
			replaced = true
		}
		merged = append(merged, existing)
	}
	if !replaced {
		merged = append(merged, inst)
	}
	root.Instances = merged

	if err := os.MkdirAll(defaultInstallRoot, 0o700); err != nil {
		return "", err
	}
	if err := secureInstallRoot(); err != nil {
		return "", fmt.Errorf("secure %s: %w", defaultInstallRoot, err)
	}
	if err := writeRootConfig(defaultConfigPath, root); err != nil {
		return "", err
	}
	if err := mergeCredentials(defaultCredentialsPath, defaultCredentialsPath, envKey, o.token); err != nil {
		return "", err
	}
	if err := writeInstallMetaVersioned(defaultMetaPath, root, version, instanceID); err != nil {
		return "", err
	}
	return instanceID, nil
}

func runBind(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: xnode bind <add-node|add-machine|remove|remove-node|remove-machine> ...")
	}
	if err := ensureRoot("bind"); err != nil {
		return err
	}
	sub, rest := args[0], args[1:]
	switch sub {
	case "add-node", "add-machine", "add":
		fs := flag.NewFlagSet("bind "+sub, flag.ContinueOnError)
		var o bindOptions
		o.register(fs)
		if err := fs.Parse(rest); err != nil {
			return err
		}
		switch sub {
		case "add-node":
			o.mode = "node"
		case "add-machine":
			o.mode = "machine"
		}
		if err := o.normalize(); err != nil {
			return err
		}
		id, err := bindInstance(o)
		if err != nil {
			return fmt.Errorf("bind failed: %w", err)
		}
		fmt.Printf(tr("Binding %s saved, restarting service...\n", "节点 %s 已保存，正在重启服务...\n"), id)
		return detectServiceManager().restart()
	case "remove-node":
		panel, nodeID, err := parseRemoveNodeArgs(rest)
		if err != nil {
			return err
		}
		return removeBinding(panel, nodeID, 0, "")
	case "remove-machine":
		panel, machineID, err := parseRemoveMachineArgs(rest)
		if err != nil {
			return err
		}
		return removeBinding(panel, 0, machineID, "")
	case "remove":
		if len(rest) == 0 {
			return errors.New("usage: xnode bind remove <instance-id>")
		}
		return removeBinding("", 0, 0, rest[0])
	default:
		return fmt.Errorf("unknown bind command: %s", sub)
	}
}
