package conf

import (
	"os"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func readFile(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func TestMigrateConfigFile_SingleNode(t *testing.T) {
	const legacy = `# panel binding
panel:
  url: "https://panel.example.com"
  token: "tok"
  node_id: 7
  node_type: "vless"
kernel:
  type: xray
`
	path := writeTemp(t, legacy)
	backup, err := MigrateConfigFile(path)
	if err != nil {
		t.Fatalf("MigrateConfigFile: %v", err)
	}
	if backup != path+".bak" {
		t.Fatalf("backup: got %q", backup)
	}
	if got := readFile(t, backup); got != legacy {
		t.Fatalf("backup content changed:\n%s", got)
	}

	out := readFile(t, path)
	if !strings.Contains(out, "# panel binding") {
		t.Errorf("comment lost:\n%s", out)
	}
	var raw struct {
		Panel map[string]any `yaml:"panel"`
		Nodes []NodeEntry    `yaml:"nodes"`
	}
	if err := yaml.Unmarshal([]byte(out), &raw); err != nil {
		t.Fatal(err)
	}
	if _, ok := raw.Panel["node_id"]; ok {
		t.Errorf("panel.node_id kept:\n%s", out)
	}
	if len(raw.Nodes) != 1 || raw.Nodes[0].NodeID != 7 || raw.Nodes[0].NodeType != "vless" {
		t.Errorf("nodes: got %+v\n%s", raw.Nodes, out)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load migrated: %v", err)
	}
	if cfg.Kernel.Type != "xray" || len(cfg.Nodes) != 1 || cfg.Nodes[0].NodeID != 7 {
		t.Errorf("migrated config: kernel %q nodes %+v", cfg.Kernel.Type, cfg.Nodes)
	}

	again, err := MigrateConfigFile(path)
	if err != nil || again != "" {
		t.Errorf("second run: backup %q err %v", again, err)
	}
}

func TestMigrateConfigFile_KeepsExistingBackup(t *testing.T) {
	path := writeTemp(t, "panel:\n  url: \"https://p.example.com\"\n  token: \"tok\"\n  node_id: 1\n")
	if err := os.WriteFile(path+".bak", []byte("old"), 0o644); err != nil {
		t.Fatal(err)
	}
	backup, err := MigrateConfigFile(path)
	if err != nil {
		t.Fatalf("MigrateConfigFile: %v", err)
	}
	if backup == path+".bak" || !strings.HasSuffix(backup, ".bak") {
		t.Fatalf("backup: got %q", backup)
	}
	if got := readFile(t, path+".bak"); got != "old" {
		t.Errorf("existing backup overwritten: %q", got)
	}
}

func TestMigrateConfigFile_NodesListWins(t *testing.T) {
	path := writeTemp(t, `
panel:
  url: "https://p.example.com"
  token: "tok"
  node_id: 1
nodes:
  - node_id: 2
  - node_id: 3
`)
	if _, err := MigrateConfigFile(path); err != nil {
		t.Fatalf("MigrateConfigFile: %v", err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(cfg.Nodes) != 2 || cfg.Nodes[0].NodeID != 2 || cfg.Nodes[1].NodeID != 3 {
		t.Errorf("nodes: got %+v", cfg.Nodes)
	}
	if strings.Contains(readFile(t, path), "node_id: 1") {
		t.Errorf("panel.node_id kept:\n%s", readFile(t, path))
	}
}

func TestMigrateConfigFile_Instances(t *testing.T) {
	t.Setenv("PANEL_A_TOKEN", "token-a")
	t.Setenv("PANEL_B_TOKEN", "token-b")
	path := writeTemp(t, `
instances:
  - panel:
      url: "https://a.example.com"
      token_env: PANEL_A_TOKEN
      node_id: 4
      node_type: "trojan"
  - panel:
      url: "https://b.example.com"
      token_env: PANEL_B_TOKEN
    machine:
      machine_id: 9
      token_env: PANEL_B_TOKEN
`)
	backup, err := MigrateConfigFile(path)
	if err != nil || backup == "" {
		t.Fatalf("MigrateConfigFile: backup %q err %v", backup, err)
	}
	root, err := LoadRoot(path)
	if err != nil {
		t.Fatalf("LoadRoot: %v", err)
	}
	if len(root.Instances) != 2 {
		t.Fatalf("instances: got %d", len(root.Instances))
	}
	a := root.Instances[0]
	if len(a.Nodes) != 1 || a.Nodes[0].NodeID != 4 || a.Nodes[0].NodeType != "trojan" {
		t.Errorf("instance a nodes: got %+v", a.Nodes)
	}
	b := root.Instances[1]
	if len(b.Nodes) != 0 || !b.IsMachineMode() {
		t.Errorf("instance b: nodes %+v machine %v", b.Nodes, b.IsMachineMode())
	}
}

func TestMigrateConfigFile_NoChange(t *testing.T) {
	const current = "panel:\n  url: \"https://p.example.com\"\n  token: \"tok\"\nnodes:\n  - node_id: 1\n"
	path := writeTemp(t, current)
	backup, err := MigrateConfigFile(path)
	if err != nil || backup != "" {
		t.Fatalf("backup %q err %v", backup, err)
	}
	if got := readFile(t, path); got != current {
		t.Errorf("file rewritten:\n%s", got)
	}
	if _, err := os.Stat(path + ".bak"); !os.IsNotExist(err) {
		t.Errorf("unexpected backup: %v", err)
	}
}

func TestLoad_EnvNodeIDOverridesSingleNode(t *testing.T) {
	t.Setenv("NODE_ID", "12")
	t.Setenv("NODE_TYPE", "hysteria2")
	path := writeTemp(t, "panel:\n  url: \"https://p.example.com\"\n  token: \"tok\"\n  node_id: 1\n")
	root, err := LoadRoot(path)
	if err != nil {
		t.Fatalf("LoadRoot: %v", err)
	}
	if n := root.Config.Nodes; len(n) != 1 || n[0].NodeID != 12 || n[0].NodeType != "hysteria2" {
		t.Errorf("nodes: got %+v", n)
	}
}

func TestLoad_EnvOnlyConfig(t *testing.T) {
	t.Setenv("API_HOST", "https://p.example.com")
	t.Setenv("API_KEY", "tok")
	t.Setenv("NODE_ID", "3")
	root, err := LoadRoot(writeTemp(t, ""))
	if err != nil {
		t.Fatalf("LoadRoot: %v", err)
	}
	if n := root.Config.Nodes; len(n) != 1 || n[0].NodeID != 3 {
		t.Errorf("nodes: got %+v", n)
	}
}
