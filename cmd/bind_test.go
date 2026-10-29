package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestWritableRootConfig_MigratesLegacyNode(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yml")
	legacy := "panel:\n  url: \"https://p.example.com\"\n  token_env: PANEL_TOKEN\n  node_id: 5\n  node_type: vless\n"
	if err := os.WriteFile(path, []byte(legacy), 0o600); err != nil {
		t.Fatal(err)
	}
	root, err := loadWritableRootConfig(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if err := writeRootConfig(path, root); err != nil {
		t.Fatalf("write: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	out := string(data)
	if !strings.Contains(out, "nodes:") || strings.Count(out, "node_id: 5") != 1 {
		t.Fatalf("nodes not written:\n%s", out)
	}

	root, err = loadWritableRootConfig(path)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if len(root.Instances) != 1 {
		t.Fatalf("instances: got %d", len(root.Instances))
	}
	inst := root.Instances[0]
	if len(inst.Nodes) != 1 || inst.Nodes[0].NodeID != 5 || inst.Nodes[0].NodeType != "vless" {
		t.Errorf("nodes: got %+v", inst.Nodes)
	}
	if inst.Panel.NodeID != 0 {
		t.Errorf("panel.node_id kept: %d", inst.Panel.NodeID)
	}
	if got := firstNodeID(&inst); got != 5 {
		t.Errorf("firstNodeID: got %d", got)
	}
}
