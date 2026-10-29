package conf

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"gopkg.in/yaml.v3"
)

// migrateLegacyNode moves the legacy single-node form (panel.node_id and
// panel.node_type) into Nodes. As before, an explicit nodes list wins and
// machine and standalone configs ignore the panel node fields.
func (c *Config) migrateLegacyNode() {
	if c.Panel.NodeID == 0 && c.Panel.NodeType == "" {
		return
	}
	if len(c.Nodes) == 0 && !c.IsMachineMode() && !c.IsStandalone() {
		c.Nodes = []NodeEntry{{NodeID: c.Panel.NodeID, NodeType: c.Panel.NodeType}}
	}
	c.Panel.NodeID, c.Panel.NodeType = 0, ""
}

// MigrateLegacyNodes converts every config in rc to the nodes list form.
func (rc *RootConfig) MigrateLegacyNodes() {
	rc.Config.migrateLegacyNode()
	for i := range rc.Instances {
		rc.Instances[i].migrateLegacyNode()
	}
}

// MigrateConfigFile rewrites a config file that still uses panel.node_id into
// the nodes list form, keeping the original next to it. It returns the backup
// path, or "" when the file needed no change.
func MigrateConfigFile(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return "", nil
		}
		return "", err
	}
	var doc yaml.Node
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return "", fmt.Errorf("parse config: %w", err)
	}
	if len(doc.Content) == 0 || doc.Content[0].Kind != yaml.MappingNode {
		return "", nil
	}
	root := doc.Content[0]
	changed := false
	// Instances do not inherit panel or nodes, so with instances only their
	// own mappings matter.
	if instances := mappingValue(root, "instances"); instances != nil && instances.Kind == yaml.SequenceNode && len(instances.Content) > 0 {
		for _, inst := range instances.Content {
			if inst.Kind == yaml.MappingNode && migrateNodeMapping(inst) {
				changed = true
			}
		}
	} else {
		changed = migrateNodeMapping(root)
	}
	if !changed {
		return "", nil
	}

	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(&doc); err != nil {
		return "", fmt.Errorf("marshal config: %w", err)
	}
	if err := enc.Close(); err != nil {
		return "", fmt.Errorf("marshal config: %w", err)
	}

	perm := os.FileMode(0o600)
	if st, err := os.Stat(path); err == nil {
		perm = st.Mode().Perm()
	}
	backup := path + ".bak"
	if _, err := os.Stat(backup); err == nil {
		backup = fmt.Sprintf("%s.%s.bak", path, time.Now().Format("20060102150405"))
	}
	if err := os.WriteFile(backup, data, perm); err != nil {
		return "", fmt.Errorf("write backup: %w", err)
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), filepath.Base(path)+".tmp*")
	if err != nil {
		return "", err
	}
	tmpName := tmp.Name()
	_, werr := tmp.Write(buf.Bytes())
	cerr := tmp.Close()
	if werr == nil {
		werr = cerr
	}
	if werr == nil {
		werr = os.Chmod(tmpName, perm)
	}
	if werr == nil {
		werr = os.Rename(tmpName, path)
	}
	if werr != nil {
		os.Remove(tmpName)
		return "", werr
	}
	return backup, nil
}

// migrateNodeMapping applies migrateLegacyNode to one config mapping.
func migrateNodeMapping(m *yaml.Node) bool {
	panel := mappingValue(m, "panel")
	if panel == nil || panel.Kind != yaml.MappingNode {
		return false
	}
	var c Config
	if err := m.Decode(&c); err != nil {
		return false
	}
	nodeID := removeMappingKey(panel, "node_id")
	nodeType := removeMappingKey(panel, "node_type")
	if nodeID == nil && nodeType == nil {
		return false
	}
	if len(c.Nodes) > 0 || c.IsMachineMode() || c.IsStandalone() {
		return true
	}
	entry := &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
	if nodeID != nil {
		entry.Content = append(entry.Content, scalarNode("node_id"), nodeID)
	}
	if nodeType != nil && nodeType.Value != "" {
		entry.Content = append(entry.Content, scalarNode("node_type"), nodeType)
	}
	nodes := &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq", Content: []*yaml.Node{entry}}
	if existing := mappingValue(m, "nodes"); existing != nil {
		*existing = *nodes
		return true
	}
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == "panel" {
			rest := append([]*yaml.Node{scalarNode("nodes"), nodes}, m.Content[i+2:]...)
			m.Content = append(m.Content[:i+2], rest...)
			break
		}
	}
	return true
}

func mappingValue(m *yaml.Node, key string) *yaml.Node {
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == key {
			return m.Content[i+1]
		}
	}
	return nil
}

func removeMappingKey(m *yaml.Node, key string) *yaml.Node {
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == key {
			v := m.Content[i+1]
			m.Content = append(m.Content[:i], m.Content[i+2:]...)
			return v
		}
	}
	return nil
}

func scalarNode(v string) *yaml.Node {
	return &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: v}
}
