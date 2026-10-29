package cmd

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"sort"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/KilluaAoki/XNode/conf"
)

type instanceRow struct {
	ID      string `json:"id"`
	Mode    string `json:"mode"`
	Panel   string `json:"panel"`
	Target  string `json:"target"`
	Service string `json:"service"`
	Health  string `json:"health"`
}

func runStatus() error {
	fmt.Println(tr("xnode status", "xnode 状态"))
	fmt.Println()

	ver := tr("unknown", "未知")
	if meta, err := loadInstallMeta(defaultMetaPath); err == nil && meta.Version != "" {
		ver = meta.Version
	}
	fmt.Printf(tr("  version:  %s\n", "  版本：%s\n"), ver)

	svc := detectServiceManager()
	state := tr("not installed", "未安装")
	if svc.installed() {
		state = fmt.Sprintf("%s (%s)", stateLabel(svc.state()), svc.kind)
	}
	fmt.Printf(tr("  service:  %s\n", "  服务：%s\n"), state)

	health := instanceAwareHealth()
	fmt.Printf(tr("  health:   %s\n", "  健康：%s\n"), healthLabel(health))
	fmt.Println()

	rows, err := collectInstanceRows()
	if err != nil {
		fmt.Printf("  %v\n", err)
		return nil
	}
	return printRows(rows, "text")
}

func healthLabel(h string) string {
	switch h {
	case "ok":
		return tr("ok", "正常")
	case "down":
		return tr("down", "异常")
	case "disabled":
		return tr("disabled", "未启用")
	}
	return h
}

func errNoBindings() error {
	return errors.New(tr("no bindings configured; run 'xnode install' first", "尚未添加节点，请先安装"))
}

func runList(args []string) error {
	output := parseOutput(args)
	rows, err := collectInstanceRows()
	if err != nil {
		return err
	}
	return printRows(rows, output)
}

func runInstance(args []string) error {
	if len(args) == 0 {
		return runList(nil)
	}
	if args[0] == "list" {
		return runList(args[1:])
	}
	if args[0] != "get" {
		return fmt.Errorf("unknown instance command: %s", args[0])
	}
	if len(args) < 2 {
		return errors.New("usage: xnode instance get <id> [--output text|json]")
	}
	id := args[1]
	output := parseOutput(args[2:])
	rows, err := collectInstanceRows()
	if err != nil {
		return err
	}
	for _, row := range rows {
		if row.ID == id {
			return printRows([]instanceRow{row}, output)
		}
	}
	return fmt.Errorf("instance not found: %s", id)
}

func runHealth() error {
	h := instanceAwareHealth()
	fmt.Println(h)
	if h == "down" {
		return errors.New("health check failed")
	}
	return nil
}

func parseOutput(args []string) string {
	for i := 0; i < len(args); i++ {
		if args[i] == "--output" && i+1 < len(args) {
			return args[i+1]
		}
		if strings.HasPrefix(args[i], "--output=") {
			return strings.TrimPrefix(args[i], "--output=")
		}
	}
	return "text"
}

func collectInstanceRows() ([]instanceRow, error) {
	rows, err := collectRowsFromMeta()
	if err == nil && len(rows) > 0 {
		return rows, nil
	}
	return collectRowsFromConfig()
}

func collectRowsFromMeta() ([]instanceRow, error) {
	meta, err := loadInstallMeta(defaultMetaPath)
	if err != nil {
		return nil, err
	}
	serviceStatus := detectServiceManager().state()
	healthStatus := instanceAwareHealth()
	rows := make([]instanceRow, 0, len(meta.Instances))
	for _, inst := range meta.Instances {
		rows = append(rows, instanceRow{
			ID:      inst.ID,
			Mode:    inst.Mode,
			Panel:   inst.PanelURL,
			Target:  formatTarget(inst.NodeID, inst.MachineID),
			Service: serviceStatus,
			Health:  healthStatus,
		})
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].ID < rows[j].ID })
	return rows, nil
}

func collectRowsFromConfig() ([]instanceRow, error) {
	if !fileExists(defaultConfigPath) {
		return nil, errNoBindings()
	}
	root, err := conf.LoadRoot(defaultConfigPath)
	if err != nil {
		return nil, err
	}
	instances, err := root.NormalizeInstances()
	if err != nil {
		return nil, err
	}
	serviceStatus := detectServiceManager().state()
	healthStatus := instanceAwareHealth()
	rows := make([]instanceRow, 0, len(instances))
	for _, inst := range instances {
		mode := "node"
		if inst.IsMachineMode() {
			mode = "machine"
		}
		rows = append(rows, instanceRow{
			ID:      inst.InstanceID,
			Mode:    mode,
			Panel:   inst.Panel.URL,
			Target:  formatTarget(intPtr(firstNodeID(inst)), machineIDPtr(inst)),
			Service: serviceStatus,
			Health:  healthStatus,
		})
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].ID < rows[j].ID })
	return rows, nil
}

func printRows(rows []instanceRow, output string) error {
	if len(rows) == 0 && output != "json" {
		fmt.Println(errNoBindings())
		return nil
	}
	if output == "json" {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(rows)
	}
	var buf bytes.Buffer
	tw := tabwriter.NewWriter(&buf, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "ID\tMODE\tPANEL\tTARGET\tSERVICE\tHEALTH")
	for _, row := range rows {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n", row.ID, row.Mode, row.Panel, row.Target, row.Service, row.Health)
	}
	tw.Flush()
	_, err := fmt.Print(buf.String())
	return err
}

func instanceAwareHealth() string {
	port := 0
	if meta, err := loadInstallMeta(defaultMetaPath); err == nil {
		for _, inst := range meta.Instances {
			if inst.HealthPort > 0 {
				port = inst.HealthPort
				break
			}
		}
	}
	if port == 0 {
		if root, err := loadWritableRootConfig(defaultConfigPath); err == nil {
			if root.HealthPort > 0 {
				port = root.HealthPort
			}
			if port == 0 {
				instances, _ := root.NormalizeInstances()
				for _, inst := range instances {
					if inst.HealthPort > 0 {
						port = inst.HealthPort
						break
					}
				}
			}
		}
	}
	if port == 0 {
		return "disabled"
	}
	url := fmt.Sprintf("http://127.0.0.1:%d/healthz", port)
	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return "down"
	}
	resp.Body.Close()
	if resp.StatusCode == 200 {
		return "ok"
	}
	return "down"
}

func formatTarget(nodeID *int, machineID *int) string {
	if nodeID != nil && *nodeID > 0 {
		return fmt.Sprintf("node_id=%d", *nodeID)
	}
	if machineID != nil && *machineID > 0 {
		return fmt.Sprintf("machine_id=%d", *machineID)
	}
	return ""
}
