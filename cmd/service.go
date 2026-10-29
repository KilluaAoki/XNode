package cmd

import (
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"strconv"
	"strings"
	"time"
)

const (
	serviceName      = "xnode"
	systemdUnitPath  = "/etc/systemd/system/xnode.service"
	openrcScriptPath = "/etc/init.d/xnode"
	launchdLabel     = "com.killuaaoki.xnode"
	launchdPlistPath = "/Library/LaunchDaemons/com.killuaaoki.xnode.plist"
)

type initSystem string

const (
	initSystemd initSystem = "systemd"
	initOpenRC  initSystem = "openrc"
	initLaunchd initSystem = "launchd"
	initWindows initSystem = "windows"
)

type serviceManager struct {
	kind initSystem
}

func detectServiceManager() serviceManager {
	return serviceManager{kind: detectInitSystem(runtime.GOOS, dirExists, commandExists)}
}

func detectInitSystem(goos string, hasDir func(string) bool, hasCmd func(string) bool) initSystem {
	switch {
	case goos == "windows":
		return initWindows
	case goos == "darwin":
		return initLaunchd
	case hasDir("/run/systemd/system"):
		return initSystemd
	case hasCmd("rc-service"):
		return initOpenRC
	default:
		return initSystemd
	}
}

func dirExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.IsDir()
}

func commandExists(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}

func (s serviceManager) unitPath() string {
	switch s.kind {
	case initOpenRC:
		return openrcScriptPath
	case initLaunchd:
		return launchdPlistPath
	case initWindows:
		return ""
	default:
		return systemdUnitPath
	}
}

func (s serviceManager) installed() bool {
	if s.kind == initWindows {
		return winInstalled()
	}
	return fileExists(s.unitPath())
}

func (s serviceManager) launchdTarget() string {
	return "system/" + launchdLabel
}

func (s serviceManager) launchdLoaded() bool {
	return exec.Command("launchctl", "print", s.launchdTarget()).Run() == nil
}

func (s serviceManager) launchdBootstrap() error {
	var err error
	for i := 0; i < 5; i++ {
		if err = privileged("launchctl", "bootstrap", "system", launchdPlistPath); err == nil {
			return nil
		}
		time.Sleep(time.Second)
	}
	return err
}

func (s serviceManager) start() error {
	switch s.kind {
	case initOpenRC:
		return privileged("rc-service", serviceName, "start")
	case initLaunchd:
		if s.launchdLoaded() {
			return privileged("launchctl", "kickstart", s.launchdTarget())
		}
		return s.launchdBootstrap()
	case initWindows:
		return winStart()
	default:
		return privileged("systemctl", "start", serviceName)
	}
}

func (s serviceManager) stop() error {
	switch s.kind {
	case initOpenRC:
		return privileged("rc-service", serviceName, "stop")
	case initLaunchd:
		if !s.launchdLoaded() {
			return nil
		}
		return privileged("launchctl", "bootout", s.launchdTarget())
	case initWindows:
		return winStop()
	default:
		return privileged("systemctl", "stop", serviceName)
	}
}

func (s serviceManager) restart() error {
	switch s.kind {
	case initOpenRC:
		return privileged("rc-service", serviceName, "restart")
	case initLaunchd:
		if s.launchdLoaded() {
			return privileged("launchctl", "kickstart", "-k", s.launchdTarget())
		}
		return s.launchdBootstrap()
	case initWindows:
		if err := winStop(); err != nil {
			return err
		}
		return winStart()
	default:
		return privileged("systemctl", "restart", serviceName)
	}
}

func (s serviceManager) enable() error {
	switch s.kind {
	case initOpenRC:
		return privileged("rc-update", "add", serviceName, "default")
	case initLaunchd:
		return privileged("launchctl", "enable", s.launchdTarget())
	case initWindows:
		return winSetAutoStart(true)
	default:
		return privileged("systemctl", "enable", serviceName)
	}
}

func (s serviceManager) disable() error {
	switch s.kind {
	case initOpenRC:
		return privileged("rc-update", "del", serviceName, "default")
	case initLaunchd:
		return privileged("launchctl", "disable", s.launchdTarget())
	case initWindows:
		return winSetAutoStart(false)
	default:
		return privileged("systemctl", "disable", serviceName)
	}
}

func (s serviceManager) reload() error {
	switch s.kind {
	case initSystemd:
		return privileged("systemctl", "daemon-reload")
	case initLaunchd:
		if s.launchdLoaded() {
			return privileged("launchctl", "bootout", s.launchdTarget())
		}
	}
	return nil
}

func (s serviceManager) control(action string) error {
	switch action {
	case "start":
		return s.start()
	case "stop":
		return s.stop()
	case "restart":
		return s.restart()
	case "enable":
		return s.enable()
	case "disable":
		return s.disable()
	default:
		return fmt.Errorf("unknown service action: %s", action)
	}
}

func (s serviceManager) status(extra []string) error {
	switch s.kind {
	case initOpenRC:
		return privileged("rc-service", serviceName, "status")
	case initLaunchd:
		return privileged("launchctl", "print", s.launchdTarget())
	case initWindows:
		return winStatus()
	default:
		return privileged("systemctl", append([]string{"status", serviceName, "--no-pager"}, extra...)...)
	}
}

func (s serviceManager) logs(extra []string) error {
	if s.kind == initWindows {
		lines, follow, err := parseTailArgs(extra)
		if err != nil {
			return err
		}
		stop := make(chan os.Signal, 1)
		signal.Notify(stop, os.Interrupt)
		defer signal.Stop(stop)
		return tailFile(serviceLogPath, lines, follow, os.Stdout, stop)
	}
	if s.kind == initSystemd {
		if len(extra) == 0 {
			extra = []string{"-f"}
		}
		return privileged("journalctl", append([]string{"-u", serviceName}, extra...)...)
	}
	if len(extra) == 0 {
		extra = []string{"-n", "100", "-f"}
	}
	return privileged("tail", append(extra, serviceLogPath)...)
}

func (s serviceManager) state() string {
	switch s.kind {
	case initOpenRC:
		out, _ := exec.Command("rc-service", serviceName, "status").CombinedOutput()
		return openrcState(string(out))
	case initLaunchd:
		out, err := exec.Command("launchctl", "print", s.launchdTarget()).CombinedOutput()
		if err != nil {
			return "inactive"
		}
		return launchdState(string(out))
	case initWindows:
		return winState()
	default:
		out, err := exec.Command("systemctl", "is-active", serviceName).CombinedOutput()
		if state := strings.TrimSpace(string(out)); state != "" {
			return state
		}
		if err != nil {
			return "unknown"
		}
		return ""
	}
}

func (s serviceManager) enabled() bool {
	switch s.kind {
	case initOpenRC:
		out, _ := exec.Command("rc-update", "show", "default").CombinedOutput()
		return openrcEnabled(string(out))
	case initLaunchd:
		if !s.installed() {
			return false
		}
		out, _ := exec.Command("launchctl", "print-disabled", "system").CombinedOutput()
		return !launchdDisabled(string(out))
	case initWindows:
		return winAutoStart()
	default:
		out, _ := exec.Command("systemctl", "is-enabled", serviceName).CombinedOutput()
		return strings.TrimSpace(string(out)) == "enabled"
	}
}

func openrcEnabled(out string) bool {
	for _, line := range strings.Split(out, "\n") {
		name, _, _ := strings.Cut(strings.TrimSpace(line), "|")
		if strings.TrimSpace(name) == serviceName {
			return true
		}
	}
	return false
}

func launchdDisabled(out string) bool {
	for _, line := range strings.Split(out, "\n") {
		k, v, ok := strings.Cut(strings.TrimSpace(line), "=>")
		if ok && strings.Trim(strings.TrimSpace(k), `"`) == launchdLabel {
			v = strings.TrimSpace(v)
			return v == "true" || v == "disabled"
		}
	}
	return false
}

func openrcState(out string) string {
	switch {
	case strings.Contains(out, "started"):
		return "active"
	case strings.Contains(out, "crashed"):
		return "failed"
	case strings.Contains(out, "stopped"):
		return "inactive"
	default:
		return "unknown"
	}
}

func launchdState(out string) string {
	for _, line := range strings.Split(out, "\n") {
		k, v, ok := strings.Cut(strings.TrimSpace(line), "=")
		if ok && strings.TrimSpace(k) == "state" {
			if strings.TrimSpace(v) == "running" {
				return "active"
			}
			return "inactive"
		}
	}
	return "unknown"
}

func (s serviceManager) remove() []string {
	if s.kind == initWindows {
		return winRemove()
	}
	var warnings []string
	if err := s.stop(); err != nil {
		warnings = append(warnings, fmt.Sprintf("stop service: %v", err))
	}
	if s.kind != initLaunchd {
		if err := s.disable(); err != nil {
			warnings = append(warnings, fmt.Sprintf("disable service: %v", err))
		}
	}
	if err := os.Remove(s.unitPath()); err != nil && !os.IsNotExist(err) {
		warnings = append(warnings, fmt.Sprintf("remove service file: %v", err))
	}
	s.reload()
	return warnings
}

func privileged(name string, args ...string) error {
	if isElevated() || !commandExists("sudo") {
		return runCommand(name, args...)
	}
	return runCommand("sudo", append([]string{name}, args...)...)
}

func (s serviceManager) active() bool {
	return s.state() == "active"
}

func (s serviceManager) unitMode() os.FileMode {
	if s.kind == initOpenRC {
		return 0o755
	}
	return 0o644
}

func (s serviceManager) render(binary string) string {
	switch s.kind {
	case initOpenRC:
		return fmt.Sprintf(openrcTemplate, serviceName, binary, defaultConfigPath, defaultCredentialsPath, defaultInstallRoot, serviceLogPath, serviceLogPath)
	case initLaunchd:
		limit := launchdFileLimit()
		return fmt.Sprintf(launchdTemplate, launchdLabel, binary, defaultConfigPath, defaultCredentialsPath, defaultInstallRoot, limit, limit, serviceLogPath, serviceLogPath)
	default:
		return fmt.Sprintf(systemdTemplate, defaultInstallRoot, defaultCredentialsPath, binary, defaultConfigPath)
	}
}

func (s serviceManager) writeUnit(binary string) error {
	if s.kind == initWindows {
		return winWriteService(binary)
	}
	path := s.unitPath()
	if err := os.WriteFile(path, []byte(s.render(binary)), s.unitMode()); err != nil {
		return fmt.Errorf("write service file: %w", err)
	}
	if s.kind == initLaunchd {
		os.Chown(path, 0, 0)
	}
	return nil
}

func (s serviceManager) recentLogs() {
	if s.kind == initSystemd && commandExists("journalctl") {
		runCommand("journalctl", "-u", serviceName, "-n", "30", "--no-pager")
		return
	}
	if fileExists(serviceLogPath) {
		tailFile(serviceLogPath, 30, false, os.Stdout, nil)
	}
}

func (s serviceManager) waitHealthy(port int, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	client := &http.Client{Timeout: 2 * time.Second}
	for time.Now().Before(deadline) {
		if s.active() {
			if port <= 0 {
				return true
			}
			if resp, err := client.Get("http://127.0.0.1:" + strconv.Itoa(port) + "/healthz"); err == nil {
				resp.Body.Close()
				if resp.StatusCode == http.StatusOK {
					return true
				}
			}
		}
		time.Sleep(time.Second)
	}
	return false
}

func launchdFileLimit() int {
	out, err := exec.Command("sysctl", "-n", "kern.maxfilesperproc").Output()
	if err == nil {
		if n, err := strconv.Atoi(strings.TrimSpace(string(out))); err == nil && n > 0 {
			return n
		}
	}
	return 65536
}

const systemdTemplate = `[Unit]
Description=XNode
Documentation=https://github.com/KilluaAoki/XNode
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=%s
EnvironmentFile=-%s
ExecStart=%s server -c %s
Restart=always
RestartSec=5
LimitNOFILE=1048576
NoNewPrivileges=true
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
`

const openrcTemplate = `#!/sbin/openrc-run

name="%s"
description="XNode"
supervisor="supervise-daemon"
command="%s"
command_args="server -c %s -e %s"
directory="%s"
output_log="%s"
error_log="%s"
respawn_delay=5
respawn_max=0
rc_ulimit="-n 1048576"

depend() {
    need net
    after firewall
}
`

const launchdTemplate = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>%s</string>
    <key>ProgramArguments</key>
    <array>
        <string>%s</string>
        <string>server</string>
        <string>-c</string>
        <string>%s</string>
        <string>-e</string>
        <string>%s</string>
    </array>
    <key>WorkingDirectory</key>
    <string>%s</string>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>ThrottleInterval</key>
    <integer>5</integer>
    <key>SoftResourceLimits</key>
    <dict>
        <key>NumberOfFiles</key>
        <integer>%d</integer>
    </dict>
    <key>HardResourceLimits</key>
    <dict>
        <key>NumberOfFiles</key>
        <integer>%d</integer>
    </dict>
    <key>StandardOutPath</key>
    <string>%s</string>
    <key>StandardErrorPath</key>
    <string>%s</string>
</dict>
</plist>
`
