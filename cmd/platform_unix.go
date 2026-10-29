//go:build !windows

package cmd

import (
	"errors"
	"os"
	"os/exec"
	"runtime"
)

const (
	defaultInstallRoot     = "/etc/xnode"
	defaultConfigPath      = "/etc/xnode/config.yml"
	defaultMetaPath        = "/etc/xnode/install-meta.json"
	defaultCredentialsPath = "/etc/xnode/credentials.env"
	defaultBackupDir       = "/etc/xnode/backups"
	defaultBinaryPath      = "/usr/local/bin/xnode"
	linkBinaryPath         = "/usr/bin/xnode"
	serviceLogPath         = "/var/log/xnode.log"
	exeSuffix              = ""
	elevationHint          = "requires root privileges; run with sudo"
	elevationHintZH        = "需要 root 权限，请使用 sudo 运行"
)

var errNoWindowsService = errors.New("windows service manager is unavailable on this platform")

func isElevated() bool {
	return os.Geteuid() == 0
}

func prepareConsole() {}

func systemLanguage() string {
	if runtime.GOOS != "darwin" {
		return ""
	}
	out, err := exec.Command("defaults", "read", "-g", "AppleLocale").Output()
	if err != nil {
		return ""
	}
	return string(out)
}

func runAsService(func() error) (bool, error) {
	return false, nil
}

func secureInstallRoot() error {
	return nil
}

func linkSelf() {
	switch runtime.GOOS {
	case "darwin":
		exec.Command("xattr", "-d", "com.apple.quarantine", defaultBinaryPath).Run()
	case "linux":
		os.Remove(linkBinaryPath)
		os.Symlink(defaultBinaryPath, linkBinaryPath)
	}
}

func unlinkSelf() []string {
	if err := os.Remove(linkBinaryPath); err != nil && !os.IsNotExist(err) {
		return []string{"remove " + linkBinaryPath + ": " + err.Error()}
	}
	return nil
}

func removeBinary(path string) error {
	return os.Remove(path)
}

func winInstalled() bool           { return false }
func winStart() error              { return errNoWindowsService }
func winStop() error               { return errNoWindowsService }
func winSetAutoStart(bool) error   { return errNoWindowsService }
func winState() string             { return "unknown" }
func winAutoStart() bool           { return false }
func winStatus() error             { return errNoWindowsService }
func winRemove() []string          { return nil }
func winWriteService(string) error { return errNoWindowsService }
