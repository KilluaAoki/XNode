//go:build windows

package cmd

import (
	"strings"
	"testing"

	"golang.org/x/sys/windows/svc"
)

func TestWindowsServiceState(t *testing.T) {
	cases := map[svc.State]string{
		svc.Running:      "active",
		svc.Stopped:      "inactive",
		svc.StartPending: "activating",
		svc.StopPending:  "deactivating",
		svc.Paused:       "unknown",
	}
	for in, want := range cases {
		if got := windowsServiceState(in); got != want {
			t.Fatalf("windowsServiceState(%d) = %q, want %q", in, got, want)
		}
	}
}

func TestServiceCommandLine(t *testing.T) {
	got := serviceCommandLine(`C:\Program Files\xnode\xnode.exe`, []string{"server", "-c", `C:\ProgramData\xnode\config.yml`})
	want := `"C:\Program Files\xnode\xnode.exe" server -c C:\ProgramData\xnode\config.yml`
	if got != want {
		t.Fatalf("serviceCommandLine = %q, want %q", got, want)
	}
}

func TestWindowsPaths(t *testing.T) {
	for _, p := range []string{defaultConfigPath, defaultCredentialsPath, defaultMetaPath, defaultBackupDir, serviceLogPath} {
		if !strings.HasPrefix(p, defaultInstallRoot+`\`) {
			t.Fatalf("%s is outside %s", p, defaultInstallRoot)
		}
	}
	if !strings.HasSuffix(defaultBinaryPath, `\xnode\xnode.exe`) {
		t.Fatalf("unexpected binary path %s", defaultBinaryPath)
	}
}
