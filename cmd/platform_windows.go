//go:build windows

package cmd

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime/debug"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

const (
	exeSuffix       = ".exe"
	elevationHint   = "requires Administrator privileges; run from an elevated terminal"
	elevationHintZH = "需要管理员权限，请在以管理员身份运行的终端中执行"
	firewallRule    = "XNode"
	installRootACL  = "D:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"
	environmentKey  = `SYSTEM\CurrentControlSet\Control\Session Manager\Environment`
)

var (
	defaultInstallRoot     = filepath.Join(knownFolder(windows.FOLDERID_ProgramData, "ProgramData", `C:\ProgramData`), "xnode")
	defaultConfigPath      = filepath.Join(defaultInstallRoot, "config.yml")
	defaultMetaPath        = filepath.Join(defaultInstallRoot, "install-meta.json")
	defaultCredentialsPath = filepath.Join(defaultInstallRoot, "credentials.env")
	defaultBackupDir       = filepath.Join(defaultInstallRoot, "backups")
	serviceLogPath         = filepath.Join(defaultInstallRoot, "xnode.log")
	defaultBinaryPath      = filepath.Join(knownFolder(windows.FOLDERID_ProgramFiles, "ProgramFiles", `C:\Program Files`), "xnode", "xnode.exe")
)

func knownFolder(id *windows.KNOWNFOLDERID, env, fallback string) string {
	if p, err := windows.KnownFolderPath(id, 0); err == nil && p != "" {
		return p
	}
	if p := os.Getenv(env); p != "" {
		return p
	}
	return fallback
}

func isElevated() bool {
	return windows.GetCurrentProcessToken().IsElevated()
}

func prepareConsole() {
	for _, f := range []*os.File{os.Stdout, os.Stderr} {
		h := windows.Handle(f.Fd())
		var mode uint32
		if windows.GetConsoleMode(h, &mode) == nil {
			windows.SetConsoleMode(h, mode|windows.ENABLE_VIRTUAL_TERMINAL_PROCESSING)
		}
	}
}

func systemLanguage() string {
	langs, err := windows.GetUserPreferredUILanguages(windows.MUI_LANGUAGE_NAME)
	if err != nil || len(langs) == 0 {
		return ""
	}
	return langs[0]
}

type windowsService struct {
	run func() error
}

func (w *windowsService) Execute(_ []string, req <-chan svc.ChangeRequest, status chan<- svc.Status) (bool, uint32) {
	status <- svc.Status{State: svc.StartPending}
	done := make(chan error, 1)
	go func() { done <- w.run() }()
	status <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}
	for {
		select {
		case err := <-done:
			status <- svc.Status{State: svc.StopPending}
			if err != nil {
				fmt.Fprintln(os.Stderr, err)
				return true, 1
			}
			return false, 0
		case c := <-req:
			switch c.Cmd {
			case svc.Interrogate:
				status <- c.CurrentStatus
			case svc.Stop, svc.Shutdown:
				status <- svc.Status{State: svc.StopPending}
				requestStop()
			}
		}
	}
}

func runAsService(run func() error) (bool, error) {
	if ok, err := svc.IsWindowsService(); err != nil || !ok {
		return false, nil
	}
	if err := os.MkdirAll(defaultInstallRoot, 0o700); err == nil {
		os.Chdir(defaultInstallRoot)
	}
	if f, err := os.OpenFile(serviceLogPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644); err == nil {
		os.Stdout = f
		os.Stderr = f
		debug.SetCrashOutput(f, debug.CrashOptions{})
	}
	return true, svc.Run(serviceName, &windowsService{run: run})
}

func secureInstallRoot() error {
	sd, err := windows.SecurityDescriptorFromString(installRootACL)
	if err != nil {
		return err
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return err
	}
	return windows.SetNamedSecurityInfo(defaultInstallRoot, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil)
}

func linkSelf() {
	dir := filepath.Dir(defaultBinaryPath)
	if err := updateMachinePath(dir, true); err != nil {
		fmt.Printf("Warning: add %s to PATH failed: %v\n", dir, err)
	}
}

func unlinkSelf() []string {
	var warnings []string
	dir := filepath.Dir(defaultBinaryPath)
	if err := updateMachinePath(dir, false); err != nil {
		warnings = append(warnings, fmt.Sprintf("remove %s from PATH: %v", dir, err))
	}
	if err := os.Remove(dir); err != nil && !os.IsNotExist(err) {
		removeAfterReboot(dir)
	}
	return warnings
}

func updateMachinePath(dir string, add bool) error {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, environmentKey, registry.QUERY_VALUE|registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer k.Close()
	cur, typ, err := k.GetStringValue("Path")
	if err != nil && !errors.Is(err, registry.ErrNotExist) {
		return err
	}
	next := editPathList(cur, dir, add)
	if next == cur {
		return nil
	}
	if typ == registry.SZ {
		err = k.SetStringValue("Path", next)
	} else {
		err = k.SetExpandStringValue("Path", next)
	}
	if err != nil {
		return err
	}
	broadcastEnvironmentChange()
	return nil
}

func broadcastEnvironmentChange() {
	env, err := windows.UTF16PtrFromString("Environment")
	if err != nil {
		return
	}
	proc := windows.NewLazySystemDLL("user32.dll").NewProc("SendMessageTimeoutW")
	var result uintptr
	proc.Call(0xffff, 0x001a, 0, uintptr(unsafe.Pointer(env)), 0x0002, 5000, uintptr(unsafe.Pointer(&result)))
}

func removeBinary(path string) error {
	err := os.Remove(path)
	if err == nil || os.IsNotExist(err) {
		return err
	}
	if removeAfterReboot(path) == nil {
		fmt.Printf("%s is in use and will be removed after reboot\n", path)
		return nil
	}
	return err
}

func removeAfterReboot(path string) error {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	return windows.MoveFileEx(p, nil, windows.MOVEFILE_DELAY_UNTIL_REBOOT)
}

const serviceQueryAccess = windows.SERVICE_QUERY_STATUS | windows.SERVICE_QUERY_CONFIG

func withService(access uint32, fn func(*mgr.Service) error) error {
	h, err := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_CONNECT)
	if err != nil {
		return err
	}
	defer windows.CloseServiceHandle(h)
	name, err := windows.UTF16PtrFromString(serviceName)
	if err != nil {
		return err
	}
	sh, err := windows.OpenService(h, name, access)
	if err != nil {
		return err
	}
	s := &mgr.Service{Name: serviceName, Handle: sh}
	defer s.Close()
	return fn(s)
}

func winInstalled() bool {
	return withService(serviceQueryAccess, func(*mgr.Service) error { return nil }) == nil
}

func winStart() error {
	return withService(windows.SERVICE_ALL_ACCESS, func(s *mgr.Service) error {
		if err := s.Start(); err != nil && !errors.Is(err, windows.ERROR_SERVICE_ALREADY_RUNNING) {
			return err
		}
		return nil
	})
}

func winStop() error {
	err := withService(windows.SERVICE_ALL_ACCESS, func(s *mgr.Service) error {
		st, err := s.Control(svc.Stop)
		switch {
		case errors.Is(err, windows.ERROR_SERVICE_NOT_ACTIVE):
			return nil
		case errors.Is(err, windows.ERROR_SERVICE_CANNOT_ACCEPT_CTRL):
			if st, err = s.Query(); err != nil {
				return err
			}
		case err != nil:
			return err
		}
		deadline := time.Now().Add(30 * time.Second)
		for st.State != svc.Stopped {
			if time.Now().After(deadline) {
				return errors.New("timed out waiting for the service to stop")
			}
			time.Sleep(300 * time.Millisecond)
			if st, err = s.Query(); err != nil {
				return err
			}
		}
		return nil
	})
	if errors.Is(err, windows.ERROR_SERVICE_DOES_NOT_EXIST) {
		return nil
	}
	return err
}

func winSetAutoStart(on bool) error {
	return withService(windows.SERVICE_ALL_ACCESS, func(s *mgr.Service) error {
		cfg, err := s.Config()
		if err != nil {
			return err
		}
		cfg.StartType, cfg.DelayedAutoStart = mgr.StartManual, false
		if on {
			cfg.StartType, cfg.DelayedAutoStart = mgr.StartAutomatic, true
		}
		return s.UpdateConfig(cfg)
	})
}

func winAutoStart() bool {
	auto := false
	withService(serviceQueryAccess, func(s *mgr.Service) error {
		cfg, err := s.Config()
		if err != nil {
			return err
		}
		auto = cfg.StartType == mgr.StartAutomatic
		return nil
	})
	return auto
}

func winState() string {
	state := "inactive"
	err := withService(serviceQueryAccess, func(s *mgr.Service) error {
		st, err := s.Query()
		if err != nil {
			return err
		}
		state = windowsServiceState(st.State)
		return nil
	})
	if err != nil && !errors.Is(err, windows.ERROR_SERVICE_DOES_NOT_EXIST) {
		return "unknown"
	}
	return state
}

func windowsServiceState(st svc.State) string {
	switch st {
	case svc.Running:
		return "active"
	case svc.StartPending, svc.ContinuePending:
		return "activating"
	case svc.StopPending:
		return "deactivating"
	case svc.Stopped:
		return "inactive"
	default:
		return "unknown"
	}
}

func winStatus() error {
	return withService(serviceQueryAccess, func(s *mgr.Service) error {
		st, err := s.Query()
		if err != nil {
			return err
		}
		cfg, err := s.Config()
		if err != nil {
			return err
		}
		startup := "manual"
		switch {
		case cfg.StartType == mgr.StartAutomatic && cfg.DelayedAutoStart:
			startup = "automatic (delayed)"
		case cfg.StartType == mgr.StartAutomatic:
			startup = "automatic"
		case cfg.StartType == mgr.StartDisabled:
			startup = "disabled"
		}
		fmt.Printf("Service:  %s (%s)\n", serviceName, cfg.DisplayName)
		fmt.Printf("State:    %s\n", windowsServiceState(st.State))
		if st.ProcessId != 0 {
			fmt.Printf("PID:      %d\n", st.ProcessId)
		}
		fmt.Printf("Startup:  %s\n", startup)
		fmt.Printf("Command:  %s\n", cfg.BinaryPathName)
		fmt.Printf("Log:      %s\n", serviceLogPath)
		return nil
	})
}

func winRemove() []string {
	var warnings []string
	if err := winStop(); err != nil {
		warnings = append(warnings, fmt.Sprintf("stop service: %v", err))
	}
	if err := withService(windows.SERVICE_ALL_ACCESS, func(s *mgr.Service) error { return s.Delete() }); err != nil && !errors.Is(err, windows.ERROR_SERVICE_DOES_NOT_EXIST) {
		warnings = append(warnings, fmt.Sprintf("delete service: %v", err))
	}
	netsh(`advfirewall firewall delete rule name="` + firewallRule + `"`)
	return warnings
}

func winWriteService(binary string) error {
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	args := []string{"server", "-c", defaultConfigPath, "-e", defaultCredentialsPath}
	s, err := m.OpenService(serviceName)
	if err == nil {
		defer s.Close()
		cfg, err := s.Config()
		if err != nil {
			return err
		}
		cfg.BinaryPathName = serviceCommandLine(binary, args)
		cfg.DisplayName = "XNode"
		cfg.Description = "XNode node backend for Xboard"
		if err := s.UpdateConfig(cfg); err != nil {
			return fmt.Errorf("update service: %w", err)
		}
	} else {
		s, err = m.CreateService(serviceName, binary, mgr.Config{
			DisplayName:      "XNode",
			Description:      "XNode node backend for Xboard",
			StartType:        mgr.StartAutomatic,
			DelayedAutoStart: true,
		}, args...)
		if err != nil {
			return fmt.Errorf("create service: %w", err)
		}
		defer s.Close()
	}
	restart := mgr.RecoveryAction{Type: mgr.ServiceRestart, Delay: 5 * time.Second}
	if err := s.SetRecoveryActions([]mgr.RecoveryAction{restart, restart, restart}, 86400); err != nil {
		return fmt.Errorf("set recovery actions: %w", err)
	}
	s.SetRecoveryActionsOnNonCrashFailures(true)
	netsh(`advfirewall firewall delete rule name="` + firewallRule + `"`)
	if err := netsh(`advfirewall firewall add rule name="` + firewallRule + `" dir=in action=allow enable=yes profile=any program="` + binary + `"`); err != nil {
		fmt.Printf("Warning: add firewall rule failed: %v\n", err)
	}
	return nil
}

func serviceCommandLine(binary string, args []string) string {
	line := syscall.EscapeArg(binary)
	for _, a := range args {
		line += " " + syscall.EscapeArg(a)
	}
	return line
}

func netsh(args string) error {
	sys, err := windows.GetSystemDirectory()
	if err != nil {
		return err
	}
	path := filepath.Join(sys, "netsh.exe")
	cmd := exec.Command(path)
	cmd.SysProcAttr = &syscall.SysProcAttr{CmdLine: syscall.EscapeArg(path) + " " + args}
	return cmd.Run()
}
