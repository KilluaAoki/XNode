package cmd

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

type backup struct {
	dir   string
	files map[string]string
}

func newBackup(paths ...string) (*backup, error) {
	b := &backup{dir: filepath.Join(defaultBackupDir, time.Now().Format("20060102-150405")), files: map[string]string{}}
	if err := os.MkdirAll(b.dir, 0o700); err != nil {
		return nil, err
	}
	for _, p := range paths {
		if p == "" {
			continue
		}
		if !fileExists(p) {
			b.files[p] = ""
			continue
		}
		dst := filepath.Join(b.dir, filepath.Base(p))
		if err := copyFile(p, dst); err != nil {
			return nil, fmt.Errorf("backup %s: %w", p, err)
		}
		b.files[p] = dst
	}
	return b, nil
}

func (b *backup) restore() {
	for p, saved := range b.files {
		if saved == "" {
			os.Remove(p)
			continue
		}
		if err := replaceFile(saved, p); err != nil {
			fmt.Printf("Warning: restore %s failed: %v\n", p, err)
		}
	}
}

func runInstall(args []string) error {
	fs := flag.NewFlagSet("install", flag.ContinueOnError)
	var o bindOptions
	o.register(fs)
	yes := fs.Bool("y", false, "do not prompt")
	fs.BoolVar(yes, "yes", false, "do not prompt")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if err := ensureRoot("install"); err != nil {
		return err
	}
	kernelSet := false
	fs.Visit(func(f *flag.Flag) {
		if f.Name == "kernel" || f.Name == "k" {
			kernelSet = true
		}
	})
	if (o.panelURL == "" || o.token == "" || (o.nodeID <= 0 && o.machineID <= 0)) && !*yes && interactive() {
		if !inMenu {
			printTitle()
			if err := promptLanguage(); err != nil {
				return err
			}
		}
		if !inMenu && !detectServiceManager().installed() {
			ok, err := confirmDefault(tr("First install detected. Configure a node now?", "检测到首次安装，是否现在配置节点？"), true)
			if err != nil {
				return err
			}
			if !ok {
				if err := installSelf(); err != nil {
					return err
				}
				fmt.Println(tr("xnode installed. Run 'xnode' and choose 1 to configure a node later", "xnode 已安装，之后运行 xnode 并选择 1 即可配置节点"))
				return nil
			}
		}
		if err := promptBind(&o, kernelSet); err != nil {
			return err
		}
	}
	if err := o.normalize(); err != nil {
		return err
	}

	svc := detectServiceManager()
	bk, err := newBackup(defaultBinaryPath, defaultConfigPath, defaultCredentialsPath, defaultMetaPath, svc.unitPath())
	if err != nil {
		return err
	}
	fail := func(err error) error {
		fmt.Println(tr("Install failed, rolling back...", "安装失败，正在回滚..."))
		svc.stop()
		bk.restore()
		svc.reload()
		if svc.installed() && fileExists(defaultConfigPath) {
			svc.restart()
		}
		return err
	}

	if svc.installed() {
		svc.stop()
	}
	if err := installSelf(); err != nil {
		return fail(err)
	}
	id, err := bindInstance(o)
	if err != nil {
		return fail(err)
	}
	if err := svc.writeUnit(defaultBinaryPath); err != nil {
		return fail(err)
	}
	svc.reload()
	if err := svc.enable(); err != nil {
		fmt.Printf(tr("Warning: enable service failed: %v\n", "警告：设置开机自启失败：%v\n"), err)
	}
	if err := svc.restart(); err != nil {
		return fail(fmt.Errorf("start service: %w", err))
	}
	if !svc.waitHealthy(o.healthPort, 30*time.Second) {
		svc.recentLogs()
		return fail(errors.New("service failed health check"))
	}

	fmt.Printf(tr("Installed binding %s\n", "已安装节点 %s\n"), id)
	fmt.Printf(tr("  config:      %s\n", "  配置文件：%s\n"), defaultConfigPath)
	fmt.Printf(tr("  credentials: %s\n", "  密钥文件：%s\n"), defaultCredentialsPath)
	if o.healthPort > 0 {
		fmt.Printf(tr("  health:      http://127.0.0.1:%d/healthz\n", "  健康检查：http://127.0.0.1:%d/healthz\n"), o.healthPort)
	}
	fmt.Println(tr("Run 'xnode' for the management menu", "运行 xnode 打开管理菜单"))
	return nil
}

func installSelf() error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	if resolved, err := filepath.EvalSymlinks(exe); err == nil {
		exe = resolved
	}
	if target, err := filepath.EvalSymlinks(defaultBinaryPath); err == nil && target == exe {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(defaultBinaryPath), 0o755); err != nil {
		return err
	}
	if err := replaceFile(exe, defaultBinaryPath); err != nil {
		return fmt.Errorf("install binary: %w", err)
	}
	linkSelf()
	return nil
}

func runUpgrade(args []string) error {
	fs := flag.NewFlagSet("upgrade", flag.ContinueOnError)
	ver := fs.String("version", "latest", "release tag or latest")
	from := fs.String("from", "", "use a local binary instead of downloading")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() > 0 {
		*ver = fs.Arg(0)
	}
	if err := ensureRoot("upgrade"); err != nil {
		return err
	}
	staged := filepath.Join(filepath.Dir(defaultBinaryPath), ".xnode.new"+exeSuffix)
	defer os.Remove(staged)
	if *from != "" {
		if err := copyFile(*from, staged); err != nil {
			return err
		}
	} else {
		asset, err := releaseAsset(runtime.GOOS, runtime.GOARCH)
		if err != nil {
			return err
		}
		url := resolveDownloadURL(asset, *ver)
		fmt.Printf(tr("Downloading %s...\n", "正在下载 %s...\n"), url)
		archive := staged + ".zip"
		defer os.Remove(archive)
		if err := downloadFile(url, archive); err != nil {
			return fmt.Errorf("download: %w", err)
		}
		sums := staged + ".sha256"
		defer os.Remove(sums)
		if err := downloadFile(resolveDownloadURL(checksumAsset, *ver), sums); err != nil {
			return fmt.Errorf("download checksums: %w", err)
		}
		if err := verifyChecksum(archive, sums, asset); err != nil {
			return err
		}
		if err := extractZipFile(archive, appName+exeSuffix, staged); err != nil {
			return fmt.Errorf("extract: %w", err)
		}
	}
	if err := os.Chmod(staged, 0o755); err != nil {
		return err
	}
	out, err := exec.Command(staged, "version").CombinedOutput()
	if err != nil {
		return fmt.Errorf("downloaded binary failed version check: %s", strings.TrimSpace(string(out)))
	}
	newVer := strings.TrimSpace(string(out))

	svc := detectServiceManager()
	bk, err := newBackup(defaultBinaryPath, svc.unitPath())
	if err != nil {
		return err
	}
	if err := replaceFile(staged, defaultBinaryPath); err != nil {
		return fmt.Errorf("replace binary: %w", err)
	}
	linkSelf()
	if svc.installed() {
		if err := svc.writeUnit(defaultBinaryPath); err != nil {
			bk.restore()
			return err
		}
		svc.reload()
		port := configuredHealthPort()
		if err := svc.restart(); err != nil || !svc.waitHealthy(port, 30*time.Second) {
			svc.recentLogs()
			fmt.Println(tr("Upgrade failed, rolling back...", "升级失败，正在回滚..."))
			svc.stop()
			bk.restore()
			svc.reload()
			if e := svc.restart(); e != nil {
				return fmt.Errorf("upgrade and rollback restart both failed: %w", e)
			}
			return errors.New("upgrade failed, previous version restored")
		}
	}
	if root, err := loadWritableRootConfig(defaultConfigPath); err == nil {
		instances, _ := root.NormalizeInstances()
		writeInstallMetaVersioned(defaultMetaPath, root, newVer, latestInstanceID(instances))
	}
	fmt.Printf(tr("Upgraded to %s\n", "已升级到 %s\n"), newVer)
	return nil
}

func runUninstall(args []string) error {
	fs := flag.NewFlagSet("uninstall", flag.ContinueOnError)
	purge := fs.Bool("purge", false, "also delete "+defaultInstallRoot)
	yes := fs.Bool("y", false, "do not prompt")
	fs.BoolVar(yes, "yes", false, "do not prompt")
	if err := fs.Parse(args); err != nil {
		return err
	}
	_, err := uninstall(*purge, *yes)
	return err
}

func uninstall(purge, yes bool) (bool, error) {
	if err := ensureRoot("uninstall"); err != nil {
		return false, err
	}
	if !yes {
		ok, err := confirm(tr("Proceed with uninstall?", "确认卸载？"))
		if !ok || err != nil {
			fmt.Println(tr("Uninstall cancelled", "已取消卸载"))
			return false, nil
		}
		if !purge {
			if purge, err = confirm(tr("Also delete config and credentials?", "同时删除配置和密钥文件？")); err != nil {
				fmt.Println(tr("Uninstall cancelled", "已取消卸载"))
				return false, nil
			}
		}
	}

	var warnings []string
	if svc := detectServiceManager(); svc.installed() {
		warnings = append(warnings, svc.remove()...)
	}
	stale, _ := filepath.Glob(defaultBinaryPath + ".*old")
	for _, p := range append([]string{defaultBinaryPath}, stale...) {
		if err := removeBinary(p); err != nil && !os.IsNotExist(err) {
			warnings = append(warnings, fmt.Sprintf("remove %s: %v", p, err))
		}
	}
	warnings = append(warnings, unlinkSelf()...)
	if purge {
		if err := os.RemoveAll(defaultInstallRoot); err != nil {
			warnings = append(warnings, fmt.Sprintf("remove %s: %v", defaultInstallRoot, err))
		}
		os.Remove(serviceLogPath)
	} else {
		os.Remove(defaultMetaPath)
		fmt.Printf(tr("Config preserved under %s\n", "配置已保留在 %s\n"), defaultInstallRoot)
	}
	for _, w := range warnings {
		fmt.Printf(tr("Warning: %s\n", "警告：%s\n"), w)
	}
	fmt.Println(tr("Uninstall complete", "卸载完成"))
	return true, nil
}

func configuredHealthPort() int {
	root, err := loadWritableRootConfig(defaultConfigPath)
	if err != nil {
		return 0
	}
	if root.HealthPort > 0 {
		return root.HealthPort
	}
	for _, inst := range root.Instances {
		if inst.HealthPort > 0 {
			return inst.HealthPort
		}
	}
	return 0
}
