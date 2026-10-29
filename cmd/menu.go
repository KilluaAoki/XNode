package cmd

import (
	"bufio"
	"errors"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"strings"
	"time"

	"golang.org/x/text/width"
)

const (
	colorRed    = "\033[0;31m"
	colorGreen  = "\033[0;32m"
	colorYellow = "\033[0;33m"
	colorReset  = "\033[0m"
)

const (
	promptAttempts = 3
	menuWidth      = 40
)

var menuRule = strings.Repeat("-", menuWidth)

func displayWidth(s string) int {
	n := 0
	for _, r := range s {
		switch width.LookupRune(r).Kind() {
		case width.EastAsianWide, width.EastAsianFullwidth:
			n += 2
		default:
			n++
		}
	}
	return n
}

func centerIndent(w int) string {
	if w >= menuWidth {
		return ""
	}
	return strings.Repeat(" ", (menuWidth-w)/2)
}

var (
	stdin          = bufio.NewReader(os.Stdin)
	pendingLine    chan lineResult
	interrupts     <-chan os.Signal
	errInterrupted = fmt.Errorf("%w: interrupted", errCancelled)
)

type lineResult struct {
	line string
	err  error
}

func nextLine() (string, error) {
	select {
	case <-interrupts:
	default:
	}
	if pendingLine == nil {
		ch := make(chan lineResult, 1)
		r := stdin
		go func() {
			line, err := r.ReadString('\n')
			ch <- lineResult{line, err}
		}()
		pendingLine = ch
	}
	select {
	case res := <-pendingLine:
		pendingLine = nil
		return res.line, res.err
	case <-interrupts:
		fmt.Println()
		return "", errInterrupted
	}
}

func readLine(prompt, def string) (string, error) {
	if def != "" {
		fmt.Printf("%s [%s]: ", prompt, def)
	} else {
		fmt.Printf("%s: ", prompt)
	}
	line, err := nextLine()
	if line = strings.TrimSpace(line); line != "" {
		return line, nil
	}
	if errors.Is(err, errInterrupted) {
		return "", err
	}
	if err != nil {
		fmt.Println()
		return "", errCancelled
	}
	return def, nil
}

func printError(msg string) {
	fmt.Println(colorRed + msg + colorReset)
}

func readValid(prompt, def string, check func(string) error) (string, error) {
	for i := 0; i < promptAttempts; i++ {
		v, err := readLine(prompt, def)
		if err != nil {
			return "", err
		}
		if err = check(v); err == nil {
			return v, nil
		}
		printError(err.Error())
	}
	return "", errCancelled
}

func readPositive(prompt string, def int) (int, error) {
	d := ""
	if def > 0 {
		d = strconv.Itoa(def)
	}
	raw, err := readValid(prompt, d, func(s string) error {
		if n, err := strconv.Atoi(s); err != nil || n <= 0 {
			return errors.New(tr("Enter a positive integer", "请输入正整数"))
		}
		return nil
	})
	if err != nil {
		return 0, err
	}
	return strconv.Atoi(raw)
}

type choice struct {
	value   string
	label   string
	aliases []string
}

func (c choice) matches(s string) bool {
	if s == c.value {
		return true
	}
	for _, a := range c.aliases {
		if s == a {
			return true
		}
	}
	return false
}

func readChoice(title string, options []choice, def string) (string, error) {
	fmt.Println(title)
	defKey := ""
	for i, o := range options {
		label := o.label
		if label == "" {
			label = o.value
		}
		fmt.Printf("  %s%2d.%s %s\n", colorGreen, i+1, colorReset, label)
		if o.matches(def) {
			defKey = strconv.Itoa(i + 1)
		}
	}
	var picked string
	_, err := readValid(tr("Select", "请选择"), defKey, func(s string) error {
		s = strings.ToLower(s)
		for i, o := range options {
			if s == strconv.Itoa(i+1) || o.matches(s) {
				picked = o.value
				return nil
			}
		}
		return errors.New(tr("Invalid choice", "无效选项"))
	})
	return picked, err
}

func confirm(prompt string) (bool, error) {
	return confirmDefault(prompt, false)
}

func confirmDefault(prompt string, def bool) (bool, error) {
	hint := " [y/N]"
	if def {
		hint = " [Y/n]"
	}
	answer, err := readLine(prompt+hint, "")
	switch strings.ToLower(answer) {
	case "y", "yes":
		return true, err
	case "":
		return def && err == nil, err
	}
	return false, err
}

var nodeTypes = []choice{
	{value: "vless"},
	{value: "vmess", aliases: []string{"v2ray"}},
	{value: "trojan"},
	{value: "shadowsocks", aliases: []string{"ss"}},
	{value: "hysteria", label: "hysteria (hysteria2)", aliases: []string{"hysteria2", "hy2"}},
	{value: "tuic"},
	{value: "anytls"},
	{value: "naive"},
	{value: "socks"},
	{value: "http"},
	{value: "mieru"},
}

var xrayNodeTypes = map[string]bool{"vless": true, "vmess": true, "trojan": true, "shadowsocks": true, "hysteria": true}

func canonicalNodeType(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	for _, c := range nodeTypes {
		if c.matches(s) {
			return c.value
		}
	}
	return s
}

func checkPanelURL(s string) error {
	u, err := url.Parse(strings.TrimSpace(s))
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return errors.New(tr("Enter a URL starting with http:// or https://", "请输入以 http:// 或 https:// 开头的地址"))
	}
	return nil
}

func checkRequired(s string) error {
	if strings.TrimSpace(s) == "" {
		return errors.New(tr("This field is required", "此项必填"))
	}
	return nil
}

func promptLanguage() error {
	if os.Getenv("XNODE_LANG") != "" || fileExists(langPath()) {
		return nil
	}
	def := "en"
	if langZH {
		def = "zh"
	}
	picked, err := readChoice("Language / 语言", []choice{
		{value: "en", label: "English", aliases: []string{"english"}},
		{value: "zh", label: "中文", aliases: []string{"chinese", "cn", "中文"}},
	}, def)
	if err != nil {
		return err
	}
	langZH = picked == "zh"
	saveLang()
	return nil
}

func printTitle() {
	title := "XNode " + version
	fmt.Printf("\n%s%sXNode%s %s\n", centerIndent(displayWidth(title)), colorGreen, colorReset, version)
	fmt.Printf("%s%s\n", centerIndent(displayWidth(repoURL)), repoURL)
	fmt.Println(menuRule)
}

func promptBind(o *bindOptions, kernelSet bool) error {
	var err error
	if o.panelURL == "" {
		if o.panelURL, err = readValid(tr("Panel URL", "面板地址"), "", checkPanelURL); err != nil {
			return err
		}
	}
	if o.token == "" {
		if o.token, err = readValid(tr("Panel token", "通信密钥"), "", checkRequired); err != nil {
			return err
		}
	}
	if o.mode == "" && o.nodeID <= 0 && o.machineID <= 0 {
		if o.mode, err = readChoice(tr("Binding mode", "绑定方式"), []choice{
			{value: "node", label: tr("Node (node ID)", "节点（节点 ID）")},
			{value: "machine", label: tr("Machine (machine ID)", "机器（机器 ID）")},
		}, "node"); err != nil {
			return err
		}
	}
	if o.mode == "machine" || o.machineID > 0 {
		if o.machineID <= 0 {
			if o.machineID, err = readPositive(tr("Machine ID", "机器 ID"), 0); err != nil {
				return err
			}
		}
		return nil
	}
	if o.nodeID <= 0 {
		if o.nodeID, err = readPositive(tr("Node ID", "节点 ID"), 0); err != nil {
			return err
		}
	}
	if o.nodeType == "" {
		if o.nodeType, err = readChoice(tr("Node type", "节点协议"), nodeTypes, "vless"); err != nil {
			return err
		}
	}
	o.nodeType = canonicalNodeType(o.nodeType)
	if kernelSet {
		return nil
	}
	if !xrayNodeTypes[o.nodeType] {
		o.kernel = "singbox"
		fmt.Printf(tr("Kernel: singbox (%s is not supported by xray)\n", "内核：singbox（xray 不支持 %s）\n"), o.nodeType)
		return nil
	}
	o.kernel, err = readChoice(tr("Kernel", "内核"), []choice{
		{value: "singbox", label: "sing-box", aliases: []string{"sing-box", "sing"}},
		{value: "xray", label: "Xray"},
	}, o.kernel)
	return err
}

func withInterruptShield(fn func() error) error {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, os.Interrupt)
	interrupts = ch
	defer func() {
		signal.Stop(ch)
		interrupts = nil
	}()
	return fn()
}

type menuItem struct {
	key string
	en  string
	zh  string
	run func() error
}

const languageKey = "18"

var (
	inMenu      bool
	errMenuExit = errors.New("exit menu")
)

func toggleLanguage() error {
	langZH = !langZH
	if err := saveLang(); err != nil {
		fmt.Printf(colorYellow+tr("Language not saved: %v", "语言设置未保存：%v")+colorReset+"\n", err)
	}
	return nil
}

func runMenu() error {
	inMenu = true
	defer func() { inMenu = false }()
	svc := detectServiceManager()
	items := []menuItem{
		{"1", "Install or add binding", "安装或添加节点", func() error { return runInstall(nil) }},
		{"2", "Upgrade", "升级", menuUpgrade},
		{"3", "Uninstall", "卸载", menuUninstall},
		{},
		{"4", "Start", "启动", menuService(svc, "start")},
		{"5", "Stop", "停止", menuService(svc, "stop")},
		{"6", "Restart", "重启", menuService(svc, "restart")},
		{"7", "Status", "查看状态", func() error { return runStatus() }},
		{"8", "Logs", "查看日志", func() error {
			if !svc.installed() {
				return errNotInstalled()
			}
			if err := svc.logs(nil); err != nil && !errors.As(err, new(*exec.ExitError)) {
				return err
			}
			return nil
		}},
		{},
		{"9", "Enable autostart", "设置开机自启", menuService(svc, "enable")},
		{"10", "Disable autostart", "取消开机自启", menuService(svc, "disable")},
		{},
		{"11", "List bindings", "查看节点列表", func() error { return runList(nil) }},
		{"12", "Remove binding", "删除节点", menuRemoveBinding},
		{"13", "Edit config", "编辑配置", func() error { return runConfig([]string{"edit"}) }},
		{"14", "Generate x25519 key", "生成 X25519 密钥", func() error { return runX25519(nil) }},
		{"15", "Generate ML-KEM-768 key", "生成 ML-KEM-768 密钥", func() error { return runMLKEM768(nil) }},
		{"16", "Enable BBR", "开启 BBR", runBBR},
		{"17", "Version", "查看版本", func() error { return run([]string{"version"}) }},
		{languageKey, "中文 / Language", "English / 语言", toggleLanguage},
	}
	notice := ""
	for {
		fmt.Print("\033[H\033[2J")
		exit := menuItem{key: "0", en: "Exit", zh: "退出"}
		block := 0
		for _, it := range append(items, exit) {
			if w := displayWidth(fmt.Sprintf("%2s. %s", it.key, tr(it.en, it.zh))); it.key != "" && w > block {
				block = w
			}
		}
		indent := centerIndent(block)
		printTitle()
		for _, it := range append(items, exit) {
			if it.key == "" {
				fmt.Println(menuRule)
				continue
			}
			fmt.Printf("%s%s%2s.%s %s\n", indent, colorGreen, it.key, colorReset, tr(it.en, it.zh))
		}
		fmt.Println(menuRule)
		printServiceStatus(svc)
		fmt.Println(menuRule)
		if notice != "" {
			printError(notice)
			notice = ""
		}

		key, err := readLine(fmt.Sprintf("%s [0-%s]", tr("Select", "请选择"), languageKey), "")
		if err != nil || key == "0" || key == "q" {
			return nil
		}
		if key == "" {
			continue
		}
		var selected *menuItem
		for i := range items {
			if items[i].key == key {
				selected = &items[i]
			}
		}
		if selected == nil {
			notice = tr("Invalid choice", "无效选项")
			continue
		}
		err = withInterruptShield(selected.run)
		if errors.Is(err, errMenuExit) {
			return nil
		}
		if err != nil && !errors.Is(err, errCancelled) {
			printError(err.Error())
		}
		if selected.key != languageKey && !errors.Is(err, errInterrupted) {
			readLine(tr("Press Enter to continue", "按回车键继续"), "")
		}
	}
}

type statusLine struct {
	label, value, color, suffix string
}

func printServiceStatus(svc serviceManager) {
	service := statusLine{label: tr("Service: ", "服务状态："), value: tr("not installed", "未安装"), color: colorRed}
	lines := []statusLine{service}
	if svc.installed() {
		raw := svc.state()
		service.value, service.color, service.suffix = stateLabel(raw), colorYellow, fmt.Sprintf(" (%s)", svc.kind)
		switch raw {
		case "active":
			service.color = colorGreen
		case "failed", "inactive":
			service.color = colorRed
		}
		auto := statusLine{label: tr("Autostart: ", "开机自启："), value: tr("no", "否"), color: colorRed}
		if svc.enabled() {
			auto.value, auto.color = tr("yes", "是"), colorGreen
		}
		lines = []statusLine{service, auto}
	}
	block := 0
	for _, l := range lines {
		block = max(block, displayWidth(l.label+l.value+l.suffix))
	}
	indent := centerIndent(block)
	for _, l := range lines {
		fmt.Printf("%s%s%s%s%s%s\n", indent, l.label, l.color, l.value, colorReset, l.suffix)
	}
}

func stateLabel(state string) string {
	switch state {
	case "active":
		return tr("running", "运行中")
	case "inactive":
		return tr("stopped", "已停止")
	case "failed":
		return tr("failed", "异常")
	case "activating":
		return tr("starting", "启动中")
	case "deactivating":
		return tr("stopping", "停止中")
	case "unknown", "":
		return tr("unknown", "未知")
	}
	return state
}

func errNotInstalled() error {
	return errors.New(tr("service is not installed; install first", "服务未安装，请先安装"))
}

func serviceNoop(svc serviceManager, action string) string {
	switch action {
	case "start":
		if svc.active() {
			return tr("Service is already running; choose Restart to restart it", "服务已在运行，如需重启请选择重启")
		}
	case "stop":
		if state := svc.state(); state == "inactive" || state == "failed" {
			return tr("Service is not running", "服务未在运行")
		}
	case "enable":
		if svc.enabled() {
			return tr("Autostart is already enabled", "已是开机自启，无需重复设置")
		}
	case "disable":
		if !svc.enabled() {
			return tr("Autostart is already disabled", "开机自启未开启，无需取消")
		}
	}
	return ""
}

func menuService(svc serviceManager, action string) func() error {
	return func() error {
		if !svc.installed() {
			return errNotInstalled()
		}
		if skip := serviceNoop(svc, action); skip != "" {
			fmt.Println(colorYellow + skip + colorReset)
			return nil
		}
		if err := svc.control(action); err != nil {
			return err
		}
		var msg string
		switch action {
		case "start", "restart":
			deadline := time.Now().Add(5 * time.Second)
			for !svc.active() {
				if time.Now().After(deadline) {
					fmt.Println(tr("Recent logs:", "最近日志："))
					svc.recentLogs()
					return errors.New(tr("service did not start; see the logs above", "服务未能启动，请检查以上日志"))
				}
				time.Sleep(500 * time.Millisecond)
			}
			msg = tr("Service started", "服务已启动")
			if action == "restart" {
				msg = tr("Service restarted", "服务已重启")
			}
		case "stop":
			msg = tr("Service stopped", "服务已停止")
		case "enable":
			msg = tr("Autostart enabled", "已设置开机自启")
		case "disable":
			msg = tr("Autostart disabled", "已取消开机自启")
		}
		fmt.Println(colorGreen + msg + colorReset)
		return nil
	}
}

func menuUpgrade() error {
	if err := ensureRoot("upgrade"); err != nil {
		return err
	}
	ver, err := readLine(tr("Version", "版本"), "latest")
	if err != nil {
		return err
	}
	if err := runUpgrade([]string{"--version", ver}); err != nil {
		return err
	}
	fmt.Println(tr("Run 'xnode' again to use the new version", "重新运行 xnode 以使用新版本"))
	return errMenuExit
}

func menuUninstall() error {
	done, err := uninstall(false, false)
	if err != nil {
		return err
	}
	if done {
		return errMenuExit
	}
	return nil
}

func menuRemoveBinding() error {
	if err := ensureRoot("remove binding"); err != nil {
		return err
	}
	rows, err := collectInstanceRows()
	if err != nil {
		return err
	}
	if len(rows) == 0 {
		return errNoBindings()
	}
	options := make([]choice, 0, len(rows))
	for _, row := range rows {
		options = append(options, choice{value: row.ID, label: fmt.Sprintf("%s  %s  %s", row.ID, row.Panel, row.Target)})
	}
	id, err := readChoice(tr("Binding to remove", "选择要删除的节点"), options, "")
	if err != nil {
		return err
	}
	if ok, err := confirm(fmt.Sprintf(tr("Remove %s?", "确认删除 %s？"), id)); !ok || err != nil {
		return errCancelled
	}
	return removeBinding("", 0, 0, id)
}

func runConfig(args []string) error {
	sub := "show"
	if len(args) > 0 {
		sub = args[0]
	}
	switch sub {
	case "path":
		fmt.Println(defaultConfigPath)
		return nil
	case "show":
		data, err := os.ReadFile(defaultConfigPath)
		if err != nil {
			return err
		}
		os.Stdout.Write(data)
		return nil
	case "edit":
		if err := ensureRoot("config edit"); err != nil {
			return err
		}
		if !fileExists(defaultConfigPath) {
			return errors.New(tr("config not found; install first", "配置文件不存在，请先安装"))
		}
		editor := os.Getenv("EDITOR")
		if editor == "" {
			for _, e := range []string{"nano", "vim", "vi", "notepad"} {
				if commandExists(e) {
					editor = e
					break
				}
			}
		}
		if editor == "" {
			return errors.New(tr("no editor found; set $EDITOR", "未找到编辑器，请设置 $EDITOR"))
		}
		cmd := exec.Command(editor, defaultConfigPath)
		cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
		if err := cmd.Run(); err != nil {
			return err
		}
		fmt.Println(tr("Saved; a running node reloads the config automatically", "已保存，运行中的节点会自动重载配置"))
		return nil
	default:
		return fmt.Errorf("unknown config command: %s", sub)
	}
}
