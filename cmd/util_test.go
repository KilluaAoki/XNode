package cmd

import (
	"archive/zip"
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestReleaseAsset(t *testing.T) {
	cases := map[[2]string]string{
		{"linux", "amd64"}:   "xnode-linux-64.zip",
		{"linux", "arm64"}:   "xnode-linux-arm64-v8a.zip",
		{"linux", "arm"}:     "xnode-linux-arm32-v7a.zip",
		{"darwin", "amd64"}:  "xnode-macos-64.zip",
		{"darwin", "arm64"}:  "xnode-macos-arm64-v8a.zip",
		{"windows", "amd64"}: "xnode-windows-64.zip",
		{"windows", "arm64"}: "xnode-windows-arm64-v8a.zip",
	}
	for in, want := range cases {
		got, err := releaseAsset(in[0], in[1])
		if err != nil || got != want {
			t.Fatalf("releaseAsset(%s, %s) = %q, %v; want %q", in[0], in[1], got, err, want)
		}
	}
	for _, in := range [][2]string{{"windows", "arm"}, {"windows", "386"}, {"linux", "386"}, {"darwin", "arm"}, {"freebsd", "amd64"}} {
		if _, err := releaseAsset(in[0], in[1]); err == nil {
			t.Fatalf("releaseAsset(%s, %s) should fail", in[0], in[1])
		}
	}
}

func TestExtractZipFile(t *testing.T) {
	dir := t.TempDir()
	archive := filepath.Join(dir, "xnode.zip")
	f, err := os.Create(archive)
	if err != nil {
		t.Fatal(err)
	}
	w := zip.NewWriter(f)
	for name, body := range map[string]string{"README.md": "readme", "xnode": "binary"} {
		e, err := w.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		e.Write([]byte(body))
	}
	w.Close()
	f.Close()

	dest := filepath.Join(dir, "out")
	if err := extractZipFile(archive, "xnode", dest); err != nil {
		t.Fatal(err)
	}
	if data, _ := os.ReadFile(dest); string(data) != "binary" {
		t.Fatalf("extracted %q", data)
	}
	if err := extractZipFile(archive, "missing", dest); err == nil {
		t.Fatal("missing entry should fail")
	}
}

func TestEditPathList(t *testing.T) {
	dir := `C:\Program Files\xnode`
	cases := []struct {
		list string
		add  bool
		want string
	}{
		{"", true, dir},
		{`C:\Windows;C:\Windows\System32`, true, `C:\Windows;C:\Windows\System32;` + dir},
		{`C:\Windows;`, true, `C:\Windows;` + dir},
		{`C:\Windows;c:\program files\XNODE\`, true, `C:\Windows;c:\program files\XNODE\`},
		{`C:\Windows;` + dir + `;C:\Tools`, false, `C:\Windows;C:\Tools`},
		{`C:\Windows;"` + dir + `"`, false, `C:\Windows`},
		{`C:\Windows`, false, `C:\Windows`},
	}
	for _, c := range cases {
		if got := editPathList(c.list, dir, c.add); got != c.want {
			t.Fatalf("editPathList(%q, add=%v) = %q, want %q", c.list, c.add, got, c.want)
		}
	}
}

func TestParseTailArgs(t *testing.T) {
	cases := []struct {
		args   []string
		lines  int
		follow bool
	}{
		{nil, 100, true},
		{[]string{"-n", "20"}, 20, false},
		{[]string{"-f", "-n", "5"}, 5, true},
		{[]string{"--lines", "0", "--follow"}, 0, true},
	}
	for _, c := range cases {
		lines, follow, err := parseTailArgs(c.args)
		if err != nil || lines != c.lines || follow != c.follow {
			t.Fatalf("parseTailArgs(%v) = %d, %v, %v", c.args, lines, follow, err)
		}
	}
	for _, args := range [][]string{{"-n"}, {"-n", "x"}, {"-n", "-1"}, {"--bogus"}} {
		if _, _, err := parseTailArgs(args); err == nil {
			t.Fatalf("parseTailArgs(%v) should fail", args)
		}
	}
}

func TestLastLines(t *testing.T) {
	data := []byte("a\nb\nc\n")
	cases := map[int]string{0: "", 1: "c\n", 2: "b\nc\n", 3: "a\nb\nc\n", 9: "a\nb\nc\n"}
	for n, want := range cases {
		if got := string(lastLines(data, n)); got != want {
			t.Fatalf("lastLines(%d) = %q, want %q", n, got, want)
		}
	}
	if got := string(lastLines([]byte("a\nb"), 1)); got != "b" {
		t.Fatalf("lastLines without trailing newline = %q", got)
	}
}

func TestTailFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "xnode.log")
	if err := os.WriteFile(path, []byte("one\ntwo\nthree\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := tailFile(path, 2, false, &out, nil); err != nil {
		t.Fatal(err)
	}
	if out.String() != "two\nthree\n" {
		t.Fatalf("tailFile = %q", out.String())
	}
}

func TestReplaceFile(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "new")
	dst := filepath.Join(dir, "xnode")
	os.WriteFile(src, []byte("v2"), 0o755)
	os.WriteFile(dst, []byte("v1"), 0o755)
	os.WriteFile(dst+".old", []byte("stale"), 0o755)
	if err := replaceFile(src, dst); err != nil {
		t.Fatal(err)
	}
	if data, _ := os.ReadFile(dst); string(data) != "v2" {
		t.Fatalf("replaceFile wrote %q", data)
	}
	tmp := filepath.Join(dir, "tmp")
	os.WriteFile(tmp, []byte("v3"), 0o755)
	if err := swapInUseFile(tmp, dst); err != nil {
		t.Fatal(err)
	}
	if data, _ := os.ReadFile(dst); string(data) != "v3" {
		t.Fatalf("swapInUseFile wrote %q", data)
	}
	if matches, _ := filepath.Glob(dst + ".*old"); len(matches) != 0 {
		t.Fatalf("stale backups left: %v", matches)
	}
}

func feedInput(t *testing.T, input string) {
	t.Helper()
	t.Setenv("XNODE_LANG", "en")
	devnull, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	prev, prevZH, prevOut := stdin, langZH, os.Stdout
	stdin = bufio.NewReader(strings.NewReader(input))
	langZH = false
	os.Stdout = devnull
	pendingLine, interrupts = nil, nil
	t.Cleanup(func() {
		stdin, langZH, os.Stdout = prev, prevZH, prevOut
		pendingLine, interrupts = nil, nil
		devnull.Close()
	})
}

func TestReadLineInterrupt(t *testing.T) {
	feedInput(t, "")
	pr, pw := io.Pipe()
	t.Cleanup(func() { pw.Close() })
	stdin = bufio.NewReader(pr)
	ch := make(chan os.Signal, 1)
	interrupts = ch
	go func() {
		time.Sleep(50 * time.Millisecond)
		ch <- os.Interrupt
	}()
	if _, err := readValid("x", "d", checkRequired); !errors.Is(err, errInterrupted) {
		t.Fatalf("want errInterrupted, got %v", err)
	}
	interrupts = nil
	go pw.Write([]byte("next\n"))
	if v, err := readLine("x", ""); err != nil || v != "next" {
		t.Fatalf("got %q, %v", v, err)
	}
}

func TestPromptBind_Full(t *testing.T) {
	feedInput(t, "panel.example.com\nhttps://panel.example.com\ntok\n\nabc\n0\n7\nhysteria2\n2\n")
	o := bindOptions{kernel: "singbox"}
	if err := promptBind(&o, false); err != nil {
		t.Fatal(err)
	}
	if o.panelURL != "https://panel.example.com" || o.token != "tok" || o.nodeID != 7 || o.nodeType != "hysteria" || o.kernel != "xray" {
		t.Fatalf("unexpected options: %+v", o)
	}
}

func TestPromptBind_SkipsGivenAndForcesSingbox(t *testing.T) {
	feedInput(t, "11\n")
	o := bindOptions{panelURL: "https://p", token: "t", nodeID: 3, kernel: "xray"}
	if err := promptBind(&o, false); err != nil {
		t.Fatal(err)
	}
	if o.nodeType != "mieru" || o.kernel != "singbox" {
		t.Fatalf("unexpected options: %+v", o)
	}
}

func TestPromptBind_DefaultsAndKernelFlag(t *testing.T) {
	feedInput(t, "\n")
	o := bindOptions{panelURL: "https://p", token: "t", nodeID: 3, kernel: "xray"}
	if err := promptBind(&o, true); err != nil {
		t.Fatal(err)
	}
	if o.nodeType != "vless" || o.kernel != "xray" {
		t.Fatalf("unexpected options: %+v", o)
	}
}

func TestPromptBind_Machine(t *testing.T) {
	feedInput(t, "5\n")
	o := bindOptions{panelURL: "https://p", token: "t", mode: "machine"}
	if err := promptBind(&o, false); err != nil {
		t.Fatal(err)
	}
	if o.machineID != 5 || o.nodeID != 0 || o.nodeType != "" {
		t.Fatalf("unexpected options: %+v", o)
	}
}

func TestPromptBind_ChooseMachine(t *testing.T) {
	feedInput(t, "https://p\nt\n2\n9\n")
	o := bindOptions{kernel: "singbox"}
	if err := promptBind(&o, false); err != nil {
		t.Fatal(err)
	}
	if o.mode != "machine" || o.machineID != 9 || o.nodeID != 0 || o.nodeType != "" {
		t.Fatalf("unexpected options: %+v", o)
	}
}

func TestPromptBind_GivesUpOnEOF(t *testing.T) {
	feedInput(t, "")
	o := bindOptions{}
	if err := promptBind(&o, false); !errors.Is(err, errCancelled) {
		t.Fatalf("want errCancelled, got %v", err)
	}
}

func TestCanonicalNodeType(t *testing.T) {
	cases := map[string]string{"V2Ray": "vmess", " hysteria2 ": "hysteria", "ss": "shadowsocks", "vless": "vless", "custom": "custom", "": ""}
	for in, want := range cases {
		if got := canonicalNodeType(in); got != want {
			t.Errorf("%q: got %q, want %q", in, got, want)
		}
	}
}

func TestLanguageDetection(t *testing.T) {
	for _, tag := range []string{"zh_CN.UTF-8", "zh-Hans-CN", "ZH", "zh"} {
		if !isChineseTag(tag) {
			t.Errorf("%q should be Chinese", tag)
		}
	}
	for _, tag := range []string{"en_US.UTF-8", "C", "", "ja-JP"} {
		if isChineseTag(tag) {
			t.Errorf("%q should not be Chinese", tag)
		}
	}
	prev := langZH
	defer func() { langZH = prev }()
	t.Setenv("XNODE_LANG", "zh")
	initLang()
	if !langZH || tr("a", "b") != "b" {
		t.Fatal("XNODE_LANG=zh not applied")
	}
	t.Setenv("XNODE_LANG", "en")
	initLang()
	if langZH || tr("a", "b") != "a" {
		t.Fatal("XNODE_LANG=en not applied")
	}
}

func TestMenuCentering(t *testing.T) {
	cases := map[string]int{"": 0, "abc": 3, "中文": 4, "服务：未安装": 12, "14. 生成 X25519 密钥": 20}
	for in, want := range cases {
		if got := displayWidth(in); got != want {
			t.Errorf("%q: got %d, want %d", in, got, want)
		}
	}
	if got := centerIndent(20); got != strings.Repeat(" ", 10) {
		t.Errorf("centerIndent(20) = %q", got)
	}
	if got := centerIndent(menuWidth + 5); got != "" {
		t.Errorf("overflow indent = %q", got)
	}
}

func TestConfirmDefault(t *testing.T) {
	cases := []struct {
		input string
		def   bool
		want  bool
	}{
		{"\n", true, true},
		{"\n", false, false},
		{"n\n", true, false},
		{"Y\n", false, true},
		{"yes\n", false, true},
		{"x\n", true, false},
	}
	for _, c := range cases {
		feedInput(t, c.input)
		if got, err := confirmDefault("q", c.def); err != nil || got != c.want {
			t.Fatalf("confirmDefault(%q, %v) = %v, %v; want %v", c.input, c.def, got, err, c.want)
		}
	}
	feedInput(t, "")
	if got, err := confirmDefault("q", true); got || !errors.Is(err, errCancelled) {
		t.Fatalf("EOF: got %v, %v", got, err)
	}
}

func TestVerifyChecksum(t *testing.T) {
	dir := t.TempDir()
	archive := filepath.Join(dir, "a.zip")
	if err := os.WriteFile(archive, []byte("payload"), 0o644); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte("payload"))
	good := hex.EncodeToString(sum[:])
	writeSums := func(body string) string {
		p := filepath.Join(dir, "sums.txt")
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}

	other := strings.Repeat("0", 64)
	if err := verifyChecksum(archive, writeSums(other+"  xnode-macos-64.zip\n"+good+"  xnode-linux-64.zip\n"), "xnode-linux-64.zip"); err != nil {
		t.Fatalf("matching entry: %v", err)
	}
	if err := verifyChecksum(archive, writeSums(strings.ToUpper(good)+" *xnode-linux-64.zip\n"), "xnode-linux-64.zip"); err != nil {
		t.Fatalf("binary-mode entry: %v", err)
	}
	if err := verifyChecksum(archive, writeSums(other+"  xnode-linux-64.zip\n"), "xnode-linux-64.zip"); err == nil {
		t.Fatal("expected mismatch error")
	}
	if err := verifyChecksum(archive, writeSums(good+"  xnode-macos-64.zip\n"), "xnode-linux-64.zip"); err == nil {
		t.Fatal("expected missing-entry error")
	}
}
