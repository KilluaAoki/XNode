package nlog

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
	"sync"
	"time"
)

const (
	ColorReset  = "\033[0m"
	ColorGray   = "\033[90m"
	ColorWhite  = "\033[37m"
	ColorYellow = "\033[33m"
	ColorRed    = "\033[31m"
	ColorCyan   = "\033[36m"
	ColorGreen  = "\033[32m"
	ColorBlue   = "\033[34m"
)

type NodeLog struct {
	prefix string
}

var (
	mu          sync.RWMutex
	defaultNode string
	nodeLoggers = make(map[string]*NodeLog)

	logMu     sync.RWMutex
	logWriter io.Writer = os.Stdout
	logMin              = slog.LevelInfo
	logColor            = true
)

func Init(w io.Writer, minLevel slog.Level, color bool) {
	if w == nil {
		w = os.Stdout
	}
	logMu.Lock()
	defer logMu.Unlock()
	logWriter = w
	logMin = minLevel
	logColor = color
}

func formatMsg(msg string, args []any) string {
	if len(args) == 0 {
		return msg
	}
	var b strings.Builder
	b.WriteString(msg)
	for i := 0; i < len(args); i += 2 {
		if i+1 < len(args) {
			fmt.Fprintf(&b, " %v=%v", args[i], args[i+1])
		} else {
			fmt.Fprintf(&b, " %v", args[i])
		}
	}
	return b.String()
}

func SetDefault(prefix string) {
	mu.Lock()
	defaultNode = prefix
	mu.Unlock()
}

func ForNode(protocol string, port int) *NodeLog {
	key := fmt.Sprintf("%s:%d", normalizeProto(protocol), port)
	mu.RLock()
	if nl, ok := nodeLoggers[key]; ok {
		mu.RUnlock()
		return nl
	}
	mu.RUnlock()

	mu.Lock()
	defer mu.Unlock()
	if nl, ok := nodeLoggers[key]; ok {
		return nl
	}
	nl := &NodeLog{prefix: key}
	nodeLoggers[key] = nl
	return nl
}

func Core() *NodeLog {
	mu.RLock()
	if nl, ok := nodeLoggers["core"]; ok {
		mu.RUnlock()
		return nl
	}
	mu.RUnlock()

	mu.Lock()
	defer mu.Unlock()
	if nl, ok := nodeLoggers["core"]; ok {
		return nl
	}
	nl := &NodeLog{prefix: "core"}
	nodeLoggers["core"] = nl
	return nl
}

func normalizeProto(p string) string {
	switch strings.ToLower(p) {
	case "shadowsocks", "ss":
		return "shadowsocks"
	case "vmess":
		return "vmess"
	case "vless":
		return "vless"
	case "trojan":
		return "trojan"
	case "hysteria2", "hysteria":
		return "hysteria2"
	case "tuic":
		return "tuic"
	case "anytls":
		return "anytls"
	case "naive":
		return "naive"
	case "http":
		return "http"
	case "socks":
		return "socks"
	default:
		return p
	}
}

func (nl *NodeLog) Debug(msg string, args ...any) {
	logWithColor(slog.LevelDebug, nl.prefix, msg, args...)
}

func (nl *NodeLog) Info(msg string, args ...any) {
	logWithColor(slog.LevelInfo, nl.prefix, msg, args...)
}

func (nl *NodeLog) Warn(msg string, args ...any) {
	logWithColor(slog.LevelWarn, nl.prefix, msg, args...)
}

func (nl *NodeLog) Error(msg string, args ...any) {
	logWithColor(slog.LevelError, nl.prefix, msg, args...)
}

func logWithColor(level slog.Level, prefix, msg string, args ...any) {
	logMu.RLock()
	out := logWriter
	min := logMin
	color := logColor
	logMu.RUnlock()

	if level < min {
		return
	}

	now := time.Now().Format("15:04:05.000")
	fullMsg := formatMsg(msg, args)

	var levelStr string
	switch level {
	case slog.LevelDebug:
		levelStr = "DEBUG"
	case slog.LevelInfo:
		levelStr = "INFO "
	case slog.LevelWarn:
		levelStr = "WARN "
	case slog.LevelError:
		levelStr = "ERROR"
	default:
		levelStr = "?????"
	}

	if !color {
		fmt.Fprintf(out, "%s %s [%s] %s\n", now, strings.TrimSpace(levelStr), prefix, fullMsg)
		return
	}

	var levelColor string
	switch level {
	case slog.LevelDebug:
		levelColor = ColorGreen
	case slog.LevelInfo:
		levelColor = ColorWhite
	case slog.LevelWarn:
		levelColor = ColorYellow
	case slog.LevelError:
		levelColor = ColorRed
	default:
		levelColor = ColorWhite
	}

	prefixColor := ColorCyan
	if prefix == "core" {
		prefixColor = ColorBlue
	}

	fmt.Fprintf(out, "%s%s%s %s%s%s %s[%s]%s %s\n",
		ColorGray, now, ColorReset,
		levelColor, levelStr, ColorReset,
		prefixColor, prefix, ColorReset,
		fullMsg,
	)
}

type StartupSummary struct {
	mu    sync.Mutex
	nodes []nodeInfo
}

type nodeInfo struct {
	Protocol string
	Port     int
	Users    int
}

func NewStartupSummary() *StartupSummary {
	return &StartupSummary{}
}

func (s *StartupSummary) AddNode(protocol string, port, users int) {
	s.mu.Lock()
	s.nodes = append(s.nodes, nodeInfo{protocol, port, users})
	s.mu.Unlock()
}

func (s *StartupSummary) Print() {
	s.mu.Lock()
	defer s.mu.Unlock()

	if len(s.nodes) == 0 {
		Core().Warn("no nodes configured")
		return
	}

	byProto := make(map[string][]nodeInfo)
	for _, n := range s.nodes {
		proto := normalizeProto(n.Protocol)
		byProto[proto] = append(byProto[proto], n)
	}

	parts := make([]string, 0, len(byProto))
	for proto, nodes := range byProto {
		ports := make([]string, 0, len(nodes))
		for _, n := range nodes {
			ports = append(ports, fmt.Sprintf("%d", n.Port))
		}
		parts = append(parts, fmt.Sprintf("%s:%s", proto, strings.Join(ports, ",")))
	}

	Core().Info(fmt.Sprintf("started %d nodes: %s", len(s.nodes), strings.Join(parts, " | ")))
}

func ConfigUpdated(nl *NodeLog, users int) {
	nl.Info(fmt.Sprintf("config updated, %d users", users))
}

func HotReload(nl *NodeLog, what string) {
	nl.Debug(fmt.Sprintf("hot-reload: %s", what))
}

func FullRestart(nl *NodeLog, reason string) {
	nl.Info(fmt.Sprintf("kernel restart: %s", reason))
}

func ReportPushed(users, online int) {
	Core().Info(fmt.Sprintf("report pushed: %d users, %d online", users, online))
}

func TrackerStats(conns, users int) {
	Core().Debug(fmt.Sprintf("tracker: %d conns, %d users online", conns, users))
}

type ctxKey struct{}

func WithNode(ctx context.Context, nl *NodeLog) context.Context {
	return context.WithValue(ctx, ctxKey{}, nl)
}

func FromContext(ctx context.Context) *NodeLog {
	if nl, ok := ctx.Value(ctxKey{}).(*NodeLog); ok {
		return nl
	}
	return Core()
}
