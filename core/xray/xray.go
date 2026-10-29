package xray

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/uuid"
	xrayCore "github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/inbound"
	"github.com/xtls/xray-core/features/stats"
	"github.com/xtls/xray-core/infra/conf/serial"
	xrayProxy "github.com/xtls/xray-core/proxy"
	"github.com/xtls/xray-core/proxy/shadowsocks"
	ss2022 "github.com/xtls/xray-core/proxy/shadowsocks_2022"
	"github.com/xtls/xray-core/proxy/trojan"
	"github.com/xtls/xray-core/proxy/vless"
	"github.com/xtls/xray-core/proxy/vmess"
	"golang.org/x/time/rate"

	_ "github.com/xtls/xray-core/main/distro/all"

	"github.com/KilluaAoki/XNode/common/nlog"
	"github.com/KilluaAoki/XNode/conf"
	"github.com/KilluaAoki/XNode/core"
	"github.com/KilluaAoki/XNode/core/geodata"
)

const (
	drainTimeout = 5 * time.Second
	startTimeout = 30 * time.Second
	// recycleTimeout bounds how long a replaced instance keeps serving its
	// established connections after a restart.
	recycleTimeout = time.Minute
)

type Xray struct {
	cfg conf.KernelConfig

	mu              sync.Mutex
	instance        *xrayCore.Instance
	limitDispatcher *LimitDispatcher
	users           []core.UserSpec
	nodeConfig      *core.NodeSpec
	tls             core.TLSCert
	protocol        string
	inboundTag      string
	lastKernelHash  string
	cumTraffic      map[int][2]int64
	speedLimitFunc  func(string) *rate.Limiter

	// gate outlives instances so global device state survives restarts.
	gate       *core.DeviceGate
	totalConns atomic.Int64

	running atomic.Bool
}

func New(cfg conf.KernelConfig) *Xray {
	return &Xray{
		cfg:        cfg,
		cumTraffic: make(map[int][2]int64),
		gate:       core.NewDeviceGate(),
	}
}

func (x *Xray) Name() string { return "xray" }

func (x *Xray) Protocols() []string {
	return []string{
		"vmess", "vless", "trojan", "shadowsocks",
		"hysteria",
	}
}

func (x *Xray) Start(nodeConfig *core.NodeSpec, users []core.UserSpec, tls core.TLSCert) error {
	geoDir := x.ensureGeoData(nodeConfig)

	data, err := marshalConfig(x.cfg, nodeConfig, users, tls)
	if err != nil {
		return err
	}

	// xray resolves geo files through a process-wide environment variable
	// while parsing the config and building the router, so both steps run
	// under the creation lock with the variable pointing at this kernel's dir.
	xrayCreationMu.Lock()
	if geoDir != "" {
		os.Setenv("XRAY_LOCATION_ASSET", geoDir)
	}
	pbConfig, err := serial.LoadJSONConfig(bytes.NewReader(data))
	if err != nil {
		xrayCreationMu.Unlock()
		return fmt.Errorf("parse xray config: %w", err)
	}
	inst, err := xrayCore.New(pbConfig)
	ld := globalLimitDispatcher.Load()
	xrayCreationMu.Unlock()
	if err != nil {
		return fmt.Errorf("create xray: %w", err)
	}
	if ld != nil {
		ld.SetDeviceGate(x.gate)
		ld.SetConnCounter(&x.totalConns)
	}

	if err := startWithTimeout(inst, startTimeout); err != nil {
		inst.Close()
		return err
	}

	x.mu.Lock()
	old := x.instance
	oldLD := x.limitDispatcher
	x.instance = inst
	x.limitDispatcher = ld
	x.users = users
	x.nodeConfig = nodeConfig
	x.tls = tls
	x.protocol = nodeConfig.Protocol
	x.inboundTag = nodeConfig.Protocol + "-in"
	x.cumTraffic = make(map[int][2]int64)
	x.lastKernelHash = core.ComputeHash(nodeConfig, users)
	x.running.Store(true)
	x.mu.Unlock()

	if old != nil {
		stopAccepting(old)
		go retire(old, oldLD, recycleTimeout)
	}

	x.updateDispatcherLimits(users)

	nlog.Core().Info("xray started",
		"users", len(users),
		"protocol", nodeConfig.Protocol,
	)
	return nil
}

func (x *Xray) Reload(nodeConfig *core.NodeSpec, users []core.UserSpec, tls core.TLSCert) error {
	x.updateDispatcherLimits(users)

	newHash := core.ComputeHash(nodeConfig, users)

	x.mu.Lock()
	same := x.lastKernelHash == newHash && tlsEqual(x.tls, tls)
	if same {
		x.users = users
		x.mu.Unlock()
		nlog.Core().Debug("xray: limits updated, kernel configuration unchanged")
		return nil
	}
	x.mu.Unlock()

	nlog.Core().Info("xray: configuration changed, performing full restart")
	return x.Start(nodeConfig, users, tls)
}

func (x *Xray) Stop() {
	x.running.Store(false)

	x.mu.Lock()
	inst := x.instance
	ld := x.limitDispatcher
	x.instance = nil
	x.limitDispatcher = nil
	x.mu.Unlock()

	if inst != nil {
		stopAccepting(inst)
		retire(inst, ld, drainTimeout)
	}
}

func (x *Xray) IsRunning() bool { return x.running.Load() }

func tlsEqual(a, b core.TLSCert) bool {
	return bytes.Equal(a.CertPEM, b.CertPEM) && bytes.Equal(a.KeyPEM, b.KeyPEM)
}

func (x *Xray) GetUserTraffic(_ context.Context) (traffic map[int][2]int64, aliveIPs map[int]map[string]bool, connCount int, err error) {
	if !x.running.Load() {
		return nil, nil, 0, nil
	}

	x.mu.Lock()
	ld := x.limitDispatcher
	traffic, err = x.aggregateStats()
	x.mu.Unlock()
	if err != nil {
		return nil, nil, 0, err
	}

	if ld != nil {
		aliveIPs, connCount = ld.GetConnectionState()
	}
	return traffic, aliveIPs, connCount, nil
}

func (x *Xray) TotalConnections() int64 { return x.totalConns.Load() }

func (x *Xray) closeUserLinks(emails []string) {
	if len(emails) == 0 {
		return
	}
	x.mu.Lock()
	ld := x.limitDispatcher
	x.mu.Unlock()
	if ld == nil {
		return
	}
	if n := ld.CloseUsers(emails); n > 0 {
		nlog.Core().Info("xray: closed connections of removed users", "users", len(emails), "connections", n)
	}
}

func (x *Xray) SetSpeedLimitFunc(fn func(string) *rate.Limiter) {
	x.mu.Lock()
	x.speedLimitFunc = fn
	users := x.users
	x.mu.Unlock()
	x.updateDispatcherLimits(users)
}

func (x *Xray) SetDeviceLimitFunc(_ func(string) (int, bool)) {}

func (x *Xray) UpdateGlobalDevices(users map[int][]string) {
	x.gate.UpdateGlobalIPs(users)
	nlog.Core().Debug("global device state updated", "users", len(users))
}

func (x *Xray) ClearGlobalDevices() {
	x.gate.ClearGlobalIPs()
	nlog.Core().Debug("global device state cleared")
}

func (x *Xray) UpdateRemoteDeviceCounts(counts map[int]int) {
	x.gate.UpdateRemoteCounts(counts)
}

func (x *Xray) AddUsers(users []core.UserSpec) (int, error) {
	x.mu.Lock()
	if x.instance == nil {
		x.mu.Unlock()
		return 0, fmt.Errorf("not running")
	}

	userMap := make(map[int]core.UserSpec, len(x.users))
	for _, u := range x.users {
		userMap[u.ID] = u
	}
	var toAdd []core.UserSpec
	for _, u := range users {
		if _, exists := userMap[u.ID]; !exists {
			toAdd = append(toAdd, u)
		}
		userMap[u.ID] = u
	}
	merged := make([]core.UserSpec, 0, len(userMap))
	for _, u := range userMap {
		merged = append(merged, u)
	}

	if len(toAdd) == 0 {
		x.users = merged
		x.mu.Unlock()
		x.updateDispatcherLimits(merged)
		return 0, nil
	}

	um, err := x.getUserManager()
	if err != nil {
		nc, t := x.nodeConfig, x.tls
		x.mu.Unlock()
		nlog.Core().Debug("xray: AddUsers fallback to restart", "reason", err)
		if err := x.Start(nc, merged, t); err != nil {
			return 0, err
		}
		return len(toAdd), nil
	}

	proto := x.protocol
	nc, t := x.nodeConfig, x.tls
	x.mu.Unlock()

	ctx := context.Background()
	added := 0
	for _, u := range toAdd {
		mu, err := toMemoryUser(proto, nc, u)
		if err != nil {
			nlog.Core().Warn("xray: skip user, cannot build account", "user", u.ID, "error", err)
			continue
		}
		if err := um.AddUser(ctx, mu); err != nil {
			nlog.Core().Warn("xray: AddUser failed, restarting with full user list", "user", u.ID, "error", err)
			if err := x.Start(nc, merged, t); err != nil {
				return 0, err
			}
			return len(toAdd), nil
		}
		added++
	}

	x.mu.Lock()
	x.users = merged
	x.mu.Unlock()
	x.updateDispatcherLimits(merged)

	nlog.Core().Info("xray: users added via UserManager", "added", added, "total", len(merged))
	return added, nil
}

func (x *Xray) RemoveUsers(users []core.UserSpec) (int, error) {
	x.mu.Lock()
	if x.instance == nil {
		x.mu.Unlock()
		return 0, fmt.Errorf("not running")
	}
	removeSet := make(map[int]struct{}, len(users))
	for _, u := range users {
		removeSet[u.ID] = struct{}{}
	}
	var kept []core.UserSpec
	removed := 0
	for _, u := range x.users {
		if _, rm := removeSet[u.ID]; rm {
			removed++
		} else {
			kept = append(kept, u)
		}
	}
	if removed == 0 {
		x.mu.Unlock()
		return 0, nil
	}

	if len(kept) == 0 {
		x.mu.Unlock()
		x.Stop()
		return removed, nil
	}

	um, err := x.getUserManager()
	if err != nil {
		nc, t := x.nodeConfig, x.tls
		x.mu.Unlock()
		nlog.Core().Debug("xray: RemoveUsers fallback to restart", "reason", err)
		if err := x.Start(nc, kept, t); err != nil {
			return 0, err
		}
		return removed, nil
	}
	x.mu.Unlock()

	ctx := context.Background()
	actualRemoved := 0
	emails := make([]string, 0, len(users))
	for _, u := range users {
		email := userEmail(u.ID)
		emails = append(emails, email)
		if err := um.RemoveUser(ctx, email); err != nil {
			nlog.Core().Debug("xray: RemoveUser skipped", "user", u.ID, "error", err)
			continue
		}
		actualRemoved++
	}
	x.updateDispatcherLimits(kept)
	x.closeUserLinks(emails)

	x.mu.Lock()
	x.users = kept
	x.mu.Unlock()

	nlog.Core().Info("xray: users removed via UserManager", "removed", actualRemoved, "total", len(kept))
	return actualRemoved, nil
}

func (x *Xray) UpdateUsers(users []core.UserSpec) (added, removed int, err error) {
	x.mu.Lock()
	if x.instance == nil {
		x.mu.Unlock()
		return 0, 0, fmt.Errorf("not running")
	}
	toAdd, toRemove := core.UserDiff(x.users, users)
	added, removed = len(toAdd), len(toRemove)

	if added == 0 && removed == 0 {
		x.users = users
		x.mu.Unlock()
		x.updateDispatcherLimits(users)
		nlog.Core().Info("xray: limits updated, kernel unchanged")
		return 0, 0, nil
	}

	um, umErr := x.getUserManager()
	if umErr != nil {
		nc, t := x.nodeConfig, x.tls
		x.mu.Unlock()
		nlog.Core().Debug("xray: UpdateUsers fallback to restart", "reason", umErr)
		if err = x.Start(nc, users, t); err != nil {
			return 0, 0, err
		}
		return
	}

	proto := x.protocol
	nc, t := x.nodeConfig, x.tls
	x.mu.Unlock()

	ctx := context.Background()

	emails := make([]string, 0, len(toRemove))
	for _, u := range toRemove {
		email := userEmail(u.ID)
		emails = append(emails, email)
		if err := um.RemoveUser(ctx, email); err != nil {
			nlog.Core().Debug("xray: RemoveUser skipped in UpdateUsers", "user", u.ID, "error", err)
		}
	}
	x.updateDispatcherLimits(users)
	x.closeUserLinks(emails)
	for _, u := range toAdd {
		mu, err := toMemoryUser(proto, nc, u)
		if err != nil {
			nlog.Core().Warn("xray: skip user in UpdateUsers", "user", u.ID, "error", err)
			continue
		}
		if err := um.AddUser(ctx, mu); err != nil {
			// The live user set is now partial; rebuild the instance from
			// the full list rather than leave users unable to connect.
			nlog.Core().Warn("xray: AddUser failed, restarting with full user list", "user", u.ID, "error", err)
			if startErr := x.Start(nc, users, t); startErr != nil {
				return 0, 0, startErr
			}
			return added, removed, nil
		}
	}

	x.mu.Lock()
	x.users = users
	x.mu.Unlock()

	nlog.Core().Info("xray: users updated via UserManager", "added", added, "removed", removed, "total", len(users))
	return
}

var _ core.Kernel = (*Xray)(nil)

func (x *Xray) getUserManager() (xrayProxy.UserManager, error) {
	if x.instance == nil {
		return nil, fmt.Errorf("instance is nil")
	}

	im := x.instance.GetFeature(inbound.ManagerType())
	if im == nil {
		return nil, fmt.Errorf("inbound manager not available")
	}
	inboundMgr, ok := im.(inbound.Manager)
	if !ok {
		return nil, fmt.Errorf("inbound manager type assertion failed")
	}

	handler, err := inboundMgr.GetHandler(context.Background(), x.inboundTag)
	if err != nil {
		return nil, fmt.Errorf("get handler %q: %w", x.inboundTag, err)
	}

	gi, ok := handler.(xrayProxy.GetInbound)
	if !ok {
		return nil, fmt.Errorf("handler does not implement GetInbound")
	}

	um, ok := gi.GetInbound().(xrayProxy.UserManager)
	if !ok {
		return nil, fmt.Errorf("protocol %q does not support UserManager", x.protocol)
	}

	return um, nil
}

func toMemoryUser(proto string, nc *core.NodeSpec, u core.UserSpec) (*protocol.MemoryUser, error) {
	email := userEmail(u.ID)
	mu := &protocol.MemoryUser{Email: email, Level: 0}

	switch proto {
	case "vmess":
		id, err := uuid.ParseString(u.UUID)
		if err != nil {
			return nil, fmt.Errorf("parse vmess UUID: %w", err)
		}
		mu.Account = &vmess.MemoryAccount{
			ID:       protocol.NewID(id),
			Security: protocol.SecurityType_AUTO,
		}

	case "vless":
		id, err := uuid.ParseString(u.UUID)
		if err != nil {
			return nil, fmt.Errorf("parse vless UUID: %w", err)
		}
		account := &vless.MemoryAccount{
			ID:         protocol.NewID(id),
			Encryption: "none",
		}
		if nc.Flow != "" {
			account.Flow = nc.Flow
		}
		mu.Account = account

	case "trojan":
		mu.Account = &trojan.MemoryAccount{
			Password: u.UUID,
			Key:      trojanHexSha224(u.UUID),
		}

	case "shadowsocks":
		if m, ok := ss2022Methods[nc.Cipher]; ok {
			mu.Account = &ss2022.MemoryAccount{Key: ss2022UserKey(m.size, u.UUID)}
		} else {
			ct := parseCipherType(nc.Cipher)
			cipherObj, err := (&shadowsocks.Account{CipherType: ct, Password: u.UUID}).AsAccount()
			if err != nil {
				return nil, fmt.Errorf("build ss account: %w", err)
			}
			mu.Account = cipherObj
		}

	default:
		return nil, fmt.Errorf("protocol %q does not support MemoryUser", proto)
	}

	return mu, nil
}

func parseCipherType(cipher string) shadowsocks.CipherType {
	switch cipher {
	case "aes-128-gcm":
		return shadowsocks.CipherType_AES_128_GCM
	case "aes-256-gcm":
		return shadowsocks.CipherType_AES_256_GCM
	case "chacha20-ietf-poly1305", "chacha20-poly1305":
		return shadowsocks.CipherType_CHACHA20_POLY1305
	case "xchacha20-ietf-poly1305", "xchacha20-poly1305":
		return shadowsocks.CipherType_XCHACHA20_POLY1305
	default:
		return shadowsocks.CipherType_AES_256_GCM
	}
}

func trojanHexSha224(password string) []byte {
	h := sha256.New224()
	h.Write([]byte(password))
	buf := make([]byte, 56)
	hexEncode(buf, h.Sum(nil))
	return buf
}

func hexEncode(dst, src []byte) {
	const hextable = "0123456789abcdef"
	for i, v := range src {
		dst[i*2] = hextable[v>>4]
		dst[i*2+1] = hextable[v&0x0f]
	}
}

// ensureGeoData fetches the geo databases the routes need and returns the
// directory holding them, or "" when no route uses geo data.
func (x *Xray) ensureGeoData(nc *core.NodeSpec) string {
	sites, ips := core.GeoRuleNames(nc.Routes, nc.CustomRouteRules)
	needIP, needSite := len(ips) > 0, len(sites) > 0
	if !needIP && !needSite {
		return ""
	}
	dir := x.cfg.GeoDataDir
	if err := geodata.Ensure(dir, needIP, needSite); err != nil {
		nlog.Core().Warn("geo database unavailable", "error", err)
	}
	return dir
}

func marshalConfig(cfg conf.KernelConfig, nc *core.NodeSpec, users []core.UserSpec, tls core.TLSCert) ([]byte, error) {
	cfgMap := buildConfig(cfg, nc, users, tls)
	data, err := json.MarshalIndent(cfgMap, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshal config: %w", err)
	}
	nlog.Core().Debug("xray config generated", "len", len(data))
	return data, nil
}

func startWithTimeout(inst *xrayCore.Instance, timeout time.Duration) error {
	done := make(chan error, 1)
	go func() { done <- inst.Start() }()

	select {
	case err := <-done:
		if err != nil {
			return fmt.Errorf("start xray: %w", err)
		}
		return nil
	case <-time.After(timeout):
		go inst.Close()
		return fmt.Errorf("start xray: timeout after %v", timeout)
	}
}

// stopAccepting closes the listeners of inst. The inbounds use reusePort, so
// without this a replaced instance keeps taking new connections with its old
// configuration while it drains.
func stopAccepting(inst *xrayCore.Instance) {
	im, ok := inst.GetFeature(inbound.ManagerType()).(inbound.Manager)
	if !ok {
		return
	}
	ctx := context.Background()
	for _, h := range im.ListHandlers(ctx) {
		if tag := h.Tag(); tag != "" {
			im.RemoveHandler(ctx, tag)
		}
	}
}

// retire gives the established connections of inst up to timeout to finish,
// then closes it.
func retire(inst *xrayCore.Instance, ld *LimitDispatcher, timeout time.Duration) {
	if ld != nil {
		drainConns(ld, timeout)
	}
	inst.Close()
	if ld != nil {
		ld.ResetConns()
	}
	nlog.Core().Debug("xray: old instance recycled")
}

func drainConns(ld *LimitDispatcher, timeout time.Duration) {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if ld.connCount.Load() == 0 {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func (x *Xray) aggregateStats() (map[int][2]int64, error) {
	sm := x.instance.GetFeature(stats.ManagerType())
	if sm == nil {
		return nil, nil
	}
	mgr, ok := sm.(stats.Manager)
	if !ok {
		return nil, nil
	}

	traffic := make(map[int][2]int64)
	for _, u := range x.users {
		email := userEmail(u.ID)

		var dUp, dDown int64
		if c := mgr.GetCounter(fmt.Sprintf("user>>>%s>>>traffic>>>uplink", email)); c != nil {
			dUp = c.Set(0)
		}
		if c := mgr.GetCounter(fmt.Sprintf("user>>>%s>>>traffic>>>downlink", email)); c != nil {
			dDown = c.Set(0)
		}

		if dUp > 0 || dDown > 0 {
			cum := x.cumTraffic[u.ID]
			cum[0] += dUp
			cum[1] += dDown
			x.cumTraffic[u.ID] = cum
		}

		if cum := x.cumTraffic[u.ID]; cum[0] > 0 || cum[1] > 0 {
			traffic[u.ID] = cum
		}
	}
	return traffic, nil
}

func (x *Xray) updateDispatcherLimits(users []core.UserSpec) {
	x.mu.Lock()
	ld := x.limitDispatcher
	fn := x.speedLimitFunc
	x.mu.Unlock()
	if ld == nil {
		return
	}

	emailToUID := make(map[string]int, len(users)*2)
	deviceLimits := make(map[string]int)
	speedLimiters := make(map[string]*rate.Limiter)

	for _, u := range users {
		email := userEmail(u.ID)
		emailToUID[email] = u.ID
		emailToUID[u.UUID] = u.ID
		if u.DeviceLimit > 0 {
			deviceLimits[email] = u.DeviceLimit
			deviceLimits[u.UUID] = u.DeviceLimit
		}
		if lim := userSpeedLimiter(fn, u); lim != nil {
			speedLimiters[email] = lim
		}
	}

	ld.UpdateLimits(emailToUID, deviceLimits, speedLimiters)
}

func userSpeedLimiter(fn func(string) *rate.Limiter, u core.UserSpec) *rate.Limiter {
	if fn != nil {
		return fn(u.UUID)
	}
	if u.SpeedLimit <= 0 {
		return nil
	}
	bps := u.SpeedLimit * 1_000_000 / 8
	return rate.NewLimiter(rate.Limit(bps), max(bps, 64*1024))
}

var xrayCreationMu sync.Mutex
