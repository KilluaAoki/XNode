package sing

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"strconv"
	"sync"
	"sync/atomic"

	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/option"
	singJSON "github.com/sagernet/sing/common/json"
	"github.com/sagernet/sing/service"
	"golang.org/x/time/rate"

	"github.com/KilluaAoki/XNode/common/nlog"
	"github.com/KilluaAoki/XNode/conf"
	"github.com/KilluaAoki/XNode/core"
	"github.com/KilluaAoki/XNode/core/geodata"
	"github.com/KilluaAoki/XNode/core/sing/protocol"
	"github.com/KilluaAoki/XNode/core/sing/protocol/mieru"
)

type SingBox struct {
	cfg conf.KernelConfig

	mu     sync.RWMutex
	box    *box.Box
	ctx    context.Context
	cancel context.CancelFunc

	users      []core.UserSpec
	nodeConfig *core.NodeSpec
	tls        core.TLSCert

	connTracker *ConnTracker

	speedLimitFunc func(string) *rate.Limiter

	deviceLimitFunc func(string) (int, bool)

	// gate outlives restarts so global device state survives a new tracker.
	gate       *core.DeviceGate
	totalConns atomic.Int64

	trackerRegistered bool
	structureKey      string
}

func New(cfg conf.KernelConfig) *SingBox {
	return &SingBox{cfg: cfg, gate: core.NewDeviceGate()}
}

var _ core.Kernel = (*SingBox)(nil)

func (s *SingBox) TotalConnections() int64 { return s.totalConns.Load() }

func (s *SingBox) Name() string { return "sing-box" }

func (s *SingBox) Capabilities() core.Capabilities {
	return core.Capabilities{
		PerUserSpeedLimit:    true,
		DeviceLimit:          true,
		BuiltInTrafficStats:  false,
		AliveIPTracking:      true,
		ForceCloseConnection: false,
		ForceCloseUser:       true,
	}
}

func (s *SingBox) Protocols() []string {
	return []string{
		"vmess", "vless", "trojan", "shadowsocks",
		"hysteria", "hysteria2", "tuic", "naive", "socks", "http", "anytls", "mieru",
	}
}

func (s *SingBox) Start(nodeConfig *core.NodeSpec, users []core.UserSpec, tls core.TLSCert) error {
	s.ensureRuleSets(nodeConfig)
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.startLocked(buildConfig(s.cfg, nodeConfig, users, tls), nodeConfig, users, tls)
}

// ensureRuleSets downloads the geosite/geoip rule-sets referenced by routes
// so buildConfig can point at local files. It runs outside the lock.
func (s *SingBox) ensureRuleSets(nc *core.NodeSpec) {
	if nc == nil {
		return
	}
	sites, ips := core.GeoRuleNames(nc.Routes, nc.CustomRouteRules)
	geodata.EnsureRuleSets(s.cfg.GeoDataDir, sites, ips)
}

func (s *SingBox) startLocked(cfgMap M, nodeConfig *core.NodeSpec, users []core.UserSpec, tls core.TLSCert) error {
	data, err := json.Marshal(cfgMap)
	if err != nil {
		return fmt.Errorf("marshal config: %w", err)
	}

	nlog.Core().Debug("sing-box config generated", "len", len(data))

	ctx, cancel := context.WithCancel(context.Background())
	ctx = boxContext(ctx)

	opts, err := singJSON.UnmarshalExtendedContext[option.Options](ctx, data)
	if err != nil {
		cancel()
		return fmt.Errorf("parse sing-box options: %w", err)
	}

	oldBox := s.box
	oldCancel := s.cancel

	instance, err := box.New(box.Options{
		Context: ctx,
		Options: opts,
	})
	if err != nil {
		cancel()
		return fmt.Errorf("create sing-box instance: %w", err)
	}

	if err := instance.Start(); err != nil {
		instance.Close()
		cancel()
		return fmt.Errorf("start sing-box: %w", err)
	}

	s.box = instance
	s.ctx = ctx
	s.cancel = cancel
	s.users = users
	s.nodeConfig = nodeConfig
	s.tls = tls
	s.structureKey = structureKey(cfgMap, len(users) > 0)

	s.connTracker = NewConnTracker(0)
	s.connTracker.gate = s.gate
	s.connTracker.total = &s.totalConns
	s.connTracker.SetUserMap(buildUserMap(users))
	s.connTracker.SetManagedInbound(nodeConfig.Protocol + "-in")
	if s.speedLimitFunc != nil {
		s.connTracker.SetSpeedLimitFunc(s.speedLimitFunc)
	}
	if s.deviceLimitFunc != nil {
		s.connTracker.SetDeviceLimitFunc(s.deviceLimitFunc)
	}

	s.trackerRegistered = false
	s.registerTracker(ctx)

	if oldBox != nil {
		recycleOldBox(oldBox, oldCancel)
	}

	nlog.Core().Debug("sing-box started", "users", len(users))
	return nil
}

func recycleOldBox(oldBox *box.Box, oldCancel context.CancelFunc) {
	oldBox.Close()
	if oldCancel != nil {
		oldCancel()
	}
	nlog.Core().Debug("sing-box: old instance recycled")
}

func (s *SingBox) Reload(nodeConfig *core.NodeSpec, users []core.UserSpec, tls core.TLSCert) error {
	s.ensureRuleSets(nodeConfig)
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.box == nil {
		return fmt.Errorf("not running")
	}
	return s.applyLocked(nodeConfig, users, tls)
}

func (s *SingBox) applyLocked(nodeConfig *core.NodeSpec, users []core.UserSpec, tls core.TLSCert) error {
	cfgMap := buildConfig(s.cfg, nodeConfig, users, tls)
	if structureKey(cfgMap, len(users) > 0) != s.structureKey {
		nlog.Core().Debug("sing-box structure changed, restarting")
		return s.startLocked(cfgMap, nodeConfig, users, tls)
	}
	if s.connTracker != nil {
		s.connTracker.SetUserMap(buildUserMap(users))
	}
	if err := s.updateUsersLocked(cfgMap); err != nil {
		nlog.Core().Warn("sing-box user update failed, restarting", "error", err)
		return s.startLocked(cfgMap, nodeConfig, users, tls)
	}
	s.users = users
	s.nodeConfig = nodeConfig
	s.tls = tls
	nlog.Core().Debug("sing-box users updated in place", "users", len(users))
	return nil
}

func (s *SingBox) updateUsersLocked(cfgMap M) error {
	data, err := json.Marshal(cfgMap)
	if err != nil {
		return fmt.Errorf("marshal config: %w", err)
	}
	opts, err := singJSON.UnmarshalExtendedContext[option.Options](s.ctx, data)
	if err != nil {
		return fmt.Errorf("parse options: %w", err)
	}
	im := service.FromContext[adapter.InboundManager](s.ctx)
	if im == nil {
		return fmt.Errorf("inbound manager not available")
	}
	for _, inb := range opts.Inbounds {
		existing, ok := im.Get(inb.Tag)
		if !ok || existing.Type() != inb.Type {
			return fmt.Errorf("inbound %s not found", inb.Tag)
		}
		if err := updateInboundUsers(existing, inb.Options); err != nil {
			return fmt.Errorf("inbound %s: %w", inb.Tag, err)
		}
	}
	return nil
}

func updateInboundUsers(in adapter.Inbound, options any) error {
	switch o := options.(type) {
	case *option.VMessInboundOptions:
		return updateUsers(in, o.Users)
	case *option.VLESSInboundOptions:
		return updateUsers(in, o.Users)
	case *option.TrojanInboundOptions:
		return updateUsers(in, o.Users)
	case *option.HysteriaInboundOptions:
		return updateUsers(in, o.Users)
	case *option.Hysteria2InboundOptions:
		return updateUsers(in, o.Users)
	case *option.TUICInboundOptions:
		return updateUsers(in, o.Users)
	case *option.AnyTLSInboundOptions:
		return updateUsers(in, o.Users)
	case *mieru.InboundOptions:
		return updateUsers(in, o.Users)
	case *option.NaiveInboundOptions:
		return updateUsers(in, o.Users)
	case *option.SocksInboundOptions:
		return updateUsers(in, o.Users)
	case *option.HTTPMixedInboundOptions:
		return updateUsers(in, o.Users)
	case *option.ShadowsocksInboundOptions:
		m, ok := in.(adapter.ManagedSSMServer)
		if !ok {
			return fmt.Errorf("%s does not support user updates", in.Type())
		}
		names := make([]string, len(o.Users))
		passwords := make([]string, len(o.Users))
		for i, u := range o.Users {
			names[i], passwords[i] = u.Name, u.Password
		}
		return m.UpdateUsers(names, passwords)
	}
	return fmt.Errorf("%s does not support user updates", in.Type())
}

func updateUsers[T any](in adapter.Inbound, users []T) error {
	u, ok := in.(protocol.UserUpdater[T])
	if !ok {
		return fmt.Errorf("%s does not support user updates", in.Type())
	}
	return u.UpdateUsers(users)
}

func structureKey(cfg M, hasUsers bool) string {
	shadow := make(M, len(cfg))
	for k, v := range cfg {
		shadow[k] = v
	}
	if inbounds, ok := cfg["inbounds"].([]M); ok {
		stripped := make([]M, len(inbounds))
		for i, in := range inbounds {
			c := make(M, len(in))
			for k, v := range in {
				if k != "users" {
					c[k] = v
				}
			}
			stripped[i] = c
		}
		shadow["inbounds"] = stripped
	}
	data, _ := json.Marshal(shadow)
	return fmt.Sprintf("%x:%t", sha256.Sum256(data), hasUsers)
}

func (s *SingBox) registerTracker(ctx context.Context) {
	if s.trackerRegistered {
		return
	}
	router := service.FromContext[adapter.Router](ctx)
	if router == nil {
		return
	}
	if s.connTracker != nil {
		router.AppendTracker(s.connTracker)
	}
	s.trackerRegistered = true
}

func (s *SingBox) Stop() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.stop()
}

func (s *SingBox) stop() {
	if s.box == nil {
		return
	}
	s.box.Close()
	s.box = nil
	if s.cancel != nil {
		s.cancel()
		s.cancel = nil
	}
	s.ctx = nil
}

func (s *SingBox) IsRunning() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.box != nil
}

func (s *SingBox) connTrackerSafe() *ConnTracker {
	s.mu.Lock()
	ct := s.connTracker
	s.mu.Unlock()
	return ct
}

func (s *SingBox) SetSpeedLimitFunc(fn func(uuid string) *rate.Limiter) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.speedLimitFunc = fn
	if s.connTracker != nil {
		s.connTracker.SetSpeedLimitFunc(fn)
	}
}

func (s *SingBox) SetDeviceLimitFunc(fn func(uuid string) (int, bool)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.deviceLimitFunc = fn
	if s.connTracker != nil {
		s.connTracker.SetDeviceLimitFunc(fn)
	}
}

func (s *SingBox) UpdateGlobalDevices(users map[int][]string) {
	s.gate.UpdateGlobalIPs(users)
	nlog.Core().Debug("global device state updated", "users", len(users))
}

func (s *SingBox) ClearGlobalDevices() {
	s.gate.ClearGlobalIPs()
	nlog.Core().Debug("global device state cleared")
}

func (s *SingBox) UpdateRemoteDeviceCounts(counts map[int]int) {
	s.gate.UpdateRemoteCounts(counts)
}

func (s *SingBox) AddUsers(users []core.UserSpec) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.box == nil {
		return 0, fmt.Errorf("not running")
	}

	existing := make(map[int]struct{}, len(s.users))
	for _, u := range s.users {
		existing[u.ID] = struct{}{}
	}
	var toAdd []core.UserSpec
	for _, u := range users {
		if _, dup := existing[u.ID]; !dup {
			toAdd = append(toAdd, u)
		}
	}
	if len(toAdd) == 0 {
		return 0, nil
	}

	merged := append(append([]core.UserSpec{}, s.users...), toAdd...)
	if err := s.reloadInboundsLocked(merged); err != nil {
		return 0, err
	}
	s.users = merged
	return len(toAdd), nil
}

func (s *SingBox) RemoveUsers(users []core.UserSpec) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.box == nil {
		return 0, fmt.Errorf("not running")
	}

	removeSet := make(map[int]struct{}, len(users))
	for _, u := range users {
		removeSet[u.ID] = struct{}{}
	}
	var kept []core.UserSpec
	var gone []string
	for _, u := range s.users {
		if _, rm := removeSet[u.ID]; rm {
			gone = append(gone, u.UUID)
		} else {
			kept = append(kept, u)
		}
	}
	if len(gone) == 0 {
		return 0, nil
	}

	if err := s.reloadInboundsLocked(kept); err != nil {
		return 0, err
	}
	s.users = kept
	s.closeRemovedLocked(gone)
	return len(gone), nil
}

func (s *SingBox) UpdateUsers(users []core.UserSpec) (added, removed int, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.box == nil {
		return 0, 0, fmt.Errorf("not running")
	}

	toAdd, toRemove := core.UserDiff(s.users, users)
	added, removed = len(toAdd), len(toRemove)

	if added == 0 && removed == 0 {
		if s.connTracker != nil {
			s.connTracker.SetUserMap(buildUserMap(users))
		}
		s.users = users
		return 0, 0, nil
	}

	if err = s.reloadInboundsLocked(users); err != nil {
		return 0, 0, err
	}
	s.users = users
	gone := make([]string, 0, len(toRemove))
	for _, u := range toRemove {
		gone = append(gone, u.UUID)
	}
	s.closeRemovedLocked(gone)
	return
}

func (s *SingBox) closeRemovedLocked(uuids []string) {
	if s.connTracker == nil || len(uuids) == 0 {
		return
	}
	if n := s.connTracker.CloseByUUID(uuids...); n > 0 {
		nlog.Core().Info("sing-box: closed connections of removed users", "users", len(uuids), "connections", n)
	}
}

func (s *SingBox) reloadInboundsLocked(users []core.UserSpec) error {
	return s.applyLocked(s.nodeConfig, users, s.tls)
}

func (s *SingBox) GetUserTraffic(_ context.Context) (traffic map[int][2]int64, aliveIPs map[int]map[string]bool, connCount int, err error) {
	ct := s.connTrackerSafe()
	if ct == nil {
		return nil, nil, 0, nil
	}
	traffic, aliveIPs, connCount = ct.GetUserTraffic()
	return traffic, aliveIPs, connCount, nil
}

func (s *SingBox) CloseConnection(_ context.Context, connID string) error {
	ct := s.connTrackerSafe()
	if ct == nil {
		return fmt.Errorf("not running")
	}
	if !ct.CloseByID(connID) {
		nlog.Core().Debug("CloseConnection: connection not found (already closed?)", "id", connID)
	}
	return nil
}

func (s *SingBox) CloseUserConnections(_ context.Context, uuid string) error {
	ct := s.connTrackerSafe()
	if ct == nil {
		return nil
	}
	ct.CloseByUUID(uuid)
	return nil
}

func buildUserMap(users []core.UserSpec) map[string]int {
	m := make(map[string]int, len(users))
	for _, u := range users {
		m[u.UUID] = u.ID
		m[strconv.Itoa(u.ID)] = u.ID
	}
	return m
}
