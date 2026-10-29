package node

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/KilluaAoki/XNode/conf"
	"github.com/KilluaAoki/XNode/core"
	"github.com/KilluaAoki/XNode/limiter"
	"github.com/KilluaAoki/XNode/node/cert"
	"golang.org/x/time/rate"
)

type fakeKernel struct {
	running bool

	startErr  error
	updateErr error
	addErr    error
	reloadErr error

	startCalls  int
	updateCalls int
	addCalls    int
	removeCalls int
	reloadCalls int

	onUpdateUsers func([]core.UserSpec)
	onAddUsers    func([]core.UserSpec)
	onRemoveUsers func([]core.UserSpec)

	speedLimitFunc  func(string) *rate.Limiter
	deviceLimitFunc func(string) (int, bool)

	remoteCounts map[int]int
}

func (f *fakeKernel) Name() string        { return "fake" }
func (f *fakeKernel) Protocols() []string { return []string{"vless"} }
func (f *fakeKernel) Start(nodeConfig *core.NodeSpec, users []core.UserSpec, tls core.TLSCert) error {
	_, _, _ = nodeConfig, users, tls
	f.startCalls++
	if f.startErr != nil {
		return f.startErr
	}
	f.running = true
	return nil
}
func (f *fakeKernel) Stop()           { f.running = false }
func (f *fakeKernel) IsRunning() bool { return f.running }
func (f *fakeKernel) Reload(nodeConfig *core.NodeSpec, users []core.UserSpec, tls core.TLSCert) error {
	_, _, _ = nodeConfig, users, tls
	f.reloadCalls++
	return f.reloadErr
}
func (f *fakeKernel) AddUsers(users []core.UserSpec) (int, error) {
	f.addCalls++
	if f.onAddUsers != nil {
		f.onAddUsers(users)
	}
	if f.addErr != nil {
		return 0, f.addErr
	}
	return len(users), nil
}
func (f *fakeKernel) RemoveUsers(users []core.UserSpec) (int, error) {
	f.removeCalls++
	if f.onRemoveUsers != nil {
		f.onRemoveUsers(users)
	}
	return len(users), nil
}
func (f *fakeKernel) UpdateUsers(users []core.UserSpec) (int, int, error) {
	f.updateCalls++
	if f.onUpdateUsers != nil {
		f.onUpdateUsers(users)
	}
	if f.updateErr != nil {
		return 0, 0, f.updateErr
	}
	return len(users), 0, nil
}
func (f *fakeKernel) GetUserTraffic(ctx context.Context) (map[int][2]int64, map[int]map[string]bool, int, error) {
	_ = ctx
	return nil, nil, 0, nil
}
func (f *fakeKernel) SetSpeedLimitFunc(fn func(uuid string) *rate.Limiter) { f.speedLimitFunc = fn }
func (f *fakeKernel) SetDeviceLimitFunc(fn func(uuid string) (int, bool))  { f.deviceLimitFunc = fn }
func (f *fakeKernel) UpdateGlobalDevices(users map[int][]string)           { _ = users }
func (f *fakeKernel) ClearGlobalDevices()                                  {}
func (f *fakeKernel) UpdateRemoteDeviceCounts(counts map[int]int)          { f.remoteCounts = counts }

func newTestService(k *fakeKernel) *Service {
	sharedLimiter := limiter.New()
	s := &Service{
		kernel:       k,
		limiter:      sharedLimiter,
		speedTracker: limiter.NewSpeedTracker(sharedLimiter),
		cert:         cert.NewManager(conf.CertConfig{}),
	}
	k.SetSpeedLimitFunc(s.speedTracker.GetLimiter)
	k.SetDeviceLimitFunc(s.limiter.GetDeviceLimitByUUID)
	return s
}

func TestApplyUserUpdatePreparesLimiterBeforeKernelUpdate(t *testing.T) {
	k := &fakeKernel{running: true}
	s := newTestService(k)
	s.lastConfig = &core.NodeSpec{Protocol: "vless"}
	oldUsers := []core.UserSpec{{ID: 1, UUID: "uuid-old", SpeedLimit: 4}}
	s.setUserState(oldUsers)

	newUsers := []core.UserSpec{{ID: 2, UUID: "uuid-new", SpeedLimit: 8}}
	k.onUpdateUsers = func(users []core.UserSpec) {
		if len(users) != 1 || users[0].UUID != "uuid-new" {
			t.Fatalf("unexpected users passed to UpdateUsers: %#v", users)
		}
		if got := k.speedLimitFunc("uuid-new"); got == nil {
			t.Fatal("expected new user's limiter to be visible before kernel UpdateUsers")
		}
	}

	s.applyUserUpdate(context.Background(), newUsers, computeUserHash(newUsers))

	if got := k.updateCalls; got != 1 {
		t.Fatalf("UpdateUsers call count = %d, want 1", got)
	}
	if len(s.lastUsers) != 1 || s.lastUsers[0].UUID != "uuid-new" {
		t.Fatalf("lastUsers = %#v, want new users", s.lastUsers)
	}
	if s.speedTracker.GetLimiter("uuid-new") == nil {
		t.Fatal("expected limiter for new user after successful update")
	}
}

func TestApplyUserUpdateKeepsDesiredStateAndRetries(t *testing.T) {
	k := &fakeKernel{
		running:   true,
		updateErr: errors.New("update failed"),
		startErr:  errors.New("restart failed"),
		reloadErr: errors.New("reload failed"),
	}
	s := newTestService(k)
	s.lastConfig = &core.NodeSpec{Protocol: "vless"}
	s.setUserState([]core.UserSpec{{ID: 1, UUID: "uuid-old", SpeedLimit: 4}})

	newUsers := []core.UserSpec{{ID: 2, UUID: "uuid-new", SpeedLimit: 8}}
	s.applyUserUpdate(context.Background(), newUsers, computeUserHash(newUsers))

	if got := k.startCalls; got != 1 {
		t.Fatalf("Start call count = %d, want 1", got)
	}
	if len(s.lastUsers) != 1 || s.lastUsers[0].UUID != "uuid-new" {
		t.Fatalf("lastUsers = %#v, want desired users kept", s.lastUsers)
	}
	if s.speedTracker.GetLimiter("uuid-old") != nil {
		t.Fatal("removed user's limiter must not come back")
	}
	if !s.applyPending {
		t.Fatal("failed apply must stay pending")
	}

	k.startErr, k.reloadErr = nil, nil
	for i := 0; i < 4 && s.applyPending; i++ {
		s.superviseKernel()
	}
	if s.applyPending {
		t.Fatal("supervision did not recover the pending apply")
	}
	if k.reloadCalls == 0 {
		t.Fatal("expected the running kernel to be reloaded with the desired state")
	}
}

func TestSuperviseKernelRestartsStoppedKernel(t *testing.T) {
	k := &fakeKernel{}
	s := newTestService(k)
	s.lastConfig = &core.NodeSpec{Protocol: "vless"}
	s.setUserState([]core.UserSpec{{ID: 1, UUID: "uuid-1"}})

	s.superviseKernel()
	if !k.running || k.startCalls != 1 {
		t.Fatalf("running = %v, start calls = %d", k.running, k.startCalls)
	}

	k.running = false
	s.setUserState(nil)
	s.superviseKernel()
	if k.running || k.startCalls != 1 {
		t.Fatal("kernel without users must stay stopped")
	}
}

func TestApplyUserDeltaRemoveUpdatesDesiredStateWhileStopped(t *testing.T) {
	k := &fakeKernel{}
	s := newTestService(k)
	s.lastConfig = &core.NodeSpec{Protocol: "vless"}
	s.setUserState([]core.UserSpec{{ID: 1, UUID: "uuid-1"}, {ID: 2, UUID: "uuid-2"}})

	s.applyUserDelta(context.Background(), "remove", []core.UserSpec{{ID: 1, UUID: "uuid-1"}})
	if len(s.lastUsers) != 1 || s.lastUsers[0].ID != 2 {
		t.Fatalf("lastUsers = %#v, want only user 2", s.lastUsers)
	}
}

func TestApplyUserDeltaRotatedUUIDUsesFullUpdate(t *testing.T) {
	k := &fakeKernel{running: true}
	s := newTestService(k)
	s.lastConfig = &core.NodeSpec{Protocol: "vless"}
	s.setUserState([]core.UserSpec{{ID: 1, UUID: "uuid-old"}})

	var got []core.UserSpec
	k.onUpdateUsers = func(users []core.UserSpec) { got = users }
	s.applyUserDelta(context.Background(), "add", []core.UserSpec{{ID: 1, UUID: "uuid-new"}})
	if k.addCalls != 0 || k.updateCalls != 1 {
		t.Fatalf("add calls = %d, update calls = %d", k.addCalls, k.updateCalls)
	}
	if len(got) != 1 || got[0].UUID != "uuid-new" {
		t.Fatalf("UpdateUsers got %#v", got)
	}
}

func TestApplyUserDeltaAddPreparesLimiterBeforeKernelUpdate(t *testing.T) {
	k := &fakeKernel{running: true}
	s := newTestService(k)
	s.lastConfig = &core.NodeSpec{Protocol: "vless"}
	oldUsers := []core.UserSpec{{ID: 1, UUID: "uuid-old", SpeedLimit: 4}}
	s.setUserState(oldUsers)

	delta := []core.UserSpec{{ID: 2, UUID: "uuid-new", SpeedLimit: 8}}
	k.onAddUsers = func(users []core.UserSpec) {
		if len(users) != 1 || users[0].UUID != "uuid-new" {
			t.Fatalf("unexpected users passed to AddUsers: %#v", users)
		}
		if got := k.speedLimitFunc("uuid-new"); got == nil {
			t.Fatal("expected delta user's limiter to be visible before kernel AddUsers")
		}
	}

	s.applyUserDelta(context.Background(), "add", delta)

	if got := k.addCalls; got != 1 {
		t.Fatalf("AddUsers call count = %d, want 1", got)
	}
	if s.speedTracker.GetLimiter("uuid-new") == nil {
		t.Fatal("expected limiter for delta-added user after successful update")
	}
}

func TestValidateNodeRuntimeRejectsUnsupportedDNSProvider(t *testing.T) {
	cfg := &conf.Config{Kernel: conf.KernelConfig{Type: "singbox"}}
	err := validateNodeRuntime(cfg, []string{"http"}, &core.NodeSpec{
		Protocol: "http",
		CertConfig: &conf.CertConfig{
			CertMode:    "dns",
			DNSProvider: "3123123",
			Domain:      "example.com",
		},
	}, core.TLSCert{CertPEM: []byte("CERT"), KeyPEM: []byte("KEY")})
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if err.Error() == "" {
		t.Fatal("expected non-empty error")
	}
	if got := err.Error(); !strings.HasPrefix(got, `unsupported cert_config.dns_provider "3123123" (supported: `) {
		t.Fatalf("unexpected error: %v", got)
	}
}

func TestValidateNodeRuntimeAllowsSelfManagedTLSBeforeFilesExist(t *testing.T) {
	cfg := &conf.Config{Kernel: conf.KernelConfig{Type: "singbox"}}
	err := validateNodeRuntime(cfg, []string{"anytls", "hysteria"}, &core.NodeSpec{
		Protocol: "anytls",
		CertConfig: &conf.CertConfig{
			CertMode: "self",
			Domain:   "example.com",
		},
	}, core.TLSCert{})
	if err != nil {
		t.Fatalf("expected self-managed TLS config to pass validation, got %v", err)
	}
}

func TestValidateNodeRuntimeAllowsSingboxRealityWithRequiredFields(t *testing.T) {
	cfg := &conf.Config{Kernel: conf.KernelConfig{Type: "singbox"}}
	err := validateNodeRuntime(cfg, []string{"vless"}, &core.NodeSpec{
		Protocol: "vless",
		TLS:      2,
		TLSSettings: map[string]any{
			"private_key": "test-key",
			"server_name": "example.com",
		},
	}, core.TLSCert{CertPEM: []byte("CERT"), KeyPEM: []byte("KEY")})
	if err != nil {
		t.Fatalf("expected sing-box reality validation to pass, got %v", err)
	}
}

func TestValidateNodeRuntimeRejectsRealityWithoutTLSSettings(t *testing.T) {
	cfg := &conf.Config{Kernel: conf.KernelConfig{Type: "singbox"}}
	err := validateNodeRuntime(cfg, []string{"vless"}, &core.NodeSpec{
		Protocol: "vless",
		TLS:      2,
	}, core.TLSCert{CertPEM: []byte("CERT"), KeyPEM: []byte("KEY")})
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if got := err.Error(); got != "reality tls requires tls_settings" {
		t.Fatalf("unexpected error: %v", got)
	}
}

func TestValidateNodeRuntimeRejectsRealityWithoutPrivateKey(t *testing.T) {
	cfg := &conf.Config{Kernel: conf.KernelConfig{Type: "singbox"}}
	err := validateNodeRuntime(cfg, []string{"vless"}, &core.NodeSpec{
		Protocol: "vless",
		TLS:      2,
		TLSSettings: map[string]any{
			"server_name": "example.com",
		},
	}, core.TLSCert{CertPEM: []byte("CERT"), KeyPEM: []byte("KEY")})
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if got := err.Error(); got != "reality tls requires tls_settings.private_key" {
		t.Fatalf("unexpected error: %v", got)
	}
}

func TestValidateNodeRuntimeRejectsRealityWithoutServerNameOrDest(t *testing.T) {
	cfg := &conf.Config{Kernel: conf.KernelConfig{Type: "singbox"}}
	err := validateNodeRuntime(cfg, []string{"vless"}, &core.NodeSpec{
		Protocol: "vless",
		TLS:      2,
		TLSSettings: map[string]any{
			"private_key": "test-key",
		},
	}, core.TLSCert{CertPEM: []byte("CERT"), KeyPEM: []byte("KEY")})
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if got := err.Error(); got != "reality tls requires tls_settings.server_name, server_names or dest" {
		t.Fatalf("unexpected error: %v", got)
	}
}

func TestApplyAliveCountsSubtractsReportedDevices(t *testing.T) {
	k := &fakeKernel{running: true}
	s := newTestService(k)
	s.setReportedAlive(map[int][]string{1: {"1.1.1.1", "2.2.2.2"}, 2: {"3.3.3.3"}})

	s.applyAliveCounts(map[int]int{1: 3, 2: 1, 3: 2})
	if len(k.remoteCounts) != 2 || k.remoteCounts[1] != 1 || k.remoteCounts[3] != 2 {
		t.Fatalf("remote counts = %v, want map[1:1 3:2]", k.remoteCounts)
	}

	s.applyAliveCounts(nil)
	if k.remoteCounts != nil {
		t.Fatalf("nil alive list should clear remote counts, got %v", k.remoteCounts)
	}
}

func TestNodeLimitsCapUsers(t *testing.T) {
	k := &fakeKernel{running: true}
	s := newTestService(k)
	s.cfg = &conf.Config{Node: conf.NodeConfig{SpeedLimit: 50, DeviceLimit: 3}}
	s.lastConfig = &core.NodeSpec{Protocol: "vless"}

	var got []core.UserSpec
	k.onUpdateUsers = func(users []core.UserSpec) { got = users }
	raw := []core.UserSpec{
		{ID: 1, UUID: "a", SpeedLimit: 100, DeviceLimit: 5},
		{ID: 2, UUID: "b", SpeedLimit: 10, DeviceLimit: 1},
		{ID: 3, UUID: "c"},
	}
	s.handleWSEvent(context.Background(), Event{Type: EventSyncUsers, Users: raw})
	s.handleWSEvent(context.Background(), Event{Type: EventSyncUsers, Users: raw})

	if k.updateCalls != 1 {
		t.Fatalf("updateCalls = %d, want 1 (same users must not re-apply)", k.updateCalls)
	}
	want := map[int][2]int{1: {50, 3}, 2: {10, 1}, 3: {50, 3}}
	for _, u := range got {
		if w := want[u.ID]; u.SpeedLimit != w[0] || u.DeviceLimit != w[1] {
			t.Errorf("user %d limits = %d/%d, want %d/%d", u.ID, u.SpeedLimit, u.DeviceLimit, w[0], w[1])
		}
	}
	if raw[0].SpeedLimit != 100 {
		t.Error("input users must not be modified")
	}
	if limit, _ := s.limiter.GetDeviceLimitByUUID("c"); limit != 3 {
		t.Errorf("limiter device limit = %d, want 3", limit)
	}
}

func TestApplyIntervalsPrefersLocalThenPanel(t *testing.T) {
	cfg := &conf.Config{}
	cfg.Node.PullInterval = 45
	s := &Service{cfg: cfg}

	s.applyIntervals(0, 0)
	if s.pushInterval != 60 || s.pullInterval != 45 {
		t.Fatalf("defaults: push=%d pull=%d, want 60/45", s.pushInterval, s.pullInterval)
	}

	s.reportTicker = time.NewTicker(time.Hour)
	defer s.reportTicker.Stop()
	s.pullTicker = time.NewTicker(time.Hour)
	defer s.pullTicker.Stop()

	s.applyIntervals(1, 120)
	if s.pushInterval != 1 || s.pullInterval != 45 {
		t.Fatalf("panel update: push=%d pull=%d, want 1/45 (local pull pinned)", s.pushInterval, s.pullInterval)
	}
	select {
	case <-s.reportTicker.C:
	case <-time.After(10 * time.Second):
		t.Fatal("report ticker was not retimed")
	}

	s.applyIntervals(0, 0)
	if s.pushInterval != 1 {
		t.Fatalf("missing panel value should keep current push, got %d", s.pushInterval)
	}
}

func TestValidateNodeRuntimeListenIP(t *testing.T) {
	cfg := &conf.Config{Kernel: conf.KernelConfig{Type: "xray"}}
	for ip, ok := range map[string]bool{"": true, "0.0.0.0": true, "::": true, "127.0.0.1": true, "localhost": false, "0.0.0.0 ": false, "1.2.3.4:443": false} {
		err := validateNodeRuntime(cfg, []string{"vmess"}, &core.NodeSpec{Protocol: "vmess", ListenIP: ip}, core.TLSCert{})
		if (err == nil) != ok {
			t.Errorf("listen_ip %q: err=%v, want ok=%v", ip, err, ok)
		}
	}
}

func TestValidateNodeRuntimeRejectsShadowsocksPlugin(t *testing.T) {
	cfg := &conf.Config{Kernel: conf.KernelConfig{Type: "singbox"}}
	spec := &core.NodeSpec{Protocol: "shadowsocks", Cipher: "aes-128-gcm", Plugin: "obfs"}
	if err := validateNodeRuntime(cfg, []string{"shadowsocks"}, spec, core.TLSCert{}); err == nil || !strings.Contains(err.Error(), "plugin") {
		t.Fatalf("expected plugin error, got %v", err)
	}
	spec.Plugin = ""
	if err := validateNodeRuntime(cfg, []string{"shadowsocks"}, spec, core.TLSCert{}); err != nil {
		t.Fatalf("plain shadowsocks rejected: %v", err)
	}
}
