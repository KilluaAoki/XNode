package xray

import (
	"context"
	"fmt"
	"testing"

	"github.com/KilluaAoki/XNode/conf"
	"github.com/KilluaAoki/XNode/core"
	appstats "github.com/xtls/xray-core/app/stats"
	xrayCore "github.com/xtls/xray-core/core"
	xraystats "github.com/xtls/xray-core/features/stats"
	"golang.org/x/time/rate"
)

func newStatsManager(t *testing.T) xraystats.Manager {
	t.Helper()
	mgr, err := appstats.NewManager(context.Background(), &appstats.Config{})
	if err != nil {
		t.Fatalf("stats.NewManager() error = %v", err)
	}
	return mgr
}

func mustRegisterCounter(t *testing.T, mgr xraystats.Manager, name string) xraystats.Counter {
	t.Helper()
	counter, err := mgr.RegisterCounter(name)
	if err != nil {
		t.Fatalf("RegisterCounter(%q) error = %v", name, err)
	}
	return counter
}

func counterName(userID int, direction string) string {
	return fmt.Sprintf("user>>>%s>>>traffic>>>%s", userEmail(userID), direction)
}

func newStatsBackedXray(t *testing.T, users []core.UserSpec, ld *LimitDispatcher) (*Xray, xraystats.Manager) {
	t.Helper()
	mgr := newStatsManager(t)
	inst := new(xrayCore.Instance)
	if err := inst.AddFeature(mgr); err != nil {
		t.Fatalf("Instance.AddFeature(stats) error = %v", err)
	}
	x := New(conf.KernelConfig{Type: "xray"})
	x.instance = inst
	x.limitDispatcher = ld
	x.users = users
	x.cumTraffic = make(map[int][2]int64)
	x.running.Store(true)
	return x, mgr
}

func TestXrayGetUserTrafficUsesBuiltInStatsAndDispatcherState(t *testing.T) {
	users := []core.UserSpec{
		{ID: 1, UUID: "uuid-1"},
		{ID: 2, UUID: "uuid-2"},
	}

	ld := newTestDispatcher()
	email1 := userEmail(1)
	email2 := userEmail(2)
	ld.UpdateLimits(map[string]int{email1: 1, email2: 2}, nil, nil)
	ld.seedConns(email1, map[string]int{"1.1.1.1": 1})
	ld.seedConns(email2, map[string]int{"2.2.2.2": 1})
	ld.connCount.Store(7)

	x, mgr := newStatsBackedXray(t, users, ld)
	up1 := mustRegisterCounter(t, mgr, counterName(1, "uplink"))
	down1 := mustRegisterCounter(t, mgr, counterName(1, "downlink"))
	up2 := mustRegisterCounter(t, mgr, counterName(2, "uplink"))
	down2 := mustRegisterCounter(t, mgr, counterName(2, "downlink"))
	up1.Add(100)
	down1.Add(200)
	up2.Add(50)
	down2.Add(80)

	traffic, aliveIPs, connCount, err := x.GetUserTraffic(context.Background())
	if err != nil {
		t.Fatalf("GetUserTraffic() error = %v", err)
	}
	if connCount != 7 {
		t.Fatalf("connCount = %d, want 7", connCount)
	}
	if got := traffic[1]; got != [2]int64{100, 200} {
		t.Fatalf("traffic[1] = %v, want [100 200]", got)
	}
	if got := traffic[2]; got != [2]int64{50, 80} {
		t.Fatalf("traffic[2] = %v, want [50 80]", got)
	}
	if !aliveIPs[1]["1.1.1.1"] {
		t.Fatal("expected limited-user IP to be reported")
	}
	if !aliveIPs[2]["2.2.2.2"] {
		t.Fatal("expected unlimited-user IP to be reported")
	}

	up1.Add(30)
	down1.Add(40)
	traffic, _, _, err = x.GetUserTraffic(context.Background())
	if err != nil {
		t.Fatalf("second GetUserTraffic() error = %v", err)
	}
	if got := traffic[1]; got != [2]int64{130, 240} {
		t.Fatalf("traffic[1] after second poll = %v, want [130 240]", got)
	}
	if got := traffic[2]; got != [2]int64{50, 80} {
		t.Fatalf("traffic[2] after second poll = %v, want [50 80]", got)
	}
}

func TestXrayUpdateDispatcherLimitsPropagatesDeviceMetadata(t *testing.T) {
	x := New(conf.KernelConfig{Type: "xray"})
	ld := newTestDispatcher()
	x.limitDispatcher = ld

	users := []core.UserSpec{
		{ID: 7, UUID: "uuid-7", DeviceLimit: 2, SpeedLimit: 12},
		{ID: 9, UUID: "uuid-9", DeviceLimit: 0, SpeedLimit: 0},
	}

	x.updateDispatcherLimits(users)

	if got := ld.state().deviceLimits[userEmail(7)]; got != 2 {
		t.Fatalf("deviceLimits[email] = %d, want 2", got)
	}
	if got := ld.state().deviceLimits["uuid-7"]; got != 2 {
		t.Fatalf("deviceLimits[uuid] = %d, want 2", got)
	}
	if _, ok := ld.state().deviceLimits[userEmail(9)]; ok {
		t.Fatal("unexpected device limit entry for unlimited user")
	}
}

func TestXraySetSpeedLimitFuncUsesPatchedCorePath(t *testing.T) {
	x := New(conf.KernelConfig{Type: "xray"})
	called := false

	x.SetSpeedLimitFunc(func(string) *rate.Limiter {
		called = true
		return rate.NewLimiter(rate.Limit(1), 1)
	})

	if called {
		t.Fatal("patched xray path should not consult external speed-limit callbacks")
	}

	mu, err := toMemoryUser("vless", &core.NodeSpec{Protocol: "vless"}, core.UserSpec{ID: 1, UUID: "11111111-1111-1111-1111-111111111111", SpeedLimit: 8})
	if err != nil {
		t.Fatalf("toMemoryUser() error = %v", err)
	}
	if mu.Level != 0 {
		t.Fatalf("MemoryUser.Level = %d, want 0", mu.Level)
	}
}

func TestXrayUpdateDispatcherLimitsUsesSpeedLimitFunc(t *testing.T) {
	x := New(conf.KernelConfig{Type: "xray"})
	ld := newTestDispatcher()
	x.limitDispatcher = ld
	x.users = []core.UserSpec{{ID: 1, UUID: "uuid-1", SpeedLimit: 8}}
	shared := rate.NewLimiter(7, 7)
	x.SetSpeedLimitFunc(func(uuid string) *rate.Limiter {
		if uuid != "uuid-1" {
			t.Fatalf("unexpected uuid: %s", uuid)
		}
		return shared
	})
	if ld.speedLimiter(userEmail(1)) != shared {
		t.Fatal("expected dispatcher to consume shared limiter from callback")
	}
}

func TestXrayUpdateDispatcherLimitsFallsBackToUserSpeed(t *testing.T) {
	x := New(conf.KernelConfig{Type: "xray"})
	ld := newTestDispatcher()
	x.limitDispatcher = ld
	x.updateDispatcherLimits([]core.UserSpec{{ID: 2, UUID: "uuid-2", SpeedLimit: 16}, {ID: 3, UUID: "uuid-3"}})
	if ld.speedLimiter(userEmail(2)) == nil {
		t.Fatal("expected fallback limiter derived from user speed")
	}
	if ld.speedLimiter(userEmail(3)) != nil {
		t.Fatal("unexpected limiter for unlimited user")
	}
}

func TestXrayUpdateUsersLimitOnlyRefreshesDispatcherLimits(t *testing.T) {
	x := New(conf.KernelConfig{Type: "xray"})
	ld := newTestDispatcher()
	x.instance = new(xrayCore.Instance)
	x.limitDispatcher = ld
	x.users = []core.UserSpec{{ID: 1, UUID: "uuid-1", DeviceLimit: 1, SpeedLimit: 8}}

	added, removed, err := x.UpdateUsers([]core.UserSpec{{ID: 1, UUID: "uuid-1", DeviceLimit: 3, SpeedLimit: 16}})
	if err != nil {
		t.Fatalf("UpdateUsers() error = %v", err)
	}
	if added != 0 || removed != 0 {
		t.Fatalf("UpdateUsers() counts = (%d, %d), want (0, 0)", added, removed)
	}
	if got := ld.state().deviceLimits[userEmail(1)]; got != 3 {
		t.Fatalf("device limit after refresh = %d, want 3", got)
	}
	if ld.speedLimiter(userEmail(1)) == nil {
		t.Fatal("expected speed limiter to be refreshed for unchanged user set")
	}
}

func TestXrayRemoveUsersStopsKernelWhenLastUserRemoved(t *testing.T) {
	x := New(conf.KernelConfig{Type: "xray"})
	x.instance = new(xrayCore.Instance)
	ld := newTestDispatcher()
	x.limitDispatcher = ld
	x.users = []core.UserSpec{{ID: 1, UUID: "uuid-1"}}
	x.running.Store(true)

	removed, err := x.RemoveUsers([]core.UserSpec{{ID: 1, UUID: "uuid-1"}})
	if err != nil {
		t.Fatalf("RemoveUsers() error = %v", err)
	}
	if removed != 1 {
		t.Fatalf("removed = %d, want 1", removed)
	}
	if x.IsRunning() {
		t.Fatal("expected xray to stop when last user is removed")
	}
}

func TestParseUserCounter(t *testing.T) {
	cases := []struct {
		name    string
		id, dir int
		ok      bool
	}{
		{counterName(42, "uplink"), 42, 0, true},
		{counterName(42, "downlink"), 42, 1, true},
		{"inbound>>>vless-in>>>traffic>>>uplink", 0, 0, false},
		{"user>>>user@x>>>traffic>>>uplink", 0, 0, false},
		{"user>>>user@1>>>traffic>>>sideways", 0, 0, false},
		{"user>>>user@1>>>online", 0, 0, false},
	}
	for _, tc := range cases {
		id, dir, ok := parseUserCounter(tc.name)
		if id != tc.id || dir != tc.dir || ok != tc.ok {
			t.Errorf("parseUserCounter(%q) = %d, %d, %v; want %d, %d, %v", tc.name, id, dir, ok, tc.id, tc.dir, tc.ok)
		}
	}
}

func TestXrayRetiredUserTrafficReportedOnce(t *testing.T) {
	x, mgr := newStatsBackedXray(t, []core.UserSpec{{ID: 1}, {ID: 2}}, nil)
	up1 := mustRegisterCounter(t, mgr, counterName(1, "uplink"))
	mustRegisterCounter(t, mgr, counterName(2, "downlink")).Add(5)
	mustRegisterCounter(t, mgr, "inbound>>>vless-in>>>traffic>>>uplink").Add(999)
	up1.Add(10)

	if traffic, _ := x.aggregateStats(); traffic[1] != [2]int64{10, 0} || traffic[2] != [2]int64{0, 5} || len(traffic) != 2 {
		t.Fatalf("first poll = %v", traffic)
	}

	up1.Add(7)
	x.retireUserStats([]int{1})
	if mgr.GetCounter(counterName(1, "uplink")) != nil {
		t.Fatal("removed user's counter still registered")
	}

	if traffic, _ := x.aggregateStats(); traffic[1] != [2]int64{17, 0} {
		t.Fatalf("poll after removal = %v, want user 1 at [17 0]", traffic)
	}
	traffic, _ := x.aggregateStats()
	if _, ok := traffic[1]; ok {
		t.Fatalf("removed user still reported: %v", traffic)
	}
	if traffic[2] != [2]int64{0, 5} {
		t.Fatalf("remaining user = %v, want [0 5]", traffic[2])
	}
}
