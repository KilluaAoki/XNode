package core

import (
	"testing"
	"time"
)

func TestDeviceGate_LocalOnly(t *testing.T) {
	g := NewDeviceGate()
	local := map[string]int{"1.1.1.1": 1, "2.2.2.2": 3}
	if !g.Allow(1, local, "1.1.1.1", 2) {
		t.Error("existing local IP should be allowed")
	}
	if g.Allow(1, local, "0.0.0.1", 2) {
		t.Error("new IP over the local limit should be rejected regardless of sort order")
	}
	if !g.Allow(1, local, "3.3.3.3", 3) {
		t.Error("new IP under the limit should be allowed")
	}
	if !g.Allow(1, local, "3.3.3.3", 0) {
		t.Error("no limit should allow everything")
	}
	var nilGate *DeviceGate
	if nilGate.Allow(1, local, "0.0.0.1", 2) {
		t.Error("nil gate should fall back to local counting")
	}
}

func TestDeviceGate_RemoteCounts(t *testing.T) {
	now := time.Unix(1000, 0)
	g := NewDeviceGate()
	g.now = func() time.Time { return now }
	g.UpdateRemoteCounts(map[int]int{1: 2, 2: 0})

	local := map[string]int{"1.1.1.1": 1}
	if g.Allow(1, local, "2.2.2.2", 3) {
		t.Error("1 local + 2 remote should fill a limit of 3")
	}
	if !g.Allow(1, local, "1.1.1.1", 3) {
		t.Error("existing local IP should be allowed")
	}
	if !g.Allow(2, local, "2.2.2.2", 2) {
		t.Error("user without remote devices should count local only")
	}
	if !g.Allow(0, local, "2.2.2.2", 2) {
		t.Error("unknown uid should count local only")
	}

	now = now.Add(RemoteDeviceCountsTTL + time.Second)
	if !g.Allow(1, local, "2.2.2.2", 3) {
		t.Error("stale remote counts should be ignored")
	}

	now = now.Add(time.Second)
	g.UpdateRemoteCounts(map[int]int{1: 2})
	g.UpdateRemoteCounts(nil)
	if !g.Allow(1, local, "2.2.2.2", 3) {
		t.Error("cleared remote counts should be ignored")
	}
}

func TestDeviceGate_GlobalIPsPreferred(t *testing.T) {
	now := time.Unix(1000, 0)
	g := NewDeviceGate()
	g.now = func() time.Time { return now }
	g.UpdateRemoteCounts(map[int]int{1: 5})
	g.UpdateGlobalIPs(map[int][]string{1: {"9.9.9.9"}})

	local := map[string]int{"1.1.1.1": 1}
	if !g.Allow(1, local, "9.9.9.9", 2) {
		t.Error("IP in the global snapshot should be allowed")
	}
	if !g.Allow(1, local, "2.2.2.2", 2) {
		t.Error("lexicographically earlier candidate should win under the global snapshot")
	}
	if g.Allow(1, local, "99.99.99.99", 2) {
		t.Error("third device across nodes should be rejected")
	}

	now = now.Add(GlobalDeviceIPsTTL + time.Second)
	if g.Allow(1, local, "2.2.2.2", 2) {
		t.Error("stale snapshot should fall back to remote counts (1 local + 5 remote)")
	}
	g.ClearGlobalIPs()
	g.UpdateRemoteCounts(nil)
	if !g.Allow(1, local, "2.2.2.2", 2) {
		t.Error("without global data only local IPs count")
	}
}
