package core

import (
	"sort"
	"sync"
	"time"
)

const (
	// GlobalDeviceIPsTTL bounds how long a pushed global device IP snapshot
	// (WebSocket sync.devices) is trusted.
	GlobalDeviceIPsTTL = 60 * time.Second
	// RemoteDeviceCountsTTL bounds how long panel alivelist counts are trusted.
	RemoteDeviceCountsTTL = 5 * time.Minute
)

// DeviceGate decides whether a new source IP may connect for a user with a
// device limit. It combines the IPs this node currently holds with, in order
// of preference, a fresh global IP snapshot or fresh per-user counts of
// devices online on other nodes. Without fresh global data only local IPs
// are counted.
type DeviceGate struct {
	mu       sync.RWMutex
	ips      map[int]map[string]bool
	ipsAt    time.Time
	remote   map[int]int
	remoteAt time.Time

	now func() time.Time
}

func NewDeviceGate() *DeviceGate {
	return &DeviceGate{now: time.Now}
}

// UpdateGlobalIPs replaces the global device IP snapshot.
func (g *DeviceGate) UpdateGlobalIPs(users map[int][]string) {
	ips := make(map[int]map[string]bool, len(users))
	for uid, list := range users {
		set := make(map[string]bool, len(list))
		for _, ip := range list {
			set[ip] = true
		}
		ips[uid] = set
	}
	g.mu.Lock()
	g.ips = ips
	g.ipsAt = g.now()
	g.mu.Unlock()
}

// ClearGlobalIPs drops the global device IP snapshot.
func (g *DeviceGate) ClearGlobalIPs() {
	g.mu.Lock()
	g.ips = nil
	g.ipsAt = time.Time{}
	g.mu.Unlock()
}

// UpdateRemoteCounts replaces the per-user count of devices online on other
// nodes. A nil map clears it.
func (g *DeviceGate) UpdateRemoteCounts(counts map[int]int) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if counts == nil {
		g.remote = nil
		g.remoteAt = time.Time{}
		return
	}
	g.remote = make(map[int]int, len(counts))
	for uid, n := range counts {
		if n > 0 {
			g.remote[uid] = n
		}
	}
	g.remoteAt = g.now()
}

// Allow reports whether sourceIP may connect. local holds the IPs the user
// currently has on this node; uid 0 means the user is unknown globally.
func (g *DeviceGate) Allow(uid int, local map[string]int, sourceIP string, limit int) bool {
	if limit <= 0 || local[sourceIP] > 0 {
		return true
	}

	var globalIPs map[string]bool
	remote, haveRemote := 0, false
	if g != nil && uid != 0 {
		g.mu.RLock()
		now := g.now()
		if g.ips != nil && now.Sub(g.ipsAt) <= GlobalDeviceIPsTTL {
			globalIPs = g.ips[uid]
		}
		if g.remote != nil && now.Sub(g.remoteAt) <= RemoteDeviceCountsTTL {
			remote, haveRemote = g.remote[uid], true
		}
		g.mu.RUnlock()
	}

	if globalIPs != nil {
		if globalIPs[sourceIP] {
			return true
		}
		all := make(map[string]bool, len(local)+len(globalIPs))
		for ip := range local {
			all[ip] = true
		}
		for ip := range globalIPs {
			all[ip] = true
		}
		if len(all) < limit {
			return true
		}
		// Every node sees the same snapshot, so the lowest IPs win
		// consistently across nodes.
		list := make([]string, 0, len(all)+1)
		for ip := range all {
			list = append(list, ip)
		}
		list = append(list, sourceIP)
		sort.Strings(list)
		for i := 0; i < limit; i++ {
			if list[i] == sourceIP {
				return true
			}
		}
		return false
	}

	if haveRemote {
		return len(local)+remote < limit
	}
	return len(local) < limit
}
