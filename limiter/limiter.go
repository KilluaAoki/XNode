package limiter

import (
	"sync"
	"sync/atomic"

	"github.com/KilluaAoki/XNode/core"
)

type Limiter struct {
	mu    sync.RWMutex
	users map[int]core.UserSpec

	uuidDeviceLimit map[string]int

	deviceLimitEvents atomic.Uint64
}

func New() *Limiter {
	return &Limiter{
		users:           make(map[int]core.UserSpec),
		uuidDeviceLimit: make(map[string]int),
	}
}

func (l *Limiter) UpdateUsers(users []core.UserSpec) []int {
	l.mu.Lock()
	defer l.mu.Unlock()

	newUsers := make(map[int]core.UserSpec, len(users))
	for _, u := range users {
		newUsers[u.ID] = u
	}

	var removed []int
	for id := range l.users {
		if _, ok := newUsers[id]; !ok {
			removed = append(removed, id)
		}
	}

	l.users = newUsers

	idx := make(map[string]int, len(newUsers))
	for _, u := range newUsers {
		if u.DeviceLimit > 0 {
			idx[u.UUID] = u.DeviceLimit
		}
	}
	l.uuidDeviceLimit = idx

	return removed
}

type LimiterMetrics struct {
	DeviceLimitEvents uint64
}

func (l *Limiter) SnapshotMetrics() LimiterMetrics {
	return LimiterMetrics{
		DeviceLimitEvents: l.deviceLimitEvents.Load(),
	}
}

func (l *Limiter) GetDeviceLimitByUUID(uuid string) (int, bool) {
	l.mu.RLock()
	defer l.mu.RUnlock()
	limit, ok := l.uuidDeviceLimit[uuid]
	return limit, ok
}
