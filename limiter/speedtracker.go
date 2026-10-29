package limiter

import (
	"sync"
	"sync/atomic"

	"github.com/KilluaAoki/XNode/core"
	"golang.org/x/time/rate"
)

type SpeedTrackerLogCallback func(msg string)

type SpeedTracker struct {
	limiter *Limiter
	mu      sync.RWMutex
	buckets map[int]*rate.Limiter
	uuidMap map[string]int

	hasLimits atomic.Bool

	logFunc SpeedTrackerLogCallback
}

func NewSpeedTracker(l *Limiter) *SpeedTracker {
	return &SpeedTracker{
		limiter: l,
		buckets: make(map[int]*rate.Limiter),
		uuidMap: make(map[string]int),
	}
}

func (t *SpeedTracker) SetLogCallback(f SpeedTrackerLogCallback) {
	t.logFunc = f
}

func (t *SpeedTracker) UpdateBuckets() {
	currentUsers := make([]core.UserSpec, 0, 32)
	t.limiter.mu.RLock()
	for _, u := range t.limiter.users {
		currentUsers = append(currentUsers, u)
	}
	t.limiter.mu.RUnlock()

	func() {
		t.mu.Lock()
		defer t.mu.Unlock()

		newUUIDMap := make(map[string]int, len(currentUsers))
		activeIDs := make(map[int]struct{}, len(currentUsers))

		for _, user := range currentUsers {
			activeIDs[user.ID] = struct{}{}
			if user.UUID != "" {
				newUUIDMap[user.UUID] = user.ID
			}

			if lim, ok := t.buckets[user.ID]; ok {
				if user.SpeedLimit > 0 {
					bytesPerSec := int(user.SpeedLimit) * 1_000_000 / 8
					burst := bytesPerSec
					if burst < 64*1024 {
						burst = 64 * 1024
					}
					lim.SetLimit(rate.Limit(bytesPerSec))
					lim.SetBurst(burst)
				} else {
					delete(t.buckets, user.ID)
				}
			}
		}

		for id := range t.buckets {
			if _, ok := activeIDs[id]; !ok {
				delete(t.buckets, id)
			}
		}

		t.uuidMap = newUUIDMap
		t.hasLimits.Store(len(t.buckets) > 0)
	}()

	if t.logFunc != nil {
		t.logFunc("buckets updated")
	}
}

func (t *SpeedTracker) GetLimiter(user string) *rate.Limiter {
	t.mu.RLock()
	uid, exists := t.uuidMap[user]
	if !exists {
		t.mu.RUnlock()
		return nil
	}
	if lim, ok := t.buckets[uid]; ok {
		t.mu.RUnlock()
		return lim
	}
	t.mu.RUnlock()

	t.limiter.mu.RLock()
	u, userExists := t.limiter.users[uid]
	t.limiter.mu.RUnlock()

	if !userExists || u.SpeedLimit <= 0 {
		return nil
	}

	bytesPerSec := int(u.SpeedLimit) * 1_000_000 / 8
	burst := bytesPerSec
	if burst < 64*1024 {
		burst = 64 * 1024
	}
	if cap4s := bytesPerSec * 4; cap4s > 64*1024 && burst > cap4s {
		burst = cap4s
	}

	lim := rate.NewLimiter(rate.Limit(bytesPerSec), burst)

	t.mu.Lock()
	if existing, ok := t.buckets[uid]; ok {
		t.mu.Unlock()
		return existing
	}
	t.buckets[uid] = lim
	t.hasLimits.Store(true)
	t.mu.Unlock()

	return lim
}

func (t *SpeedTracker) HasLimits() bool {
	return t.hasLimits.Load()
}

func (t *SpeedTracker) LimitedUserCount() int {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return len(t.buckets)
}
