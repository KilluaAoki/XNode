package limiter

import (
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

type snapshot struct {
	traffic   map[int][2]int64
	aliveIPs  map[int]map[string]bool
	online    map[int]int
	connCount int
	inSpeed   int64
	outSpeed  int64
}

// perSecond scales bytes counted over elapsed to a per-second rate.
func perSecond(bytes int64, elapsed time.Duration) int64 {
	if elapsed <= 0 {
		return 0
	}
	return int64(float64(bytes) * float64(time.Second) / float64(elapsed))
}

type Tracker struct {
	mu sync.Mutex

	lastSeen map[int][2]int64

	pendingTraffic map[int][2]int64

	// Per-user bytes in the current and previous activity windows, used to
	// drop idle users from online device reports.
	activity     map[int]int64
	prevActivity map[int]int64

	live atomic.Pointer[snapshot]

	lastProcess time.Time
	now         func() time.Time
}

func NewTracker() *Tracker {
	t := &Tracker{
		lastSeen:       make(map[int][2]int64),
		pendingTraffic: make(map[int][2]int64),
		activity:       make(map[int]int64),
		now:            time.Now,
	}
	t.live.Store(&snapshot{
		traffic:  make(map[int][2]int64),
		aliveIPs: make(map[int]map[string]bool),
		online:   make(map[int]int),
	})
	return t
}

func (t *Tracker) Process(
	cumTraffic map[int][2]int64,
	kernelAliveIPs map[int]map[string]bool,
	connCount int,
) {
	t.mu.Lock()
	defer t.mu.Unlock()

	var cycleIn, cycleOut int64

	for uid, cum := range cumTraffic {
		prev := t.lastSeen[uid]
		deltaUp := cum[0] - prev[0]
		deltaDown := cum[1] - prev[1]

		if deltaUp < 0 {
			deltaUp = cum[0]
		}
		if deltaDown < 0 {
			deltaDown = cum[1]
		}

		t.lastSeen[uid] = cum

		if deltaUp > 0 || deltaDown > 0 {
			cur := t.pendingTraffic[uid]
			cur[0] += deltaUp
			cur[1] += deltaDown
			t.pendingTraffic[uid] = cur
			t.activity[uid] += deltaUp + deltaDown

			cycleOut += deltaUp
			cycleIn += deltaDown
		}
	}

	// Speeds cover the time since the previous Process call; the first call
	// has no baseline and reports zero.
	now := t.now()
	var elapsed time.Duration
	if !t.lastProcess.IsZero() {
		elapsed = now.Sub(t.lastProcess)
	}
	t.lastProcess = now

	online := make(map[int]int, len(kernelAliveIPs))
	for uid, ips := range kernelAliveIPs {
		online[uid] = len(ips)
	}

	t.live.Store(&snapshot{
		traffic:   copyTrafficMap(t.pendingTraffic),
		aliveIPs:  kernelAliveIPs,
		online:    online,
		connCount: connCount,
		inSpeed:   perSecond(cycleIn, elapsed),
		outSpeed:  perSecond(cycleOut, elapsed),
	})
}

func (t *Tracker) FlushTraffic(minBytes int64) map[int][2]int64 {
	t.mu.Lock()
	defer t.mu.Unlock()
	data := t.pendingTraffic
	if minBytes <= 0 {
		t.pendingTraffic = make(map[int][2]int64, len(data))
		return data
	}
	out := make(map[int][2]int64, len(data))
	for uid, v := range data {
		if v[0]+v[1] >= minBytes {
			out[uid] = v
			delete(data, uid)
		}
	}
	return out
}

func (t *Tracker) RestoreTraffic(data map[int][2]int64) {
	t.mu.Lock()
	for uid, d := range data {
		cur := t.pendingTraffic[uid]
		cur[0] += d[0]
		cur[1] += d[1]
		t.pendingTraffic[uid] = cur
	}
	t.mu.Unlock()
}

func (t *Tracker) AliveIPs() map[int][]string {
	s := t.live.Load()
	out := make(map[int][]string, len(s.aliveIPs))
	for uid, ips := range s.aliveIPs {
		list := make([]string, 0, len(ips))
		for ip := range ips {
			list = append(list, ip)
		}
		sort.Strings(list)
		out[uid] = list
	}
	return out
}

// RotateActivity starts a new activity window. ActiveAliveIPs looks at the
// current and the previous window together.
func (t *Tracker) RotateActivity() {
	t.mu.Lock()
	t.prevActivity = t.activity
	t.activity = make(map[int]int64, len(t.prevActivity))
	t.mu.Unlock()
}

// ActiveAliveIPs returns AliveIPs restricted to users whose traffic over the
// current and previous activity windows reaches minBytes.
func (t *Tracker) ActiveAliveIPs(minBytes int64) map[int][]string {
	alive := t.AliveIPs()
	if minBytes <= 0 {
		return alive
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	for uid := range alive {
		if t.activity[uid]+t.prevActivity[uid] < minBytes {
			delete(alive, uid)
		}
	}
	return alive
}

func (t *Tracker) CurrentOnline() map[int]int {
	s := t.live.Load()
	cp := make(map[int]int, len(s.online))
	for k, v := range s.online {
		cp[k] = v
	}
	return cp
}

func (t *Tracker) ActiveConnections() int {
	return t.live.Load().connCount
}

// InboundSpeed returns download bytes per second over the last track cycle.
func (t *Tracker) InboundSpeed() int64 {
	return t.live.Load().inSpeed
}

// OutboundSpeed returns upload bytes per second over the last track cycle.
func (t *Tracker) OutboundSpeed() int64 {
	return t.live.Load().outSpeed
}

func copyTrafficMap(src map[int][2]int64) map[int][2]int64 {
	dst := make(map[int][2]int64, len(src))
	for k, v := range src {
		dst[k] = v
	}
	return dst
}
