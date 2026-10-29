package monitor

import (
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/KilluaAoki/XNode/common/nlog"
	"github.com/shirou/gopsutil/v4/cpu"
	"github.com/shirou/gopsutil/v4/disk"
	"github.com/shirou/gopsutil/v4/mem"
	"github.com/shirou/gopsutil/v4/net"
)

// cacheTTL bounds how often the host is sampled; callers within the window
// share one sample, which also keeps the network speed baseline consistent.
const cacheTTL = 5 * time.Second

var startTime = time.Now()

type Status struct {
	Uptime     uint64
	CPU        float64
	MemTotal   uint64
	MemUsed    uint64
	SwapTotal  uint64
	SwapUsed   uint64
	DiskTotal  uint64
	DiskUsed   uint64
	Goroutines int

	// NetInSpeed and NetOutSpeed are -1 until a baseline exists.
	NetInSpeed  float64
	NetOutSpeed float64

	LastPauseMS float64
}

var (
	mu       sync.Mutex
	cached   Status
	cachedAt time.Time

	netPrevRecv uint64
	netPrevSent uint64
	netPrevTime time.Time
	netHasBase  bool
)

func skipInterface(name string) bool {
	lower := strings.ToLower(name)
	for _, prefix := range []string{"lo", "docker", "veth", "br-", "virbr", "vnet", "tun", "tap"} {
		if strings.HasPrefix(lower, prefix) {
			return true
		}
	}
	return false
}

// collectNetSpeed must be called with mu held.
func collectNetSpeed() (inSpeed, outSpeed float64) {
	counters, err := net.IOCounters(true)
	if err != nil {
		nlog.Core().Debug("failed to get network counters", "error", err)
		return -1, -1
	}

	var totalRecv, totalSent uint64
	for _, c := range counters {
		if skipInterface(c.Name) {
			continue
		}
		totalRecv += c.BytesRecv
		totalSent += c.BytesSent
	}

	now := time.Now()

	if !netHasBase {
		netPrevRecv, netPrevSent, netPrevTime, netHasBase = totalRecv, totalSent, now, true
		return -1, -1
	}

	elapsed := now.Sub(netPrevTime).Seconds()
	if elapsed <= 0 {
		return -1, -1
	}

	if totalRecv < netPrevRecv || totalSent < netPrevSent {
		netPrevRecv, netPrevSent, netPrevTime = totalRecv, totalSent, now
		return -1, -1
	}

	inSpeed = float64(totalRecv-netPrevRecv) / elapsed
	outSpeed = float64(totalSent-netPrevSent) / elapsed

	netPrevRecv, netPrevSent, netPrevTime = totalRecv, totalSent, now
	return inSpeed, outSpeed
}

// Collect returns host and process status, sampling at most once per cacheTTL.
func Collect() Status {
	mu.Lock()
	defer mu.Unlock()

	if cachedAt.IsZero() || time.Since(cachedAt) >= cacheTTL {
		cached = sample()
		cachedAt = time.Now()
	}
	s := cached
	s.Uptime = uint64(time.Since(startTime).Seconds())
	return s
}

func sample() Status {
	var s Status

	// gopsutil records a baseline at init, so a zero interval measures usage
	// since the previous call without blocking.
	if cpuPercent, err := cpu.Percent(0, false); err == nil && len(cpuPercent) > 0 {
		s.CPU = cpuPercent[0]
	} else if err != nil {
		nlog.Core().Debug("failed to get CPU usage", "error", err)
	}

	if vmStat, err := mem.VirtualMemory(); err == nil {
		s.MemTotal = vmStat.Total
		s.MemUsed = vmStat.Used
	}

	if swapStat, err := mem.SwapMemory(); err == nil {
		s.SwapTotal = swapStat.Total
		s.SwapUsed = swapStat.Used
	}

	if diskStat, err := disk.Usage("/"); err == nil {
		s.DiskTotal = diskStat.Total
		s.DiskUsed = diskStat.Used
	}

	s.NetInSpeed, s.NetOutSpeed = collectNetSpeed()

	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	s.Goroutines = runtime.NumGoroutine()
	if ms.NumGC > 0 {
		idx := (ms.NumGC - 1) % uint32(len(ms.PauseNs))
		s.LastPauseMS = float64(ms.PauseNs[idx]) / 1e6
	}

	return s
}
