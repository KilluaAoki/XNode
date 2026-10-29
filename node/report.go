package node

import (
	"context"
	"fmt"

	"github.com/KilluaAoki/XNode/common/monitor"
	"github.com/KilluaAoki/XNode/common/nlog"
	"github.com/KilluaAoki/XNode/core"
)

func (s *Service) trackAndEnforce(ctx context.Context) {
	s.superviseKernel()
	if !s.kernel.IsRunning() {
		return
	}

	traffic, aliveIPs, connCount, err := s.kernel.GetUserTraffic(ctx)
	if err != nil {
		nlog.Core().Debug("get user traffic failed", "error", err)
		return
	}

	s.tracker.Process(traffic, aliveIPs, connCount)

	if connCount > 0 || len(traffic) > 0 {
		if s.nodeLog != nil {
			s.nodeLog.Debug(fmt.Sprintf("tracker: %d conns, %d users online", connCount, len(traffic)))
		} else {
			nlog.TrackerStats(connCount, len(traffic))
		}
	}
}

func (s *Service) pushReportAsync() {
	defer s.tracker.RotateActivity()
	if !s.sink.SupportsReporting() {
		return
	}
	if !s.pushActive.CompareAndSwap(false, true) {
		nlog.Core().Debug("push already in progress, skipping")
		return
	}
	if s.pushBackoff.shouldSkip() {
		nlog.Core().Debug("skipping report due to backoff")
		s.pushActive.Store(false)
		return
	}

	traffic := s.tracker.FlushTraffic(s.reportMinTrafficBytes())
	aliveIPs := s.reportAliveIPs()
	online := s.tracker.CurrentOnline()
	status := monitor.Collect()
	metrics := s.buildMetrics(status)
	metrics["kernel_status"] = s.kernel.IsRunning()

	go func() {
		defer s.pushActive.Store(false)
		if err := s.sink.Report(ReportPayload{Traffic: traffic, Alive: aliveIPs, Online: online, CPU: status.CPU, Mem: [2]uint64{status.MemTotal, status.MemUsed}, Swap: [2]uint64{status.SwapTotal, status.SwapUsed}, Disk: [2]uint64{status.DiskTotal, status.DiskUsed}, Metrics: metrics}); err != nil {
			nlog.Core().Warn("failed to push report", "error", err)
			if len(traffic) > 0 {
				s.tracker.RestoreTraffic(traffic)
			}
			s.pushBackoff.onFailure()
			return
		}
		if aliveIPs != nil {
			s.setReportedAlive(aliveIPs)
		}
		s.pushBackoff.onSuccess()
		nlog.ReportPushed(len(traffic), len(online))
	}()
}

func (s *Service) pushReportSync() {
	if !s.sink.SupportsReporting() {
		return
	}
	traffic := s.tracker.FlushTraffic(0)
	aliveIPs := s.reportAliveIPs()
	online := s.tracker.CurrentOnline()
	status := monitor.Collect()
	metrics := s.buildMetrics(status)
	metrics["kernel_status"] = s.kernel.IsRunning()

	if err := s.sink.Report(ReportPayload{Traffic: traffic, Alive: aliveIPs, Online: online, CPU: status.CPU, Mem: [2]uint64{status.MemTotal, status.MemUsed}, Swap: [2]uint64{status.SwapTotal, status.SwapUsed}, Disk: [2]uint64{status.DiskTotal, status.DiskUsed}, Metrics: metrics}); err != nil {
		nlog.Core().Warn("failed to push final report", "error", err)
	}
}

func (s *Service) buildMetrics(status monitor.Status) map[string]interface{} {
	s.metricsMu.RLock()
	lastUsers := s.lastUsers
	wsClient := s.wsClient
	s.metricsMu.RUnlock()

	m := make(map[string]interface{})
	online := s.tracker.CurrentOnline()

	m["uptime"] = status.Uptime
	m["goroutines"] = status.Goroutines

	m["active_connections"] = s.tracker.ActiveConnections()
	if cc, ok := s.kernel.(core.ConnectionCounter); ok {
		m["total_connections"] = cc.TotalConnections()
	}
	m["active_users"] = len(online)
	m["total_users"] = len(lastUsers)

	m["inbound_speed"] = s.tracker.InboundSpeed()
	m["outbound_speed"] = s.tracker.OutboundSpeed()

	m["speed_limiter"] = map[string]interface{}{
		"has_limits":    s.speedTracker.HasLimits(),
		"limited_users": s.speedTracker.LimitedUserCount(),
	}

	m["gc"] = map[string]interface{}{
		"last_pause_ms": status.LastPauseMS,
	}

	api := s.source.Metrics()
	m["api"] = map[string]interface{}{
		"success": api.Success,
		"failure": api.Failure,
	}

	wsEnabled := wsClient != nil
	wsConnected := wsEnabled && wsClient.IsConnected()
	m["ws"] = map[string]interface{}{
		"enabled":   wsEnabled,
		"connected": wsConnected,
	}

	lm := s.limiter.SnapshotMetrics()
	m["limits"] = map[string]interface{}{
		"device_limit_events": lm.DeviceLimitEvents,
	}

	return m
}

func (s *Service) sendDeviceBatch() {
	if s.wsClient == nil || !s.wsClient.IsConnected() {
		return
	}

	devices := s.tracker.ActiveAliveIPs(s.deviceOnlineMinTrafficBytes())
	s.sink.ReportDevices(s.wsClient, devices)
	s.setReportedAlive(devices)
	nlog.Core().Debug("device snapshot sent", "users", len(devices))
}

func (s *Service) reportAliveIPs() map[int][]string {
	if s.wsClient != nil && s.wsClient.IsConnected() {
		return nil
	}
	return s.tracker.ActiveAliveIPs(s.deviceOnlineMinTrafficBytes())
}

func (s *Service) reportDevices() {
	s.sendDeviceBatch()
}

// reportMinTrafficBytes prefers the local report_min_traffic_kb and falls
// back to the panel's base_config.node_report_min_traffic.
func (s *Service) reportMinTrafficBytes() int64 {
	kb := s.cfg.Node.ReportMinTrafficKB
	if kb <= 0 {
		kb, _ = s.panelTrafficThresholds()
	}
	return int64(kb) * 1024
}

// deviceOnlineMinTrafficBytes is the panel's base_config.device_online_min_traffic.
func (s *Service) deviceOnlineMinTrafficBytes() int64 {
	_, kb := s.panelTrafficThresholds()
	return int64(kb) * 1024
}

func (s *Service) panelTrafficThresholds() (reportKB, deviceKB int) {
	s.metricsMu.RLock()
	defer s.metricsMu.RUnlock()
	if s.lastConfig == nil {
		return 0, 0
	}
	return max(s.lastConfig.NodeReportMinTraffic, 0), max(s.lastConfig.DeviceOnlineMinTraffic, 0)
}

func (s *Service) setReportedAlive(alive map[int][]string) {
	s.metricsMu.Lock()
	s.reportedAlive = alive
	s.metricsMu.Unlock()
}

// applyAliveCounts hands the kernel the devices each user has online on
// other nodes: the panel count minus what this node last reported.
func (s *Service) applyAliveCounts(counts map[int]int) {
	if counts == nil {
		s.kernel.UpdateRemoteDeviceCounts(nil)
		return
	}
	s.metricsMu.RLock()
	reported := s.reportedAlive
	s.metricsMu.RUnlock()

	remote := make(map[int]int, len(counts))
	for uid, n := range counts {
		if r := n - len(reported[uid]); r > 0 {
			remote[uid] = r
		}
	}
	s.kernel.UpdateRemoteDeviceCounts(remote)
	nlog.Core().Debug("remote device counts updated", "users", len(remote))
}
