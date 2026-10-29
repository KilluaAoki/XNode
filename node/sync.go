package node

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"time"

	"github.com/KilluaAoki/XNode/common/monitor"
	"github.com/KilluaAoki/XNode/common/nlog"
	"github.com/KilluaAoki/XNode/core"
)

func (s *Service) startWSClient(ctx context.Context) {
	if s.wsClient == nil {
		return
	}
	wsCtx, wsCancel := context.WithCancel(ctx)
	s.wsCancel = wsCancel
	go s.wsClient.Run(wsCtx)
}

func (s *Service) markMailboxReadyAndDrain(ctx context.Context) {
	if s.machineMailbox == nil {
		return
	}
	s.metricsMu.RLock()
	users := s.lastUsers
	config := s.lastConfig
	s.metricsMu.RUnlock()
	s.machineMailbox.SeedBaseline(users, config)
	s.machineMailbox.MarkReady()
	s.drainMachineMailbox(ctx)
}

func (s *Service) drainMachineMailbox(ctx context.Context) {
	if s.machineMailbox == nil {
		return
	}
	state := s.machineMailbox.DrainIfReady()
	if state.HasConfig {
		s.handleWSEvent(ctx, Event{Type: EventSyncConfig, Config: state.Config})
	}
	if state.HasUsers {
		s.handleWSEvent(ctx, Event{Type: EventSyncUsers, Users: state.Users})
	}
	if state.HasDevices {
		s.handleWSEvent(ctx, Event{Type: EventSyncDevices, DeviceUsers: state.DeviceUsers})
	}
	if state.NeedsReconcile {
		s.requestWSResync(ctx, "machine_mailbox_reconcile")
	}
}

func (s *Service) requestWSResync(ctx context.Context, reason string) {
	if !s.wsResyncPending.CompareAndSwap(false, true) {
		return
	}
	if s.nodeLog != nil {
		s.nodeLog.Warn("ws state may be stale, scheduling REST reconciliation", "reason", reason)
	} else {
		nlog.Core().Warn("ws state may be stale, scheduling REST reconciliation", "reason", reason)
	}
	s.pullViaAPIAsync(ctx)
}

func (s *Service) wsMetrics() map[string]interface{} {
	status := monitor.Collect()
	m := s.buildMetrics(status)
	m["kernel_status"] = s.kernel.IsRunning()
	return m
}

func (s *Service) handleWSStatus(ctx context.Context, status StatusChange) {
	if status.NeedsResync {
		s.requestWSResync(ctx, "drop_detected")
	}
	state := int8(-1)
	if status.Connected {
		state = 1
	}
	if state == s.wsState {
		return
	}
	s.wsState = state
	if status.Connected {
		s.metricsMu.Lock()
		s.wsDisconnectAt = time.Time{}
		s.metricsMu.Unlock()
		if s.nodeLog != nil {
			s.nodeLog.Info("ws connected")
		} else {
			nlog.Core().Info("ws connected")
		}
		s.pullViaAPIAsync(ctx)
	} else {
		s.metricsMu.Lock()
		if s.wsDisconnectAt.IsZero() {
			s.wsDisconnectAt = time.Now()
		}
		s.metricsMu.Unlock()
		if s.nodeLog != nil {
			s.nodeLog.Info("ws disconnected")
		} else {
			nlog.Core().Info("ws disconnected")
		}
		s.kernel.ClearGlobalDevices()
		s.pullViaAPIAsync(ctx)
	}
}

func (s *Service) wsDiscovery(ctx context.Context) {
	if !s.source.SupportsDiscovery() {
		return
	}

	needsCheck := false
	if s.wsClient == nil {
		needsCheck = true
		nlog.Core().Debug("push discovery: no push client, checking if control plane enabled push")
	} else if !s.wsDisconnectAt.IsZero() && time.Since(s.wsDisconnectAt) > 10*time.Minute {
		needsCheck = true
		nlog.Core().Debug("push discovery: push disconnected for >10min, re-checking")
	}
	if !needsCheck {
		return
	}

	pushClient, err := s.source.Discover(ctx, s.wsMetrics, s.wsEvents, s.wsStatusCh)
	if err != nil {
		nlog.Core().Debug("push discovery failed", "error", err)
		return
	}
	if s.source.SupportsPolling() {
		s.pullViaAPIAsync(ctx)
	}

	if pushClient != nil {
		if s.wsClient == nil {
			nlog.Core().Info("push discovery: control plane enabled push, creating client")
			s.metricsMu.Lock()
			s.wsClient = pushClient
			s.wsDisconnectAt = time.Time{}
			s.metricsMu.Unlock()
			s.startWSClient(ctx)
		}
	} else if s.wsClient != nil {
		nlog.Core().Info("push discovery: control plane disabled push, switching to polling")
		if s.wsCancel != nil {
			s.wsCancel()
		}
		s.metricsMu.Lock()
		s.wsClient = nil
		s.wsDisconnectAt = time.Time{}
		s.metricsMu.Unlock()
		s.wsCancel = nil
	}
}

func (s *Service) handleWSEvent(ctx context.Context, event Event) {
	switch event.Type {
	case EventSyncConfig:
		if event.Config == nil {
			return
		}
		newConfigHash := computeConfigHash(event.Config)
		if newConfigHash == s.lastConfigHash {
			return
		}
		if err := validateNodeRuntime(s.cfg, s.kernel.Protocols(), event.Config, s.cert.TLSCert()); err != nil {
			nlog.Core().Warn("ws config validation failed, ignoring update", "error", err)
			return
		}
		if s.nodeLog == nil {
			s.nodeLog = nlog.ForNode(event.Config.Protocol, event.Config.ServerPort)
		}
		s.nodeLog.Info(fmt.Sprintf("config updated, %d users", len(event.Users)))
		s.metricsMu.Lock()
		s.lastConfig = event.Config
		s.metricsMu.Unlock()
		s.lastConfigHash = newConfigHash
		s.applyRemoteOverrides(ctx, event.Config)
		s.applyChanges(ctx, true, false)

	case EventSyncUsers:
		if event.Users == nil {
			return
		}
		event.Users = s.applyNodeLimits(event.Users)
		newHash := computeUserHash(event.Users)
		if newHash == s.lastUserHash {
			return
		}
		if s.nodeLog != nil {
			s.nodeLog.Info(fmt.Sprintf("users updated, %d users", len(event.Users)))
		}
		s.applyUserUpdate(ctx, event.Users, newHash)

	case EventSyncUserDelta:
		if len(event.DeltaUsers) == 0 {
			return
		}
		event.DeltaUsers = s.applyNodeLimits(event.DeltaUsers)
		if s.nodeLog != nil {
			s.nodeLog.Info(fmt.Sprintf("users delta: %s, %d users", event.DeltaAction, len(event.DeltaUsers)))
		}
		s.applyUserDelta(ctx, event.DeltaAction, event.DeltaUsers)

	case EventSyncDevices:
		if event.DeviceUsers != nil {
			s.kernel.UpdateGlobalDevices(event.DeviceUsers)
		}

	default:
		nlog.Core().Debug(fmt.Sprintf("unknown ws event: %v", event.Type))
	}
}

func (s *Service) pullViaAPIAsync(ctx context.Context) {
	if !s.source.SupportsPolling() {
		return
	}
	if !s.pullActive.CompareAndSwap(false, true) {
		nlog.Core().Debug("pull already in progress, skipping")
		return
	}
	if s.pullBackoff.shouldSkip() {
		nlog.Core().Debug("skipping pull due to backoff")
		s.pullActive.Store(false)
		return
	}

	currentConfigHash := s.lastConfigHash
	certChanged := s.cert.CertRenewed()

	go func() {
		defer s.pullActive.Store(false)
		snapshot, err := s.source.Poll(ctx)
		if err != nil {
			nlog.Core().Error("poll control plane failed", "error", err)
			s.pullBackoff.onFailure()
			return
		}
		s.pullBackoff.onSuccess()

		result := pullResult{certChanged: certChanged, aliveCounts: snapshot.AliveCounts}
		if snapshot.Config != nil {
			result.config = snapshot.Config
			result.configHash = computeConfigHash(snapshot.Config)
			if result.configHash == currentConfigHash && !certChanged {
				result.config = nil
			}
		}
		if snapshot.Users != nil {
			result.users = s.applyNodeLimits(snapshot.Users)
			result.userHash = computeUserHash(result.users)
		}

		select {
		case s.pullResults <- result:
		case <-ctx.Done():
		}
	}()
}

func (s *Service) applyPullResult(ctx context.Context, result pullResult) {
	s.wsResyncPending.Store(false)
	s.applyAliveCounts(result.aliveCounts)
	configChanged := false

	if result.certChanged {
		nlog.Core().Info("certificate renewed, kernel restart needed")
		configChanged = true
	}

	if result.config != nil {
		if err := validateNodeRuntime(s.cfg, s.kernel.Protocols(), result.config, s.cert.TLSCert()); err != nil {
			nlog.Core().Warn("runtime config validation failed", "error", err)
			result.config = nil
		} else {
			configChanged = true
			if s.nodeLog == nil {
				s.nodeLog = nlog.ForNode(result.config.Protocol, result.config.ServerPort)
			}
			s.nodeLog.Info(fmt.Sprintf("config updated, %d users", len(s.lastUsers)))
			s.metricsMu.Lock()
			s.lastConfig = result.config
			s.metricsMu.Unlock()
			s.lastConfigHash = result.configHash
			if s.applyRemoteOverrides(ctx, result.config) {
				configChanged = true
			}
		}
	}

	if result.users != nil {
		usersChanged := result.userHash != s.lastUserHash

		if usersChanged && !configChanged {
			s.applyUserUpdate(ctx, result.users, result.userHash)
		} else if usersChanged {
			s.setUserState(result.users)
		}
	}

	if configChanged {
		s.applyChanges(ctx, true, false)
	}
}

func computeConfigHash(cfg *core.NodeSpec) string {
	if cfg == nil {
		return ""
	}
	h := sha256.New()
	data, _ := json.Marshal(cfg)
	h.Write(data)
	return fmt.Sprintf("%x", h.Sum(nil))
}

func computeUserHash(users []core.UserSpec) string {
	sorted := make([]core.UserSpec, len(users))
	copy(sorted, users)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].ID < sorted[j].ID })

	h := sha256.New()
	var buf [8]byte
	for _, u := range sorted {
		binary.LittleEndian.PutUint64(buf[:], uint64(u.ID))
		h.Write(buf[:])
		io.WriteString(h, u.UUID)
		binary.LittleEndian.PutUint64(buf[:], uint64(u.SpeedLimit))
		h.Write(buf[:])
		binary.LittleEndian.PutUint64(buf[:], uint64(u.DeviceLimit))
		h.Write(buf[:])
	}
	return fmt.Sprintf("%x", h.Sum(nil))
}
