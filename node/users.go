package node

import (
	"context"
	"fmt"

	"github.com/KilluaAoki/XNode/common/nlog"
	"github.com/KilluaAoki/XNode/core"
)

func (s *Service) setUserState(users []core.UserSpec) {
	if users == nil {
		users = []core.UserSpec{}
	}

	s.limiter.UpdateUsers(users)
	s.speedTracker.UpdateBuckets()

	s.metricsMu.Lock()
	s.lastUsers = append([]core.UserSpec(nil), users...)
	s.metricsMu.Unlock()
	s.lastUserHash = computeUserHash(users)
}

// applyNodeLimits caps each user's speed and device limits with the node
// limits from the local config.
func (s *Service) applyNodeLimits(users []core.UserSpec) []core.UserSpec {
	speed, devices := s.cfg.Node.SpeedLimit, s.cfg.Node.DeviceLimit
	if len(users) == 0 || (speed <= 0 && devices <= 0) {
		return users
	}
	out := make([]core.UserSpec, len(users))
	for i, u := range users {
		u.SpeedLimit = minLimit(u.SpeedLimit, speed)
		u.DeviceLimit = minLimit(u.DeviceLimit, devices)
		out[i] = u
	}
	return out
}

// minLimit returns the smaller positive limit; zero means unlimited.
func minLimit(a, b int) int {
	if a <= 0 {
		return max(b, 0)
	}
	if b <= 0 {
		return a
	}
	return min(a, b)
}

func (s *Service) startKernel(nc *core.NodeSpec, users []core.UserSpec) bool {
	if err := s.kernel.Start(nc, users, s.cert.TLSCert()); err != nil {
		nlog.Core().Error("failed to start kernel", "error", err)
		return false
	}

	s.appliedState.Config = nc
	s.appliedState.Users = users

	if s.nodeLog == nil {
		s.nodeLog = nlog.ForNode(nc.Protocol, nc.ServerPort)
	}
	s.speedTracker.SetLogCallback(func(msg string) {
		fullMsg := fmt.Sprintf("speedtracker: %s active_limiters=%d", msg, s.speedTracker.LimitedUserCount())
		s.nodeLog.Info(fullMsg)
	})
	s.nodeLog.Info(fmt.Sprintf("started, %d users", len(users)))
	return true
}

func (s *Service) ensureRunning() bool {
	if s.kernel.IsRunning() {
		return true
	}
	if len(s.lastUsers) > 0 && s.lastConfig != nil {
		return s.restartWith(s.lastUsers)
	}
	return false
}

func (s *Service) restartWith(users []core.UserSpec) bool {
	if s.startKernel(s.lastConfig, users) {
		s.applyPending = false
		return true
	}
	s.applyPending = true
	return false
}

func (s *Service) superviseKernel() {
	if s.lastConfig == nil || len(s.lastUsers) == 0 {
		s.applyPending = false
		return
	}
	running := s.kernel.IsRunning()
	if running && !s.applyPending {
		return
	}
	if s.kernelBackoff.shouldSkip() {
		return
	}
	ok := false
	if running {
		if err := s.kernel.Reload(s.lastConfig, s.lastUsers, s.cert.TLSCert()); err == nil {
			s.appliedState.Config = s.lastConfig
			s.appliedState.Users = s.lastUsers
			ok = true
		}
	}
	if !ok {
		ok = s.startKernel(s.lastConfig, s.lastUsers)
	}
	if !ok {
		s.applyPending = true
		s.kernelBackoff.onFailure()
		return
	}
	s.applyPending = false
	s.kernelBackoff.onSuccess()
	nlog.Core().Info("kernel recovered", "running_before", running, "users", len(s.lastUsers))
}

func (s *Service) applyUserUpdate(ctx context.Context, users []core.UserSpec, newHash string) {
	s.setUserState(users)
	if newHash != "" {
		s.lastUserHash = newHash
	}
	if !s.kernel.IsRunning() {
		s.ensureRunning()
		return
	}
	added, removed, err := s.kernel.UpdateUsers(users)
	if err != nil {
		nlog.Core().Warn(fmt.Sprintf("UpdateUsers failed, restarting kernel: %v", err))
		s.restartWith(users)
		return
	}
	if s.nodeLog != nil && (added > 0 || removed > 0) {
		s.nodeLog.Info(fmt.Sprintf("users updated: +%d -%d", added, removed))
	}
}

func (s *Service) applyUserDelta(ctx context.Context, action string, deltaUsers []core.UserSpec) {
	switch action {
	case "add":
		if len(deltaUsers) == 0 {
			return
		}
		merged := mergeUsers(s.lastUsers, deltaUsers)
		rotated := false
		for _, delta := range deltaUsers {
			for _, old := range s.lastUsers {
				if old.ID == delta.ID && old.UUID != delta.UUID {
					rotated = true
				}
			}
		}
		s.setUserState(merged)
		if !s.kernel.IsRunning() {
			s.ensureRunning()
			return
		}

		added := 0
		var err error
		if rotated {
			added, _, err = s.kernel.UpdateUsers(merged)
		} else if added, err = s.kernel.AddUsers(deltaUsers); err != nil {
			nlog.Core().Warn(fmt.Sprintf("AddUsers failed: %v, falling back to UpdateUsers", err))
			added, _, err = s.kernel.UpdateUsers(merged)
		}
		if err != nil {
			nlog.Core().Error(fmt.Sprintf("user update failed, restarting kernel: %v", err))
			s.restartWith(merged)
			return
		}
		if s.nodeLog != nil && added > 0 {
			s.nodeLog.Info(fmt.Sprintf("users added: +%d", added))
		}

	case "remove":
		if len(deltaUsers) == 0 {
			return
		}
		filtered := subtractUsers(s.lastUsers, deltaUsers)
		s.setUserState(filtered)
		if !s.kernel.IsRunning() {
			return
		}

		removed, err := s.kernel.RemoveUsers(deltaUsers)
		if err != nil {
			nlog.Core().Warn(fmt.Sprintf("RemoveUsers failed: %v, falling back to UpdateUsers", err))
			if _, _, err := s.kernel.UpdateUsers(filtered); err != nil {
				nlog.Core().Error(fmt.Sprintf("UpdateUsers fallback failed, restarting kernel: %v", err))
				if len(filtered) == 0 {
					s.kernel.Stop()
					return
				}
				s.restartWith(filtered)
				return
			}
		}
		if s.nodeLog != nil && removed > 0 {
			s.nodeLog.Info(fmt.Sprintf("users removed: -%d", removed))
		}

	default:
		nlog.Core().Warn(fmt.Sprintf("unknown user delta action: %s", action))
	}
}

func mergeUsers(base, delta []core.UserSpec) []core.UserSpec {
	if base == nil {
		base = []core.UserSpec{}
	}
	if delta == nil {
		return base
	}

	m := make(map[int]core.UserSpec, len(base))
	for _, u := range base {
		m[u.ID] = u
	}
	for _, u := range delta {
		m[u.ID] = u
	}
	out := make([]core.UserSpec, 0, len(m))
	for _, u := range m {
		out = append(out, u)
	}
	return out
}

func subtractUsers(base, delta []core.UserSpec) []core.UserSpec {
	if base == nil {
		return nil
	}
	if delta == nil || len(delta) == 0 {
		return base
	}
	removeSet := make(map[int]struct{}, len(delta))
	for _, u := range delta {
		removeSet[u.ID] = struct{}{}
	}
	out := make([]core.UserSpec, 0, len(base))
	for _, u := range base {
		if _, ok := removeSet[u.ID]; !ok {
			out = append(out, u)
		}
	}
	return out
}

func (s *Service) applyChanges(ctx context.Context, configChanged bool) {
	if !configChanged {
		return
	}

	if s.lastConfig == nil || len(s.lastUsers) == 0 {
		if len(s.lastUsers) == 0 {
			s.kernel.Stop()
			s.appliedState.Users = nil
		}
		return
	}

	if configChanged && s.kernel.IsRunning() {
		if err := s.kernel.Reload(s.lastConfig, s.lastUsers, s.cert.TLSCert()); err != nil {
			nlog.Core().Warn(fmt.Sprintf("reload failed, restarting: %v", err))
			s.restartWith(s.lastUsers)
		} else {
			s.applyPending = false
			s.appliedState.Config = s.lastConfig
			s.appliedState.Users = s.lastUsers
			if s.nodeLog != nil {
				s.nodeLog.Info(fmt.Sprintf("config updated, %d users", len(s.lastUsers)))
			}
		}
	} else if !s.kernel.IsRunning() {
		s.restartWith(s.lastUsers)
	}
}
