package node

import (
	"context"
	"fmt"

	"github.com/KilluaAoki/XNode/conf"
	"github.com/KilluaAoki/XNode/core"
)

type LocalControlPlane struct {
	cfg *conf.Config
}

func NewLocalControlPlane(cfg *conf.Config) *LocalControlPlane { return &LocalControlPlane{cfg: cfg} }
func (l *LocalControlPlane) SupportsPolling() bool             { return false }
func (l *LocalControlPlane) SupportsDiscovery() bool           { return false }
func (l *LocalControlPlane) SupportsReporting() bool           { return false }
func (l *LocalControlPlane) SupportsDeviceReports() bool       { return false }

func (l *LocalControlPlane) Initial(ctx context.Context, _ func() map[string]interface{}, _ chan<- Event, _ chan<- StatusChange) (Bootstrap, error) {
	select {
	case <-ctx.Done():
		return Bootstrap{}, ctx.Err()
	default:
	}
	nodeSpec, err := core.NodeSpecFromStandaloneValidated(l.cfg)
	if err != nil {
		return Bootstrap{}, fmt.Errorf("load standalone node config: %w", err)
	}
	return Bootstrap{
		PushInterval: l.cfg.Node.PushInterval,
		PullInterval: l.cfg.Node.PullInterval,
		Config:       nodeSpec,
		Users:        core.UserSpecsFromStandalone(l.cfg),
	}, nil
}

func (l *LocalControlPlane) Poll(ctx context.Context) (Snapshot, error) {
	select {
	case <-ctx.Done():
		return Snapshot{}, ctx.Err()
	default:
		return Snapshot{}, nil
	}
}

func (l *LocalControlPlane) Discover(ctx context.Context, _ func() map[string]interface{}, _ chan<- Event, _ chan<- StatusChange) (PushClient, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
		return nil, nil
	}
}

func (l *LocalControlPlane) Report(payload ReportPayload) error { _ = payload; return nil }
func (l *LocalControlPlane) ReportDevices(push PushClient, devices map[int][]string) {
	_, _ = push, devices
}
func (l *LocalControlPlane) Metrics() APIMetrics { return APIMetrics{} }
