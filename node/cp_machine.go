package node

import (
	"context"
	"fmt"

	"github.com/KilluaAoki/XNode/api/panel"
	"github.com/KilluaAoki/XNode/common/nlog"
	"github.com/KilluaAoki/XNode/conf"
	"github.com/KilluaAoki/XNode/core"
)

type MachinePanelControlPlane struct {
	client *panel.Client
	kcfg   conf.KernelConfig
	push   PushClient

	registerFn func(statuses chan<- StatusChange) *NodeMailbox
}

func NewMachinePanelControlPlane(
	client *panel.Client,
	kcfg conf.KernelConfig,
	push PushClient,
	registerFn func(statuses chan<- StatusChange) *NodeMailbox,
) *MachinePanelControlPlane {
	return &MachinePanelControlPlane{
		client:     client,
		kcfg:       kcfg,
		push:       push,
		registerFn: registerFn,
	}
}

func (p *MachinePanelControlPlane) SupportsPolling() bool       { return true }
func (p *MachinePanelControlPlane) SupportsDiscovery() bool     { return false }
func (p *MachinePanelControlPlane) SupportsReporting() bool     { return true }
func (p *MachinePanelControlPlane) SupportsDeviceReports() bool { return p.push != nil }

func (p *MachinePanelControlPlane) Initial(
	ctx context.Context,
	metricsFn func() map[string]interface{},
	events chan<- Event,
	statuses chan<- StatusChange,
) (Bootstrap, error) {
	hs, err := p.client.Handshake()
	if err != nil {
		nlog.Core().Debug("machine node handshake skipped, using REST", "error", err)
	}

	bootstrap := Bootstrap{}
	if hs != nil {
		bootstrap.PushInterval = hs.Settings.PushInterval
		bootstrap.PullInterval = hs.Settings.PullInterval
	}

	configSnapshot, err := p.client.GetConfig()
	if err != nil {
		return Bootstrap{}, fmt.Errorf("machine initial config: %w", err)
	}
	if configSnapshot == nil {
		return Bootstrap{}, fmt.Errorf("machine initial config is nil")
	}
	users, err := p.client.GetUsers()
	if err != nil {
		return Bootstrap{}, fmt.Errorf("machine initial users: %w", err)
	}
	bootstrap.Config, err = core.NodeSpecFromPanelValidated(configSnapshot, p.kcfg)
	if err != nil {
		return Bootstrap{}, fmt.Errorf("machine initial config normalize: %w", err)
	}
	bootstrap.Users = core.UserSpecsFromPanel(users)

	if p.push != nil {
		if p.registerFn != nil {
			bootstrap.Mailbox = p.registerFn(statuses)
		}
		bootstrap.Push = p.push
	}

	return bootstrap, nil
}

func (p *MachinePanelControlPlane) Poll(ctx context.Context) (Snapshot, error) {
	configSnapshot, err := p.client.GetConfig()
	if err != nil {
		return Snapshot{}, fmt.Errorf("machine poll config: %w", err)
	}
	users, err := p.client.GetUsers()
	if err != nil {
		return Snapshot{}, fmt.Errorf("machine poll users: %w", err)
	}
	select {
	case <-ctx.Done():
		return Snapshot{}, ctx.Err()
	default:
	}
	nodeSpec, err := core.NodeSpecFromPanelValidated(configSnapshot, p.kcfg)
	if err != nil {
		return Snapshot{}, fmt.Errorf("machine poll normalize: %w", err)
	}
	return Snapshot{Config: nodeSpec, Users: core.UserSpecsFromPanel(users)}, nil
}

func (p *MachinePanelControlPlane) Discover(
	ctx context.Context,
	metricsFn func() map[string]interface{},
	events chan<- Event,
	statuses chan<- StatusChange,
) (PushClient, error) {
	return nil, nil
}

func (p *MachinePanelControlPlane) Report(payload ReportPayload) error {
	return p.client.Report(
		payload.Traffic, payload.Alive, payload.Online,
		payload.CPU, payload.Mem, payload.Swap, payload.Disk,
		payload.Metrics,
	)
}

func (p *MachinePanelControlPlane) ReportDevices(push PushClient, devices map[int][]string) {
	if push != nil {
		push.SendDeviceReport(devices)
	}
}

func (p *MachinePanelControlPlane) Metrics() APIMetrics {
	api := p.client.SnapshotMetrics()
	return APIMetrics{Success: api.Success, Failure: api.Failure}
}
