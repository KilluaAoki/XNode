package node

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/KilluaAoki/XNode/common/nlog"
	"github.com/KilluaAoki/XNode/conf"
	"github.com/KilluaAoki/XNode/core"
	"github.com/KilluaAoki/XNode/core/sing"
	"github.com/KilluaAoki/XNode/core/xray"
	"github.com/KilluaAoki/XNode/limiter"
	"github.com/KilluaAoki/XNode/node/cert"
)

const (
	trackInterval        = 10 * time.Second
	deviceReportInterval = 30 * time.Second
	wsDiscoveryInterval  = 5 * time.Minute
)

type Service struct {
	cfg          *conf.Config
	source       Source
	sink         Sink
	kernel       core.Kernel
	tracker      *limiter.Tracker
	limiter      *limiter.Limiter
	speedTracker *limiter.SpeedTracker
	cert         *cert.Manager

	lastConfig *core.NodeSpec
	lastUsers  []core.UserSpec

	// reportedAlive is the alive IP set last delivered to the panel, used to
	// tell this node's devices apart in alivelist counts. Guarded by metricsMu.
	reportedAlive map[int][]string

	nodeLog *nlog.NodeLog

	appliedState struct {
		Config *core.NodeSpec
		Users  []core.UserSpec
	}

	pushInterval int
	pullInterval int
	// reportTicker and pullTicker are owned by Run's loop; nil before it starts.
	reportTicker *time.Ticker
	pullTicker   *time.Ticker

	lastUserHash   string
	lastConfigHash string
	pullBackoff    apiBackoff
	pushBackoff    apiBackoff
	kernelBackoff  apiBackoff
	applyPending   bool

	pushActive  atomic.Bool
	pullActive  atomic.Bool
	pullResults chan pullResult

	wsClient         PushClient
	wsEvents         chan Event
	wsStatusCh       chan StatusChange
	wsCancel         context.CancelFunc
	wsDisconnectAt   time.Time
	wsState          int8
	wsResyncPending  atomic.Bool
	machineMailbox   *NodeMailbox
	machineMailboxCh <-chan struct{}

	metricsMu sync.RWMutex
}

type pullResult struct {
	config      *core.NodeSpec
	users       []core.UserSpec
	configHash  string
	userHash    string
	certChanged bool
	// aliveCounts is the panel alivelist; nil when unavailable.
	aliveCounts map[int]int
}

type apiBackoff struct {
	mu            sync.Mutex
	skipRemaining int
}

func (b *apiBackoff) shouldSkip() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.skipRemaining > 0 {
		b.skipRemaining--
		return true
	}
	return false
}

func (b *apiBackoff) onSuccess() {
	b.mu.Lock()
	b.skipRemaining = 0
	b.mu.Unlock()
}

func (b *apiBackoff) onFailure() {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.skipRemaining <= 0 {
		b.skipRemaining = 1
	} else if b.skipRemaining < 8 {
		b.skipRemaining *= 2
	}
}

func New(cfg *conf.Config) *Service {
	var cp ControlPlane
	if cfg.IsStandalone() {
		cp = NewLocalControlPlane(cfg)
	} else {
		cp = NewPanelControlPlane(cfg.Panel, cfg.Kernel)
	}
	return newService(cfg, cp)
}

func NewWithControlPlane(cfg *conf.Config, cp ControlPlane) *Service {
	return newService(cfg, cp)
}

func newService(cfg *conf.Config, cp ControlPlane) *Service {
	certMgr := cert.NewManager(cfg.Cert)

	var k core.Kernel
	switch cfg.Kernel.Type {
	case "singbox":
		k = sing.New(cfg.Kernel)
	case "xray":
		k = xray.New(cfg.Kernel)
	default:
		nlog.Core().Warn("unsupported kernel type, defaulting to sing-box", "type", cfg.Kernel.Type)
		k = sing.New(cfg.Kernel)
	}

	l := limiter.New()
	st := limiter.NewSpeedTracker(l)

	return &Service{
		cfg:          cfg,
		source:       cp,
		sink:         cp,
		kernel:       k,
		tracker:      limiter.NewTracker(),
		limiter:      l,
		speedTracker: st,
		cert:         certMgr,
		wsEvents:     make(chan Event, 16),
		wsStatusCh:   make(chan StatusChange, 4),
		pullResults:  make(chan pullResult, 1),
	}
}

func (s *Service) Run(ctx context.Context) error {
	if err := s.cert.Start(ctx); err != nil {
		return fmt.Errorf("cert manager: %w", err)
	}
	defer s.cert.Stop()

	if err := s.initialSetup(ctx); err != nil {
		return fmt.Errorf("initial setup: %w", err)
	}
	defer s.kernel.Stop()

	trackTicker := time.NewTicker(trackInterval)
	reportTicker := time.NewTicker(pushPeriod(s.pushInterval))
	pullTicker := time.NewTicker(time.Duration(s.pullInterval) * time.Second)
	s.reportTicker, s.pullTicker = reportTicker, pullTicker
	deviceReportTicker := time.NewTicker(deviceReportInterval)

	wsDiscoveryTicker := time.NewTicker(wsDiscoveryInterval)

	defer trackTicker.Stop()
	defer reportTicker.Stop()
	defer pullTicker.Stop()
	defer deviceReportTicker.Stop()
	defer wsDiscoveryTicker.Stop()

	s.startWSClient(ctx)

	for {
		select {
		case <-ctx.Done():
			s.pushReportSync()
			return nil

		case <-trackTicker.C:
			s.trackAndEnforce(ctx)

		case <-reportTicker.C:
			s.pushReportAsync()

		case <-deviceReportTicker.C:
			s.reportDevices()

		case <-pullTicker.C:
			if s.wsClient != nil && s.wsClient.IsConnected() {
				continue
			}
			nlog.Core().Debug("polling from API (ws not connected)")
			s.pullViaAPIAsync(ctx)

		case result := <-s.pullResults:
			s.applyPullResult(ctx, result)

		case <-wsDiscoveryTicker.C:
			s.wsDiscovery(ctx)

		case status := <-s.wsStatusCh:
			s.handleWSStatus(ctx, status)

		case <-s.machineMailboxCh:
			s.drainMachineMailbox(ctx)

		case event := <-s.wsEvents:
			s.handleWSEvent(ctx, event)
		}
	}
}

func (s *Service) initialSetup(ctx context.Context) error {
	s.kernel.SetSpeedLimitFunc(s.speedTracker.GetLimiter)
	s.kernel.SetDeviceLimitFunc(s.limiter.GetDeviceLimitByUUID)

	bootstrap, err := s.source.Initial(ctx, s.wsMetrics, s.wsEvents, s.wsStatusCh)
	if err != nil {
		return err
	}

	s.applyIntervals(bootstrap.PushInterval, bootstrap.PullInterval)

	if bootstrap.Push != nil {
		s.wsClient = bootstrap.Push
	}
	s.machineMailbox = bootstrap.Mailbox
	if s.machineMailbox != nil {
		s.machineMailboxCh = s.machineMailbox.NotifyCh()
	}
	if bootstrap.Config == nil {
		if bootstrap.Push != nil {
			return nil
		}
		return fmt.Errorf("initial config is nil")
	}
	if err := validateNodeRuntime(s.cfg, s.kernel.Protocols(), bootstrap.Config, s.cert.TLSCert()); err != nil {
		return err
	}

	s.metricsMu.Lock()
	s.lastConfig = bootstrap.Config
	s.metricsMu.Unlock()
	s.lastConfigHash = computeConfigHash(bootstrap.Config)
	s.applyIntervals(bootstrap.Config.PushInterval, bootstrap.Config.PullInterval)
	bootstrap.Users = s.applyNodeLimits(bootstrap.Users)
	s.setUserState(bootstrap.Users)

	nlog.Core().Info("initial snapshot ready",
		"protocol", bootstrap.Config.Protocol,
		"port", bootstrap.Config.ServerPort,
		"users", len(bootstrap.Users),
	)

	if len(bootstrap.Users) == 0 {
		nlog.Core().Warn("no users, kernel will not start until users are available")
		s.markMailboxReadyAndDrain(ctx)
		return nil
	}

	s.applyRemoteOverrides(ctx, bootstrap.Config)
	if !s.startKernel(bootstrap.Config, bootstrap.Users) {
		return fmt.Errorf("start kernel")
	}
	s.markMailboxReadyAndDrain(ctx)
	return nil
}

func (s *Service) applyRemoteOverrides(ctx context.Context, nc *core.NodeSpec) bool {
	if nc == nil {
		return false
	}

	if nc.KernelLogLevel != "" && nc.KernelLogLevel != s.cfg.Kernel.LogLevel {
		nlog.Core().Info("cert: kernel log level override", "old", s.cfg.Kernel.LogLevel, "new", nc.KernelLogLevel)
		s.cfg.Kernel.LogLevel = nc.KernelLogLevel
	}

	if nc.CertConfig != nil {
		return s.applyNodeCert(ctx, nc.CertConfig)
	}

	if nc.AutoTLS != s.cfg.Cert.AutoTLS {
		nlog.Core().Info("cert: auto_tls policy changed (deprecated field)", "new", nc.AutoTLS)
		s.cfg.Cert.AutoTLS = nc.AutoTLS
	}
	if nc.Domain != "" && nc.Domain != s.cfg.Cert.Domain {
		s.cfg.Cert.Domain = nc.Domain
	}

	return false
}

func (s *Service) applyNodeCert(ctx context.Context, newCfg *conf.CertConfig) bool {
	if newCfg == nil {
		return false
	}
	cfgCopy := *newCfg
	cfgCopy.CertDir = s.cfg.Cert.CertDir
	if cfgCopy.ACMEStorageDir == "" {
		cfgCopy.ACMEStorageDir = s.cfg.Cert.ACMEStorageDir
	}

	changed, err := s.cert.Reconfigure(ctx, cfgCopy)
	if err != nil {
		nlog.Core().Error("failed to apply runtime cert config", "mode", cfgCopy.CertMode, "error", err)
		return false
	}
	s.cfg.Cert = cfgCopy
	if changed {
		msg := fmt.Sprintf("cert: material updated, has_cert=%v", s.cert.HasCert())
		if s.nodeLog != nil {
			s.nodeLog.Info(msg)
		} else {
			nlog.Core().Info(msg)
		}
	}
	return changed
}

// applyIntervals takes the panel's push/pull intervals (seconds, 0 = not
// sent) unless the local config pins them, and retimes the running tickers.
func (s *Service) applyIntervals(panelPush, panelPull int) {
	push := pickInterval(s.cfg.Node.PushInterval, panelPush, s.pushInterval)
	pull := pickInterval(s.cfg.Node.PullInterval, panelPull, s.pullInterval)
	if push == s.pushInterval && pull == s.pullInterval {
		return
	}
	if s.reportTicker != nil {
		nlog.Core().Info("panel intervals updated", "push", push, "pull", pull)
	}
	if s.reportTicker != nil && push != s.pushInterval {
		s.reportTicker.Reset(pushPeriod(push))
	}
	if s.pullTicker != nil && pull != s.pullInterval {
		s.pullTicker.Reset(time.Duration(pull) * time.Second)
	}
	s.pushInterval, s.pullInterval = push, pull
}

func pickInterval(local, panel, current int) int {
	switch {
	case local > 0:
		return local
	case panel > 0:
		return panel
	case current > 0:
		return current
	}
	return 60
}

func pushPeriod(seconds int) time.Duration {
	return time.Duration(max(seconds, 5)) * time.Second
}
