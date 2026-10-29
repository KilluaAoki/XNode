package xray

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	_ "unsafe"

	xrayDispatcher "github.com/xtls/xray-core/app/dispatcher"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/transport"
	"golang.org/x/time/rate"

	"github.com/KilluaAoki/XNode/common/nlog"
	"github.com/KilluaAoki/XNode/core"
)

//go:linkname typeCreatorRegistry github.com/xtls/xray-core/common.typeCreatorRegistry
var typeCreatorRegistry map[reflect.Type]common.ConfigCreator

var origDispatcherFactory common.ConfigCreator

var globalLimitDispatcher atomic.Pointer[LimitDispatcher]

func init() {
	configType := reflect.TypeOf((*xrayDispatcher.Config)(nil))
	origDispatcherFactory = typeCreatorRegistry[configType]
	typeCreatorRegistry[configType] = limitDispatcherFactory
}

func limitDispatcherFactory(ctx context.Context, config interface{}) (interface{}, error) {
	orig, err := origDispatcherFactory(ctx, config)
	if err != nil {
		return nil, err
	}
	inner, ok := orig.(routing.Dispatcher)
	if !ok {
		return orig, nil
	}
	ld := &LimitDispatcher{
		inner:     orig,
		innerDisp: inner,
	}
	globalLimitDispatcher.Store(ld)
	nlog.Core().Debug("xray: limit dispatcher installed")
	return ld, nil
}

type LimitDispatcher struct {
	inner     interface{}
	innerDisp routing.Dispatcher

	limits atomic.Pointer[limitState]

	// conns maps an email to its *userConns. Each user has its own lock so
	// new links of different users never contend.
	conns sync.Map

	gate atomic.Pointer[core.DeviceGate]

	connCount atomic.Int64
	total     atomic.Pointer[atomic.Int64]

	linksMu sync.Mutex
	links   map[string]map[*closeTrackingWriter]struct{}
}

// limitState is replaced as a whole on every user update and read without
// locking on the link path.
type limitState struct {
	emailToUID    map[string]int
	deviceLimits  map[string]int
	speedLimiters map[string]*rate.Limiter
}

var noLimits = &limitState{}

// userConns counts a user's open TCP links per source IP on this node.
type userConns struct {
	mu  sync.Mutex
	ips map[string]int
	// dead marks an entry dropped from LimitDispatcher.conns; a caller that
	// locked it after the drop must look the user up again.
	dead bool
}

func (d *LimitDispatcher) Dispatch(ctx context.Context, dest net.Destination) (*transport.Link, error) {
	email, sourceIP, isTCP, lim, err := d.identifyAndCheck(ctx, dest)
	if err != nil {
		return nil, err
	}

	link, err := d.innerDisp.Dispatch(ctx, dest)
	if err != nil {
		if email != "" && isTCP {
			d.delConn(email, sourceIP)
		}
		return nil, err
	}

	if email != "" {
		d.trackLink(link, email, sourceIP, isTCP, nil)
		if lim != nil {
			link = limitDispatchedLink(ctx, link, lim)
		}
	}
	return link, nil
}

func (d *LimitDispatcher) DispatchLink(ctx context.Context, dest net.Destination, link *transport.Link) error {
	email, sourceIP, isTCP, lim, err := d.identifyAndCheck(ctx, dest)
	if err != nil {
		return err
	}

	var tracked *closeTrackingWriter
	if email != "" {
		var cancel context.CancelFunc
		ctx, cancel = context.WithCancel(ctx)
		tracked = d.trackLink(link, email, sourceIP, isTCP, cancel)
		if lim != nil {
			limitInboundLink(link, lim)
		}
	}
	err = d.innerDisp.DispatchLink(ctx, dest, link)
	if err != nil && tracked != nil {
		tracked.finish()
	}
	return err
}

func (d *LimitDispatcher) identifyAndCheck(ctx context.Context, dest net.Destination) (email, sourceIP string, isTCP bool, lim *rate.Limiter, err error) {
	si := session.InboundFromContext(ctx)
	if si == nil || si.User == nil || len(si.User.Email) == 0 {
		return "", "", false, nil, nil
	}
	email = si.User.Email
	sourceIP = si.Source.Address.IP().String()
	isTCP = dest.Network == net.Network_TCP

	if d.revoked(email) {
		nlog.Core().Debug("xray: rejecting link of removed user", "email", email, "ip", sourceIP)
		return "", "", false, nil, errors.New("user removed: " + email)
	}
	if d.checkDeviceLimit(email, sourceIP, isTCP) {
		nlog.Core().Debug("xray: device limit exceeded", "email", email, "ip", sourceIP)
		return "", "", false, nil, errors.New("device limit exceeded for " + email)
	}
	if lim = d.speedLimiter(email); lim != nil {
		si.CanSpliceCopy = 3
	}
	return email, sourceIP, isTCP, lim, nil
}

func (d *LimitDispatcher) trackLink(link *transport.Link, email, sourceIP string, isTCP bool, cancel context.CancelFunc) *closeTrackingWriter {
	d.connCount.Add(1)
	if total := d.total.Load(); total != nil {
		total.Add(1)
	}

	reader := link.Reader
	w := &closeTrackingWriter{Writer: link.Writer}
	w.onClose = func() {
		d.removeLink(email, w)
		if cancel != nil {
			cancel()
		}
		if isTCP {
			d.delConn(email, sourceIP)
		}
		d.connCount.Add(-1)
	}
	w.kill = func() {
		if cancel != nil {
			cancel()
		}
		common.Interrupt(reader)
		w.Interrupt()
	}
	d.addLink(email, w)
	link.Writer = w
	return w
}

func (d *LimitDispatcher) addLink(email string, w *closeTrackingWriter) {
	d.linksMu.Lock()
	if d.links == nil {
		d.links = make(map[string]map[*closeTrackingWriter]struct{})
	}
	set := d.links[email]
	if set == nil {
		set = make(map[*closeTrackingWriter]struct{})
		d.links[email] = set
	}
	set[w] = struct{}{}
	d.linksMu.Unlock()
}

func (d *LimitDispatcher) removeLink(email string, w *closeTrackingWriter) {
	d.linksMu.Lock()
	if set := d.links[email]; set != nil {
		delete(set, w)
		if len(set) == 0 {
			delete(d.links, email)
		}
	}
	d.linksMu.Unlock()
}

func (d *LimitDispatcher) CloseUsers(emails []string) int {
	var victims []*closeTrackingWriter
	d.linksMu.Lock()
	for _, email := range emails {
		for w := range d.links[email] {
			victims = append(victims, w)
		}
		delete(d.links, email)
	}
	d.linksMu.Unlock()
	for _, w := range victims {
		w.kill()
	}
	return len(victims)
}

func (d *LimitDispatcher) Type() interface{} { return routing.DispatcherType() }

func (d *LimitDispatcher) Start() error {
	if s, ok := d.inner.(interface{ Start() error }); ok {
		return s.Start()
	}
	return nil
}

func (d *LimitDispatcher) Close() error {
	if c, ok := d.inner.(interface{ Close() error }); ok {
		return c.Close()
	}
	return nil
}

func (d *LimitDispatcher) UpdateLimits(emailToUID, deviceLimits map[string]int, speedLimiters map[string]*rate.Limiter) {
	d.limits.Store(&limitState{
		emailToUID:    emailToUID,
		deviceLimits:  deviceLimits,
		speedLimiters: speedLimiters,
	})
}

func (d *LimitDispatcher) state() *limitState {
	if st := d.limits.Load(); st != nil {
		return st
	}
	return noLimits
}

func (d *LimitDispatcher) revoked(email string) bool {
	if !strings.HasPrefix(email, "user@") {
		return false
	}
	st := d.state()
	if st.emailToUID == nil {
		return false
	}
	_, ok := st.emailToUID[email]
	return !ok
}

func (d *LimitDispatcher) speedLimiter(email string) *rate.Limiter {
	return d.state().speedLimiters[email]
}

func (d *LimitDispatcher) ResetConns() {
	d.conns.Range(func(key, value interface{}) bool {
		uc := value.(*userConns)
		uc.mu.Lock()
		uc.dead = true
		clear(uc.ips)
		d.conns.CompareAndDelete(key, uc)
		uc.mu.Unlock()
		return true
	})

	d.connCount.Store(0)
}

// GetConnectionState also drops users without open links. Doing it here
// rather than on every close keeps reconnecting users from reallocating
// their entry each time.
func (d *LimitDispatcher) GetConnectionState() (aliveIPs map[int]map[string]bool, connCount int) {
	aliveIPs = make(map[int]map[string]bool)
	emailToUID := d.state().emailToUID

	d.conns.Range(func(key, value interface{}) bool {
		email := key.(string)
		uc := value.(*userConns)
		uc.mu.Lock()
		if len(uc.ips) == 0 {
			uc.dead = true
			d.conns.CompareAndDelete(email, uc)
		} else if uid := emailToUID[email]; uid != 0 {
			set := aliveIPs[uid]
			if set == nil {
				set = make(map[string]bool, len(uc.ips))
				aliveIPs[uid] = set
			}
			for ip := range uc.ips {
				set[ip] = true
			}
		}
		uc.mu.Unlock()
		return true
	})

	connCount = int(d.connCount.Load())
	return
}

func (d *LimitDispatcher) SetDeviceGate(g *core.DeviceGate) {
	d.gate.Store(g)
}

// SetConnCounter sets the counter incremented for every accepted user link.
func (d *LimitDispatcher) SetConnCounter(c *atomic.Int64) {
	d.total.Store(c)
}

// checkDeviceLimit reports whether a link from sourceIP must be rejected.
// Accepted TCP links are counted until delConn; UDP links are only checked.
func (d *LimitDispatcher) checkDeviceLimit(email, sourceIP string, isTCP bool) bool {
	st := d.state()
	limit := st.deviceLimits[email]

	if !isTCP {
		if limit <= 0 {
			return false
		}
		uc := d.loadConns(email)
		if uc == nil {
			return !d.gate.Load().Allow(st.emailToUID[email], nil, sourceIP, limit)
		}
		uc.mu.Lock()
		allowed := d.gate.Load().Allow(st.emailToUID[email], uc.ips, sourceIP, limit)
		uc.mu.Unlock()
		return !allowed
	}

	for {
		uc := d.loadConns(email)
		if uc == nil {
			v, _ := d.conns.LoadOrStore(email, &userConns{ips: make(map[string]int)})
			uc = v.(*userConns)
		}
		uc.mu.Lock()
		if uc.dead {
			uc.mu.Unlock()
			continue
		}
		if limit > 0 && !d.gate.Load().Allow(st.emailToUID[email], uc.ips, sourceIP, limit) {
			uc.mu.Unlock()
			return true
		}
		uc.ips[sourceIP]++
		uc.mu.Unlock()
		return false
	}
}

func (d *LimitDispatcher) delConn(email, sourceIP string) {
	uc := d.loadConns(email)
	if uc == nil {
		return
	}
	uc.mu.Lock()
	if n := uc.ips[sourceIP] - 1; n > 0 {
		uc.ips[sourceIP] = n
	} else {
		delete(uc.ips, sourceIP)
	}
	uc.mu.Unlock()
}

func (d *LimitDispatcher) loadConns(email string) *userConns {
	if v, ok := d.conns.Load(email); ok {
		return v.(*userConns)
	}
	return nil
}

type closeTrackingWriter struct {
	buf.Writer
	onClose func()
	kill    func()
	closed  atomic.Bool
}

func (w *closeTrackingWriter) finish() {
	if w.closed.CompareAndSwap(false, true) && w.onClose != nil {
		w.onClose()
	}
}

func (w *closeTrackingWriter) Close() error {
	w.finish()
	return common.Close(w.Writer)
}

func (w *closeTrackingWriter) Interrupt() {
	w.finish()
	common.Interrupt(w.Writer)
}
