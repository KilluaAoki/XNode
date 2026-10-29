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
		inner:      orig,
		innerDisp:  inner,
		limitedIPs: make(map[string]map[string]int),
	}
	globalLimitDispatcher.Store(ld)
	nlog.Core().Debug("xray: limit dispatcher installed")
	return ld, nil
}

type LimitDispatcher struct {
	inner     interface{}
	innerDisp routing.Dispatcher

	mu            sync.RWMutex
	limitedIPs    map[string]map[string]int
	deviceLimits  map[string]int
	emailToUID    map[string]int
	speedLimiters map[string]*rate.Limiter

	unlimitedIPs sync.Map

	gate atomic.Pointer[core.DeviceGate]

	connCount atomic.Int64
	total     atomic.Pointer[atomic.Int64]

	linksMu sync.Mutex
	links   map[string]map[*closeTrackingWriter]struct{}
}

type ipCounter struct {
	ips sync.Map
}

func (ic *ipCounter) aliveIPs() map[string]bool {
	result := make(map[string]bool)
	ic.ips.Range(func(key, _ interface{}) bool {
		if rv, ok := ic.ips.Load(key); ok && rv.(*atomic.Int64).Load() > 0 {
			result[key.(string)] = true
		}
		return true
	})
	return result
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
	d.mu.Lock()
	d.emailToUID = emailToUID
	d.deviceLimits = deviceLimits
	d.speedLimiters = speedLimiters
	d.mu.Unlock()
}

func (d *LimitDispatcher) revoked(email string) bool {
	if !strings.HasPrefix(email, "user@") {
		return false
	}
	d.mu.RLock()
	defer d.mu.RUnlock()
	if d.emailToUID == nil {
		return false
	}
	_, ok := d.emailToUID[email]
	return !ok
}

func (d *LimitDispatcher) speedLimiter(email string) *rate.Limiter {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.speedLimiters[email]
}

func (d *LimitDispatcher) ResetConns() {
	d.mu.Lock()
	d.limitedIPs = make(map[string]map[string]int)
	d.mu.Unlock()

	d.unlimitedIPs.Range(func(key, _ interface{}) bool {
		d.unlimitedIPs.Delete(key)
		return true
	})

	d.connCount.Store(0)
}

func (d *LimitDispatcher) GetConnectionState() (aliveIPs map[int]map[string]bool, connCount int) {
	aliveIPs = make(map[int]map[string]bool)

	// limitedIPs is mutated in place by checkDeviceLimit and delConn, so it
	// must be read under the lock.
	d.mu.RLock()
	emailToUID := d.emailToUID
	for email, ipsMap := range d.limitedIPs {
		uid := emailToUID[email]
		if uid == 0 {
			continue
		}
		ipSet := make(map[string]bool, len(ipsMap))
		for ip := range ipsMap {
			ipSet[ip] = true
		}
		if len(ipSet) > 0 {
			aliveIPs[uid] = ipSet
		}
	}
	d.mu.RUnlock()

	d.unlimitedIPs.Range(func(key, value interface{}) bool {
		email := key.(string)
		uid := emailToUID[email]
		if uid == 0 {
			return true
		}
		ic := value.(*ipCounter)
		if ips := ic.aliveIPs(); len(ips) > 0 {
			if existing, ok := aliveIPs[uid]; ok {
				for ip := range ips {
					existing[ip] = true
				}
			} else {
				aliveIPs[uid] = ips
			}
		}
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
// Accepted TCP links are counted until delConn.
func (d *LimitDispatcher) checkDeviceLimit(email, sourceIP string, isTCP bool) bool {
	d.mu.RLock()
	limit, hasLimit := d.deviceLimits[email]
	uid := d.emailToUID[email]
	d.mu.RUnlock()

	if !hasLimit || limit <= 0 {
		if isTCP {
			v, _ := d.unlimitedIPs.LoadOrStore(email, &ipCounter{})
			ic := v.(*ipCounter)

			rv, _ := ic.ips.LoadOrStore(sourceIP, &atomic.Int64{})
			rv.(*atomic.Int64).Add(1)
		}
		return false
	}

	d.mu.Lock()
	defer d.mu.Unlock()
	ips := d.limitedIPs[email]
	if !d.gate.Load().Allow(uid, ips, sourceIP, limit) {
		return true
	}
	if isTCP {
		if ips == nil {
			ips = make(map[string]int)
			d.limitedIPs[email] = ips
		}
		ips[sourceIP]++
	}
	return false
}

func (d *LimitDispatcher) delConn(email, sourceIP string) {
	if v, ok := d.unlimitedIPs.Load(email); ok {
		ic := v.(*ipCounter)
		if rv, ok := ic.ips.Load(sourceIP); ok {
			counter := rv.(*atomic.Int64)
			if counter.Add(-1) <= 0 {
				ic.ips.Delete(sourceIP)
			}
		}
		return
	}

	d.mu.Lock()
	defer d.mu.Unlock()
	if ips, ok := d.limitedIPs[email]; ok {
		ips[sourceIP]--
		if ips[sourceIP] <= 0 {
			delete(ips, sourceIP)
		}
		if len(ips) == 0 {
			delete(d.limitedIPs, email)
		}
	}
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
