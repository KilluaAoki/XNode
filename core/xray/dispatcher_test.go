package xray

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/KilluaAoki/XNode/core"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/pipe"
	"golang.org/x/time/rate"
)

func newTestDispatcher() *LimitDispatcher {
	return &LimitDispatcher{
		limitedIPs: make(map[string]map[string]int),
	}
}

type nopReader struct{}

func (nopReader) ReadMultiBuffer() (buf.MultiBuffer, error) { return nil, nil }

func TestLimitDispatcher_DeviceLimitCheck(t *testing.T) {
	ld := newTestDispatcher()

	users := []core.UserSpec{
		{ID: 1, UUID: "uuid-1", DeviceLimit: 2, SpeedLimit: 0},
		{ID: 2, UUID: "uuid-2", DeviceLimit: 0, SpeedLimit: 10},
	}

	emailToUID := make(map[string]int)
	deviceLimits := make(map[string]int)
	speedLimits := make(map[string]*rate.Limiter)
	for _, u := range users {
		email := userEmail(u.ID)
		emailToUID[email] = u.ID
		if u.DeviceLimit > 0 {
			deviceLimits[email] = u.DeviceLimit
		}
		if u.SpeedLimit > 0 {
			speedLimits[email] = rate.NewLimiter(rate.Limit(u.SpeedLimit), u.SpeedLimit)
		}
	}
	ld.UpdateLimits(emailToUID, deviceLimits, speedLimits)

	email1 := userEmail(1)

	if ld.checkDeviceLimit(email1, "1.1.1.1", true) {
		t.Error("first IP should be allowed")
	}

	if ld.checkDeviceLimit(email1, "2.2.2.2", true) {
		t.Error("second IP should be allowed")
	}

	if !ld.checkDeviceLimit(email1, "3.3.3.3", true) {
		t.Error("third IP should be rejected (limit=2)")
	}

	if ld.checkDeviceLimit(email1, "1.1.1.1", true) {
		t.Error("same IP should always be allowed")
	}

	email2 := userEmail(2)
	for i := 0; i < 10; i++ {
		ip := "10.0.0." + string(rune('0'+i))
		if ld.checkDeviceLimit(email2, ip, true) {
			t.Errorf("user with no device limit should always be allowed (ip=%s)", ip)
		}
	}
}

func TestLimitDispatcher_DelConn(t *testing.T) {
	ld := newTestDispatcher()

	email := userEmail(1)
	deviceLimits := map[string]int{email: 2}
	ld.UpdateLimits(map[string]int{email: 1}, deviceLimits, nil)

	ld.checkDeviceLimit(email, "1.1.1.1", true)
	ld.checkDeviceLimit(email, "2.2.2.2", true)

	if !ld.checkDeviceLimit(email, "3.3.3.3", true) {
		t.Error("third IP should be rejected")
	}

	ld.delConn(email, "1.1.1.1")

	if ld.checkDeviceLimit(email, "3.3.3.3", true) {
		t.Error("after deleting one IP, new IP should be allowed")
	}
}

func TestLimitDispatcher_GetConnectionState(t *testing.T) {
	ld := newTestDispatcher()

	email1 := userEmail(1)
	email2 := userEmail(2)
	ld.UpdateLimits(map[string]int{email1: 1, email2: 2}, nil, nil)

	ic1 := &ipCounter{}
	r1 := &atomic.Int64{}
	r1.Store(1)
	ic1.ips.Store("1.1.1.1", r1)
	r2 := &atomic.Int64{}
	r2.Store(1)
	ic1.ips.Store("2.2.2.2", r2)
	ld.unlimitedIPs.Store(email1, ic1)

	ic2 := &ipCounter{}
	r3 := &atomic.Int64{}
	r3.Store(1)
	ic2.ips.Store("3.3.3.3", r3)
	ld.unlimitedIPs.Store(email2, ic2)

	ld.connCount.Store(5)

	aliveIPs, connCount := ld.GetConnectionState()

	if connCount != 5 {
		t.Errorf("expected connCount=5, got %d", connCount)
	}
	if len(aliveIPs[1]) != 2 {
		t.Errorf("user 1 IPs: got %d, want 2", len(aliveIPs[1]))
	}
	if len(aliveIPs[2]) != 1 {
		t.Errorf("user 2 IPs: got %d, want 1", len(aliveIPs[2]))
	}
}

func TestLimitDispatcher_ResetConns(t *testing.T) {
	ld := newTestDispatcher()

	ld.mu.Lock()
	ld.limitedIPs["user@1"] = map[string]int{"1.1.1.1": 1}
	ld.mu.Unlock()
	ld.connCount.Store(3)

	ld.ResetConns()

	ld.mu.RLock()
	ipCount := len(ld.limitedIPs)
	ld.mu.RUnlock()
	if ipCount != 0 {
		t.Error("limitedIPs should be empty after reset")
	}

	if ld.connCount.Load() != 0 {
		t.Error("connCount should be 0 after reset")
	}
}

func TestLimitDispatcher_UnlimitedUserFastPath(t *testing.T) {
	ld := newTestDispatcher()

	email := userEmail(1)
	ld.UpdateLimits(map[string]int{email: 1}, nil, nil)

	for i := 0; i < 100; i++ {
		ip := "10.0.0." + string(rune('0'+i%10))
		if ld.checkDeviceLimit(email, ip, true) {
			t.Errorf("unlimited user should always be allowed (ip=%s)", ip)
		}
	}

	v, ok := ld.unlimitedIPs.Load(email)
	if !ok {
		t.Error("unlimited user should have entry in unlimitedIPs")
	}
	ic := v.(*ipCounter)
	ips := ic.aliveIPs()
	if len(ips) == 0 {
		t.Error("should have tracked some IPs")
	}
}

func TestLimitDispatcher_TrackLinkPreservesReader(t *testing.T) {
	ld := newTestDispatcher()
	email := userEmail(1)
	ld.UpdateLimits(map[string]int{email: 1}, map[string]int{email: 1}, nil)

	origReader := nopReader{}
	origWriter := &closeTrackingWriter{Writer: buf.Discard, onClose: func() {}}
	link := &transport.Link{Reader: origReader, Writer: origWriter}

	ld.trackLink(link, email, "1.1.1.1", true, nil)

	if link.Reader != origReader {
		t.Fatal("trackLink must not replace link.Reader")
	}
	if link.Writer == origWriter {
		t.Fatal("trackLink should wrap link.Writer for lifecycle callbacks")
	}
}

func TestLimitDispatcher_CloseTrackingWriterReleasesConn(t *testing.T) {
	ld := newTestDispatcher()
	email := userEmail(1)
	ld.UpdateLimits(map[string]int{email: 1}, map[string]int{email: 1}, nil)
	if ld.checkDeviceLimit(email, "1.1.1.1", true) {
		t.Fatal("first connection should be allowed")
	}

	link := &transport.Link{Reader: nopReader{}, Writer: buf.Discard}
	ld.trackLink(link, email, "1.1.1.1", true, nil)

	if got := ld.connCount.Load(); got != 1 {
		t.Fatalf("expected connCount=1 after tracking, got %d", got)
	}
	cw, ok := link.Writer.(*closeTrackingWriter)
	if !ok {
		t.Fatal("expected closeTrackingWriter wrapper")
	}
	if err := cw.Close(); err != nil {
		t.Fatalf("closeTrackingWriter.Close() error = %v", err)
	}
	if got := ld.connCount.Load(); got != 0 {
		t.Fatalf("expected connCount=0 after close, got %d", got)
	}
	if ld.checkDeviceLimit(email, "2.2.2.2", true) {
		t.Fatal("device slot should be released after writer close")
	}
}

func TestLimitDispatcher_CloseUsersInterruptsLinks(t *testing.T) {
	ld := newTestDispatcher()
	email := userEmail(1)
	other := userEmail(2)
	ld.UpdateLimits(map[string]int{email: 1, other: 2}, nil, nil)

	upR, upW := pipe.New()
	downR, downW := pipe.New()
	cancelled := false
	link := &transport.Link{Reader: downR, Writer: upW}
	ld.trackLink(link, email, "1.1.1.1", true, func() { cancelled = true })

	keep := &transport.Link{Reader: nopReader{}, Writer: buf.Discard}
	ld.trackLink(keep, other, "2.2.2.2", true, nil)

	if n := ld.CloseUsers([]string{email}); n != 1 {
		t.Fatalf("CloseUsers() = %d, want 1", n)
	}
	if !cancelled {
		t.Fatal("expected context cancel on close")
	}
	if _, err := upR.ReadMultiBuffer(); err == nil {
		t.Fatal("expected uplink pipe to be interrupted")
	}
	b := buf.New()
	b.WriteString("x")
	if err := downW.WriteMultiBuffer(buf.MultiBuffer{b}); err == nil {
		t.Fatal("expected downlink pipe to be interrupted")
	}
	if got := ld.connCount.Load(); got != 1 {
		t.Fatalf("connCount = %d, want 1", got)
	}
	if n := ld.CloseUsers([]string{email}); n != 0 {
		t.Fatalf("second CloseUsers() = %d, want 0", n)
	}
	if err := common.Close(keep.Writer); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if len(ld.links) != 0 {
		t.Fatalf("links not released: %v", ld.links)
	}
}

type blockingDispatcher struct{}

func (blockingDispatcher) Type() interface{} { return nil }
func (blockingDispatcher) Start() error      { return nil }
func (blockingDispatcher) Close() error      { return nil }
func (blockingDispatcher) Dispatch(context.Context, net.Destination) (*transport.Link, error) {
	return nil, nil
}
func (blockingDispatcher) DispatchLink(ctx context.Context, _ net.Destination, link *transport.Link) error {
	<-ctx.Done()
	common.Close(link.Writer)
	return nil
}

func TestLimitDispatcher_CloseUsersCancelsDispatchLink(t *testing.T) {
	ld := newTestDispatcher()
	ld.innerDisp = blockingDispatcher{}
	email := userEmail(1)
	ld.UpdateLimits(map[string]int{email: 1}, nil, nil)

	ctx := session.ContextWithInbound(context.Background(), &session.Inbound{
		User:   &protocol.MemoryUser{Email: email},
		Source: net.TCPDestination(net.ParseAddress("1.1.1.1"), 1234),
	})
	done := make(chan error, 1)
	go func() {
		done <- ld.DispatchLink(ctx, net.TCPDestination(net.ParseAddress("8.8.8.8"), 443), &transport.Link{Reader: nopReader{}, Writer: buf.Discard})
	}()

	deadline := time.After(2 * time.Second)
	for ld.connCount.Load() == 0 {
		select {
		case <-deadline:
			t.Fatal("link was never tracked")
		default:
			time.Sleep(time.Millisecond)
		}
	}
	if n := ld.CloseUsers([]string{email}); n != 1 {
		t.Fatalf("CloseUsers() = %d, want 1", n)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("DispatchLink() error = %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("DispatchLink did not return after CloseUsers")
	}
	if got := ld.connCount.Load(); got != 0 {
		t.Fatalf("connCount = %d, want 0", got)
	}
}

func TestLimitDispatcher_RejectsRemovedUsers(t *testing.T) {
	ld := newTestDispatcher()
	dest := net.TCPDestination(net.ParseAddress("8.8.8.8"), 443)
	check := func(email string) error {
		ctx := session.ContextWithInbound(context.Background(), &session.Inbound{
			User:   &protocol.MemoryUser{Email: email},
			Source: net.TCPDestination(net.ParseAddress("1.1.1.1"), 1234),
		})
		_, _, _, _, err := ld.identifyAndCheck(ctx, dest)
		return err
	}

	if err := check(userEmail(1)); err != nil {
		t.Fatalf("before limits are known: %v", err)
	}
	ld.UpdateLimits(map[string]int{userEmail(1): 1, userEmail(2): 2}, nil, nil)
	if err := check(userEmail(1)); err != nil {
		t.Fatalf("current user rejected: %v", err)
	}
	ld.UpdateLimits(map[string]int{userEmail(2): 2}, nil, nil)
	if err := check(userEmail(1)); err == nil {
		t.Fatal("removed user still admitted")
	}
	if err := check(userEmail(2)); err != nil {
		t.Fatalf("remaining user rejected: %v", err)
	}
	if err := check("custom@example.com"); err != nil {
		t.Fatalf("unmanaged email rejected: %v", err)
	}
}

func TestLimitDispatcher_DeviceLimitRemoteCounts(t *testing.T) {
	ld := newTestDispatcher()
	email := userEmail(1)
	ld.UpdateLimits(map[string]int{email: 1}, map[string]int{email: 2}, nil)
	gate := core.NewDeviceGate()
	gate.UpdateRemoteCounts(map[int]int{1: 1})
	ld.SetDeviceGate(gate)

	if ld.checkDeviceLimit(email, "1.1.1.1", true) {
		t.Fatal("first local IP should be allowed with one remote device")
	}
	if !ld.checkDeviceLimit(email, "2.2.2.2", true) {
		t.Fatal("second local IP should be rejected: 1 local + 1 remote fills the limit")
	}
	if ld.checkDeviceLimit(email, "1.1.1.1", true) {
		t.Fatal("existing IP should stay allowed")
	}

	gate.UpdateGlobalIPs(map[int][]string{1: {"1.1.1.1"}})
	if ld.checkDeviceLimit(email, "2.2.2.2", true) {
		t.Fatal("fresh global snapshot without other devices should allow a second IP")
	}
}

func TestLimitDispatcher_TotalConnections(t *testing.T) {
	ld := newTestDispatcher()
	email := userEmail(1)
	ld.UpdateLimits(map[string]int{email: 1}, nil, nil)
	var total atomic.Int64
	ld.SetConnCounter(&total)

	for i := 0; i < 3; i++ {
		w := ld.trackLink(&transport.Link{Reader: nopReader{}, Writer: buf.Discard}, email, "1.1.1.1", true, nil)
		w.finish()
	}
	if total.Load() != 3 {
		t.Errorf("total = %d, want 3", total.Load())
	}
	if ld.connCount.Load() != 0 {
		t.Errorf("active = %d, want 0", ld.connCount.Load())
	}
}
