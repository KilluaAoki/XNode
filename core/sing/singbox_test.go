package sing

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/KilluaAoki/XNode/conf"
	"github.com/KilluaAoki/XNode/core"
	"github.com/sagernet/sing-box/adapter"
	singM "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"golang.org/x/time/rate"
)

func TestSingBoxProtocols(t *testing.T) {
	s := New(conf.KernelConfig{Type: "sing-box"})
	protocols := s.Protocols()
	found := false
	for _, protocol := range protocols {
		if protocol == "hysteria" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("Protocols() missing hysteria: %v", protocols)
	}
}

type testConn struct {
	closed bool
	reads  [][]byte
	writes [][]byte
}

func (c *testConn) Read(b []byte) (int, error) {
	if len(c.reads) == 0 {
		return 0, errors.New("eof")
	}
	chunk := c.reads[0]
	c.reads = c.reads[1:]
	n := copy(b, chunk)
	return n, nil
}

func (c *testConn) Write(b []byte) (int, error) {
	cp := append([]byte(nil), b...)
	c.writes = append(c.writes, cp)
	return len(b), nil
}

func (c *testConn) Close() error                     { c.closed = true; return nil }
func (c *testConn) LocalAddr() net.Addr              { return &net.TCPAddr{} }
func (c *testConn) RemoteAddr() net.Addr             { return &net.TCPAddr{} }
func (c *testConn) SetDeadline(time.Time) error      { return nil }
func (c *testConn) SetReadDeadline(time.Time) error  { return nil }
func (c *testConn) SetWriteDeadline(time.Time) error { return nil }

func testInboundContext(uuid, ip string) adapter.InboundContext {
	return adapter.InboundContext{
		User:   uuid,
		Source: singM.Socksaddr{Addr: netip.MustParseAddr(ip)},
	}
}

func TestConnTrackerRoutedConnectionTracksTrafficAndAliveIPs(t *testing.T) {
	tracker := NewConnTracker(0)
	tracker.SetUserMap(map[string]int{"uuid-1": 1})
	base := &testConn{reads: [][]byte{[]byte("hello")}}

	wrapped := tracker.RoutedConnection(context.Background(), base, testInboundContext("uuid-1", "1.1.1.1"), nil, nil)

	buf := make([]byte, 16)
	n, err := wrapped.Read(buf)
	if err != nil {
		t.Fatalf("Read() error = %v", err)
	}
	if n != 5 {
		t.Fatalf("Read() bytes = %d, want 5", n)
	}
	if _, err := wrapped.Write([]byte("bye")); err != nil {
		t.Fatalf("Write() error = %v", err)
	}

	traffic, aliveIPs, connCount := tracker.GetUserTraffic()
	if got := traffic[1]; got != [2]int64{5, 3} {
		t.Fatalf("traffic[1] = %v, want [5 3]", got)
	}
	if !aliveIPs[1]["1.1.1.1"] {
		t.Fatal("expected alive IP to include source address")
	}
	if connCount != 1 {
		t.Fatalf("connCount = %d, want 1", connCount)
	}

	if err := wrapped.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	_, aliveIPs, connCount = tracker.GetUserTraffic()
	if aliveIPs[1] != nil {
		t.Fatalf("aliveIPs after close = %v, want nil", aliveIPs[1])
	}
	if connCount != 0 {
		t.Fatalf("connCount after close = %d, want 0", connCount)
	}
}

func TestConnTrackerRoutedConnectionRejectsWhenDeviceLimitExceeded(t *testing.T) {
	tracker := NewConnTracker(0)
	tracker.SetUserMap(map[string]int{"uuid-1": 1})
	tracker.SetDeviceLimitFunc(func(uuid string) (int, bool) {
		if uuid != "uuid-1" {
			return 0, false
		}
		return 1, true
	})

	first := &testConn{}
	wrapped1 := tracker.RoutedConnection(context.Background(), first, testInboundContext("uuid-1", "1.1.1.1"), nil, nil)
	if wrapped1 == first {
		t.Fatal("expected first connection to be wrapped")
	}

	second := &testConn{}
	wrapped2 := tracker.RoutedConnection(context.Background(), second, testInboundContext("uuid-1", "2.2.2.2"), nil, nil)
	if wrapped2 != second {
		t.Fatal("expected rejected connection to be returned unwrapped")
	}
	if !second.closed {
		t.Fatal("expected rejected connection to be closed")
	}
}

func TestConnTrackerCheckDeviceGateMergesFreshGlobalDevices(t *testing.T) {
	tracker := NewConnTracker(0)
	tracker.SetUserMap(map[string]int{"uuid-1": 1})
	us := tracker.users[1]
	us.addConn("1.1.1.1")
	tracker.UpdateGlobalDevices(map[int][]string{1: {"9.9.9.9"}})

	if tracker.checkDeviceGate(us, 1, "2.2.2.2", 2) {
		t.Fatal("expected lexicographically earlier candidate to remain allowed")
	}
	if !tracker.checkDeviceGate(us, 1, "99.99.99.99", 2) {
		t.Fatal("expected merged local+global device state to reject lexicographically later third device")
	}
	if tracker.checkDeviceGate(us, 1, "1.1.1.1", 2) {
		t.Fatal("existing local IP should still be allowed")
	}
	if tracker.checkDeviceGate(us, 1, "9.9.9.9", 2) {
		t.Fatal("existing global IP should still be allowed")
	}
}

func TestConnTrackerCloseByUUIDClosesTrackedConnection(t *testing.T) {
	tracker := NewConnTracker(0)
	tracker.SetUserMap(map[string]int{"uuid-1": 1})
	base := &testConn{}
	wrapped := tracker.RoutedConnection(context.Background(), base, testInboundContext("uuid-1", "1.1.1.1"), nil, nil)
	if _, ok := wrapped.(*trackedConn); !ok {
		t.Fatalf("wrapped type = %T, want *trackedConn", wrapped)
	}
	if n := tracker.CloseByUUID("uuid-1"); n != 1 {
		t.Fatalf("CloseByUUID() = %d, want 1", n)
	}
	if !base.closed {
		t.Fatal("expected underlying connection to be closed")
	}
}

func TestConnTrackerRateLimitHonorsContextCancellation(t *testing.T) {
	tracker := NewConnTracker(0)
	tracker.SetUserMap(map[string]int{"uuid-1": 1})
	tracker.SetSpeedLimitFunc(func(uuid string) *rate.Limiter {
		if uuid != "uuid-1" {
			return nil
		}
		return rate.NewLimiter(rate.Limit(1), 1)
	})

	readCtx, cancelRead := context.WithCancel(context.Background())
	readBase := &testConn{reads: [][]byte{[]byte("a"), []byte("a")}}
	readTracked := tracker.RoutedConnection(readCtx, readBase, testInboundContext("uuid-1", "1.1.1.1"), nil, nil).(*trackedConn)
	buf := make([]byte, 8)
	if n, err := readTracked.Read(buf); err != nil || n != 1 {
		t.Fatalf("first Read() = (%d, %v), want (1, nil)", n, err)
	}
	cancelRead()
	if n, err := readTracked.Read(buf); !errors.Is(err, context.Canceled) || n != 1 {
		t.Fatalf("second Read() = (%d, %v), want (1, context canceled)", n, err)
	}

	writeCtx, cancelWrite := context.WithCancel(context.Background())
	writeBase := &testConn{}
	writeTracked := tracker.RoutedConnection(writeCtx, writeBase, testInboundContext("uuid-1", "1.1.1.2"), nil, nil).(*trackedConn)
	if n, err := writeTracked.Write([]byte("a")); err != nil || n != 1 {
		t.Fatalf("first Write() = (%d, %v), want (1, nil)", n, err)
	}
	cancelWrite()
	if n, err := writeTracked.Write([]byte("a")); !errors.Is(err, context.Canceled) || n != 0 {
		t.Fatalf("second Write() = (%d, %v), want (0, context canceled)", n, err)
	}
}

func TestConnTrackerCloseByUUIDClosesOnlyTargetUser(t *testing.T) {
	tracker := NewConnTracker(0)
	tracker.SetUserMap(map[string]int{"uuid-1": 1, "uuid-2": 2})
	a := &testConn{}
	b := &testConn{}
	c := &testConn{}
	tracker.RoutedConnection(context.Background(), a, testInboundContext("uuid-1", "1.1.1.1"), nil, nil)
	tracker.RoutedConnection(context.Background(), b, testInboundContext("uuid-1", "1.1.1.2"), nil, nil)
	tracker.RoutedConnection(context.Background(), c, testInboundContext("uuid-2", "2.2.2.2"), nil, nil)

	if n := tracker.CloseByUUID("uuid-1"); n != 2 {
		t.Fatalf("CloseByUUID() = %d, want 2", n)
	}
	if !a.closed || !b.closed {
		t.Fatal("expected target user connections to be closed")
	}
	if c.closed {
		t.Fatal("other user connection must stay open")
	}
	if got := tracker.ActiveCount(); got != 1 {
		t.Fatalf("ActiveCount() = %d, want 1", got)
	}
	if n := tracker.CloseByUUID("uuid-1"); n != 0 {
		t.Fatalf("second CloseByUUID() = %d, want 0", n)
	}
}

func TestConnTrackerResolvesNumericUserNames(t *testing.T) {
	tracker := NewConnTracker(0)
	tracker.SetUserMap(buildUserMap(reloadUsersPlain()))
	var limited string
	tracker.SetSpeedLimitFunc(func(uuid string) *rate.Limiter {
		limited = uuid
		return nil
	})
	conn := &testConn{reads: [][]byte{[]byte("hello")}}
	wrapped := tracker.RoutedConnection(context.Background(), conn, testInboundContext("7", "1.1.1.1"), nil, nil)
	buf := make([]byte, 16)
	if _, err := wrapped.Read(buf); err != nil {
		t.Fatal(err)
	}
	if limited != "uuid-7" {
		t.Fatalf("speed limit lookup used %q, want uuid-7", limited)
	}
	traffic, _, _ := tracker.GetUserTraffic()
	if traffic[7][0] != 5 {
		t.Fatalf("traffic[7] = %v, want upload 5", traffic[7])
	}
	if n := tracker.CloseByUUID("uuid-7"); n != 1 || !conn.closed {
		t.Fatalf("CloseByUUID() = %d, closed = %v", n, conn.closed)
	}
}

type testPacketConn struct {
	N.PacketConn
}

func TestTrackedPacketConnUnwrapCountsDirections(t *testing.T) {
	tracker := NewConnTracker(0)
	tracker.SetUserMap(map[string]int{"uuid-1": 1})
	wrapped := tracker.RoutedPacketConnection(context.Background(), &testPacketConn{}, testInboundContext("uuid-1", "1.1.1.1"), nil, nil)
	_, readCounters := wrapped.(interface {
		UnwrapPacketReader() (N.PacketReader, []N.CountFunc)
	}).UnwrapPacketReader()
	_, writeCounters := wrapped.(interface {
		UnwrapPacketWriter() (N.PacketWriter, []N.CountFunc)
	}).UnwrapPacketWriter()
	readCounters[0](10)
	writeCounters[0](3)
	traffic, _, _ := tracker.GetUserTraffic()
	if got := traffic[1]; got != [2]int64{10, 3} {
		t.Fatalf("traffic[1] = %v, want [10 3]", got)
	}
}

func reloadUsersPlain() []core.UserSpec {
	return []core.UserSpec{{ID: 7, UUID: "uuid-7"}}
}

func TestConnTrackerRejectsRemovedUsersOnManagedInbound(t *testing.T) {
	tracker := NewConnTracker(0)
	tracker.SetManagedInbound("vless-in")
	tracker.SetUserMap(map[string]int{"uuid-1": 1, "uuid-2": 2})

	route := func(user, inbound string) bool {
		md := testInboundContext(user, "1.1.1.1")
		md.Inbound = inbound
		conn := &testConn{}
		tracker.RoutedConnection(context.Background(), conn, md, nil, nil)
		return conn.closed
	}

	if route("uuid-1", "vless-in") {
		t.Fatal("current user rejected")
	}
	tracker.SetUserMap(map[string]int{"uuid-2": 2})
	if !route("uuid-1", "vless-in") {
		t.Fatal("removed user still admitted on managed inbound")
	}
	if route("uuid-2", "vless-in") {
		t.Fatal("remaining user rejected")
	}
	if route("uuid-1", "custom-in") {
		t.Fatal("unmanaged inbound must not be filtered")
	}
	if route("", "vless-in") {
		t.Fatal("anonymous connection on managed inbound must not be filtered")
	}
}
