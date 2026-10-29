package limiter

import (
	"testing"
	"time"
)

func hasTraffic(t *Tracker) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.pendingTraffic) > 0
}

func TestProcess_InitialTraffic(t *testing.T) {
	tr := NewTracker()
	cumTraffic := map[int][2]int64{
		1: {100, 200},
		2: {50, 80},
	}
	aliveIPs := map[int]map[string]bool{
		1: {"1.1.1.1": true},
		2: {"2.2.2.2": true},
	}
	tr.Process(cumTraffic, aliveIPs, 2)

	flushed := tr.FlushTraffic(0)
	if flushed[1] != [2]int64{100, 200} {
		t.Errorf("user 1 traffic: got %v", flushed[1])
	}
	if flushed[2] != [2]int64{50, 80} {
		t.Errorf("user 2 traffic: got %v", flushed[2])
	}
}

func TestProcess_DeltaCalculation(t *testing.T) {
	tr := NewTracker()

	tr.Process(map[int][2]int64{1: {100, 200}}, nil, 1)

	tr.Process(map[int][2]int64{1: {300, 500}}, nil, 1)

	flushed := tr.FlushTraffic(0)
	if flushed[1] != [2]int64{300, 500} {
		t.Errorf("accumulated: got %v, want [300,500]", flushed[1])
	}
}

func TestProcess_CounterReset(t *testing.T) {
	tr := NewTracker()

	tr.Process(map[int][2]int64{1: {1000, 2000}}, nil, 1)
	tr.FlushTraffic(0)

	tr.Process(map[int][2]int64{1: {50, 80}}, nil, 1)

	flushed := tr.FlushTraffic(0)
	if flushed[1] != [2]int64{50, 80} {
		t.Errorf("counter reset: got %v, want [50,80]", flushed[1])
	}
}

func TestProcess_UserDisappears(t *testing.T) {
	tr := NewTracker()

	tr.Process(map[int][2]int64{1: {100, 200}}, nil, 1)

	tr.Process(map[int][2]int64{}, nil, 0)

	tr.Process(map[int][2]int64{1: {50, 30}}, nil, 1)

	flushed := tr.FlushTraffic(0)
	if flushed[1] != [2]int64{150, 230} {
		t.Errorf("after disappear: got %v, want [150,230]", flushed[1])
	}
}

func TestProcess_ZeroTraffic(t *testing.T) {
	tr := NewTracker()
	tr.Process(map[int][2]int64{}, nil, 0)

	if hasTraffic(tr) {
		t.Error("expected no traffic for empty input")
	}
}

func TestFlushTraffic(t *testing.T) {
	tr := NewTracker()
	tr.Process(map[int][2]int64{
		1: {100, 200},
		2: {50, 80},
	}, nil, 2)

	flushed := tr.FlushTraffic(0)
	if flushed[1] != [2]int64{100, 200} {
		t.Errorf("flushed user 1: got %v", flushed[1])
	}
	if flushed[2] != [2]int64{50, 80} {
		t.Errorf("flushed user 2: got %v", flushed[2])
	}

	if hasTraffic(tr) {
		t.Error("expected no traffic after flush")
	}
	flushed2 := tr.FlushTraffic(0)
	if len(flushed2) != 0 {
		t.Errorf("expected empty after second flush, got %v", flushed2)
	}
}

func TestRestoreTraffic(t *testing.T) {
	tr := NewTracker()
	tr.Process(map[int][2]int64{1: {100, 200}}, nil, 1)

	flushed := tr.FlushTraffic(0)
	tr.RestoreTraffic(flushed)

	if !hasTraffic(tr) {
		t.Error("expected traffic after restore")
	}

	restored := tr.FlushTraffic(0)
	if restored[1] != [2]int64{100, 200} {
		t.Errorf("restored: got %v", restored[1])
	}
}

func TestRestoreTraffic_Additive(t *testing.T) {
	tr := NewTracker()

	tr.Process(map[int][2]int64{1: {100, 200}}, nil, 1)
	tr.Process(map[int][2]int64{1: {200, 400}}, nil, 1)

	first := tr.FlushTraffic(0)
	tr.RestoreTraffic(first)

	tr.Process(map[int][2]int64{1: {250, 500}}, nil, 1)

	final := tr.FlushTraffic(0)
	if final[1][0] != 250 || final[1][1] != 500 {
		t.Errorf("additive restore: got %v", final[1])
	}
}

func TestAliveIPs(t *testing.T) {
	tr := NewTracker()
	aliveIPs := map[int]map[string]bool{
		1: {"1.1.1.1": true, "2.2.2.2": true},
		2: {"3.3.3.3": true},
	}
	tr.Process(map[int][2]int64{1: {100, 200}, 2: {30, 40}}, aliveIPs, 3)

	flushed := tr.AliveIPs()
	if len(flushed[1]) != 2 {
		t.Errorf("user 1 IPs: got %d, want 2", len(flushed[1]))
	}
	if len(flushed[2]) != 1 {
		t.Errorf("user 2 IPs: got %d, want 1", len(flushed[2]))
	}

	flushed[1][0] = "mutated"
	again := tr.AliveIPs()
	if len(again[1]) != 2 || again[1][0] != "1.1.1.1" || again[1][1] != "2.2.2.2" {
		t.Errorf("unchanged snapshot must be returned again as a fresh copy, got %v", again)
	}

	tr.Process(nil, map[int]map[string]bool{}, 0)
	if empty := tr.AliveIPs(); empty == nil || len(empty) != 0 {
		t.Errorf("expected empty non-nil map after users go offline, got %v", empty)
	}
}

func TestAliveIPs_DedupSameIP(t *testing.T) {
	tr := NewTracker()
	aliveIPs := map[int]map[string]bool{
		1: {"1.1.1.1": true},
	}
	tr.Process(map[int][2]int64{1: {100, 200}}, aliveIPs, 2)

	flushed := tr.AliveIPs()
	if len(flushed[1]) != 1 {
		t.Errorf("expected 1 IP, got %d", len(flushed[1]))
	}
}

func TestHasTraffic(t *testing.T) {
	tr := NewTracker()
	if hasTraffic(tr) {
		t.Error("new tracker should not have traffic")
	}

	tr.Process(map[int][2]int64{1: {100, 200}}, nil, 1)
	if !hasTraffic(tr) {
		t.Error("should have traffic after process")
	}

	tr.FlushTraffic(0)
	if hasTraffic(tr) {
		t.Error("should not have traffic after flush")
	}
}

func TestProcess_NoTrafficDelta(t *testing.T) {
	tr := NewTracker()

	tr.Process(map[int][2]int64{1: {100, 200}}, nil, 1)
	tr.FlushTraffic(0)

	tr.Process(map[int][2]int64{1: {100, 200}}, nil, 1)
	if hasTraffic(tr) {
		t.Error("expected no traffic for zero delta")
	}
}

func TestTrafficAccumulation(t *testing.T) {
	tr := NewTracker()

	tr.Process(map[int][2]int64{1: {100, 200}}, nil, 1)
	tr.Process(map[int][2]int64{1: {300, 500}}, nil, 1)
	tr.Process(map[int][2]int64{1: {350, 600}}, nil, 1)

	flushed := tr.FlushTraffic(0)
	if flushed[1] != [2]int64{350, 600} {
		t.Errorf("accumulated: got %v, want [350,600]", flushed[1])
	}
}

func TestFlushTrafficMinBytesKeepsSmallUsers(t *testing.T) {
	tr := NewTracker()
	tr.Process(map[int][2]int64{1: {600, 600}, 2: {10, 10}}, nil, 0)

	flushed := tr.FlushTraffic(1024)
	if len(flushed) != 1 || flushed[1] != [2]int64{600, 600} {
		t.Fatalf("flushed = %v", flushed)
	}

	tr.Process(map[int][2]int64{1: {600, 600}, 2: {700, 400}}, nil, 0)
	flushed = tr.FlushTraffic(1024)
	if len(flushed) != 1 || flushed[2] != [2]int64{700, 400} {
		t.Fatalf("accumulated flush = %v", flushed)
	}
	if hasTraffic(tr) {
		t.Fatal("expected no pending traffic")
	}
}

func TestTracker_ActiveAliveIPs(t *testing.T) {
	tr := NewTracker()
	alive := map[int]map[string]bool{
		1: {"1.1.1.1": true},
		2: {"2.2.2.2": true},
		3: {"3.3.3.3": true},
	}
	tr.Process(map[int][2]int64{1: {600, 600}, 2: {10, 10}}, alive, 3)

	if got := tr.ActiveAliveIPs(0); len(got) != 3 {
		t.Fatalf("no threshold: got %v", got)
	}
	got := tr.ActiveAliveIPs(1000)
	if len(got) != 1 || len(got[1]) != 1 {
		t.Fatalf("threshold 1000: got %v", got)
	}

	// The previous window still counts after one rotation.
	tr.RotateActivity()
	tr.Process(map[int][2]int64{1: {600, 600}, 2: {500, 500}}, alive, 3)
	if got := tr.ActiveAliveIPs(1000); len(got) != 2 || got[3] != nil {
		t.Fatalf("after rotation: got %v", got)
	}

	tr.RotateActivity()
	tr.RotateActivity()
	if got := tr.ActiveAliveIPs(1); len(got) != 0 {
		t.Fatalf("idle windows: got %v", got)
	}
}

func TestTracker_SpeedUsesElapsedTime(t *testing.T) {
	tr := NewTracker()
	now := time.Unix(1000, 0)
	tr.now = func() time.Time { return now }

	tr.Process(map[int][2]int64{1: {100, 200}}, nil, 0)
	if tr.InboundSpeed() != 0 || tr.OutboundSpeed() != 0 {
		t.Fatalf("first cycle has no baseline, got in=%d out=%d", tr.InboundSpeed(), tr.OutboundSpeed())
	}

	now = now.Add(5 * time.Second)
	tr.Process(map[int][2]int64{1: {1100, 10200}}, nil, 0)
	if got := tr.OutboundSpeed(); got != 200 {
		t.Errorf("outbound speed = %d, want 200", got)
	}
	if got := tr.InboundSpeed(); got != 2000 {
		t.Errorf("inbound speed = %d, want 2000", got)
	}
}
