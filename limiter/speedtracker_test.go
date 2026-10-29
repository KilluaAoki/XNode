package limiter

import (
	"testing"
	"time"

	"github.com/KilluaAoki/XNode/core"
)

func TestSpeedTracker_UpdateBuckets(t *testing.T) {
	l := New()
	st := NewSpeedTracker(l)

	users := []core.UserSpec{
		{ID: 1, UUID: "u1", SpeedLimit: 3, DeviceLimit: 0},
		{ID: 2, UUID: "u2", SpeedLimit: 0, DeviceLimit: 0},
		{ID: 3, UUID: "u3", SpeedLimit: 10, DeviceLimit: 2},
	}
	l.UpdateUsers(users)
	st.UpdateBuckets()

	b1 := st.GetLimiter("u1")
	if b1 == nil {
		t.Fatal("expected bucket for user 1")
	}
	expectedRate := float64(3 * 1000000 / 8)
	if float64(b1.Limit()) != expectedRate {
		t.Errorf("user 1 rate: got %v, want %v", float64(b1.Limit()), expectedRate)
	}
	expectedBurst := 3 * 1000000 / 8
	if b1.Burst() != expectedBurst {
		t.Errorf("user 1 burst: got %v, want %v", b1.Burst(), expectedBurst)
	}

	b2 := st.GetLimiter("u2")
	if b2 != nil {
		t.Fatal("expected no bucket for user 2")
	}

	b3 := st.GetLimiter("u3")
	if b3 == nil {
		t.Fatal("expected bucket for user 3")
	}
	expectedRate3 := float64(10 * 1000000 / 8)
	if float64(b3.Limit()) != expectedRate3 {
		t.Errorf("user 3 rate: got %v, want %v", float64(b3.Limit()), expectedRate3)
	}
	expectedBurst3 := 10 * 1000000 / 8
	if b3.Burst() != expectedBurst3 {
		t.Errorf("user 3 burst: got %v, want %v", b3.Burst(), expectedBurst3)
	}
}

func TestSpeedTracker_UpdateBuckets_PreservesExisting(t *testing.T) {
	l := New()
	st := NewSpeedTracker(l)

	users := []core.UserSpec{
		{ID: 1, UUID: "u1", SpeedLimit: 3, DeviceLimit: 0},
	}
	l.UpdateUsers(users)
	st.UpdateBuckets()

	b1 := st.GetLimiter("u1")
	if b1 == nil {
		t.Fatal("expected bucket for user 1")
	}

	users2 := []core.UserSpec{
		{ID: 1, UUID: "u1", SpeedLimit: 5, DeviceLimit: 0},
	}
	l.UpdateUsers(users2)
	st.UpdateBuckets()

	b1After := st.GetLimiter("u1")
	if b1After == nil {
		t.Fatal("expected bucket for user 1 after update")
	}
	if b1 != b1After {
		t.Error("expected same rate.Limiter instance to be reused")
	}

	expectedRate := float64(5 * 1000000 / 8)
	if float64(b1After.Limit()) != expectedRate {
		t.Errorf("user 1 updated rate: got %v, want %v", float64(b1After.Limit()), expectedRate)
	}
}

func TestSpeedTracker_UpdateBuckets_RemovesUsers(t *testing.T) {
	l := New()
	st := NewSpeedTracker(l)

	users := []core.UserSpec{
		{ID: 1, UUID: "u1", SpeedLimit: 3, DeviceLimit: 0},
		{ID: 2, UUID: "u2", SpeedLimit: 5, DeviceLimit: 0},
	}
	l.UpdateUsers(users)
	st.UpdateBuckets()

	if st.GetLimiter("u1") == nil || st.GetLimiter("u2") == nil {
		t.Fatal("expected buckets for both users")
	}

	users2 := []core.UserSpec{
		{ID: 1, UUID: "u1", SpeedLimit: 3, DeviceLimit: 0},
	}
	l.UpdateUsers(users2)
	st.UpdateBuckets()

	if st.GetLimiter("u1") == nil {
		t.Fatal("expected bucket for user 1")
	}
	if st.GetLimiter("u2") != nil {
		t.Error("expected no bucket for removed user 2")
	}
}

func TestSpeedTracker_UpdateBuckets_LogCallbackMayCallLimitedUserCount(t *testing.T) {
	l := New()
	st := NewSpeedTracker(l)
	l.UpdateUsers([]core.UserSpec{{ID: 1, UUID: "u1", SpeedLimit: 1}})
	st.SetLogCallback(func(msg string) {
		_ = st.LimitedUserCount()
	})

	done := make(chan struct{})
	go func() {
		st.UpdateBuckets()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("deadlock: UpdateBuckets did not finish (log callback vs RWMutex)")
	}
}
