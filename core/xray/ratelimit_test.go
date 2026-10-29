package xray

import (
	"context"
	"testing"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/pipe"
	"golang.org/x/time/rate"
)

func TestWaitRateSplitsAboveBurst(t *testing.T) {
	lim := rate.NewLimiter(rate.Inf, 4)
	if err := waitRate(lim, 10); err != nil {
		t.Fatalf("waitRate() error = %v", err)
	}
	lim = rate.NewLimiter(1_000_000, 4)
	if err := waitRate(lim, 10); err != nil {
		t.Fatalf("waitRate() above burst error = %v", err)
	}
}

func TestLimitDispatchedLinkKeepsPipeReader(t *testing.T) {
	upR, upW := pipe.New()
	downR, downW := pipe.New()
	lim := rate.NewLimiter(rate.Inf, 1)
	link := limitDispatchedLink(context.Background(), &transport.Link{Reader: downR, Writer: upW}, lim)

	if _, ok := link.Reader.(*pipe.Reader); !ok {
		t.Fatalf("link.Reader = %T, want *pipe.Reader", link.Reader)
	}

	b := buf.New()
	b.WriteString("downlink")
	if err := downW.WriteMultiBuffer(buf.MultiBuffer{b}); err != nil {
		t.Fatalf("downlink write error = %v", err)
	}
	downW.Close()
	mb, err := link.Reader.ReadMultiBuffer()
	if err != nil {
		t.Fatalf("downlink read error = %v", err)
	}
	if got := mb.String(); got != "downlink" {
		t.Fatalf("downlink data = %q, want %q", got, "downlink")
	}
	buf.ReleaseMulti(mb)

	b = buf.New()
	b.WriteString("uplink")
	if err := link.Writer.WriteMultiBuffer(buf.MultiBuffer{b}); err != nil {
		t.Fatalf("uplink write error = %v", err)
	}
	mb, err = upR.ReadMultiBuffer()
	if err != nil {
		t.Fatalf("uplink read error = %v", err)
	}
	if got := mb.String(); got != "uplink" {
		t.Fatalf("uplink data = %q, want %q", got, "uplink")
	}
	buf.ReleaseMulti(mb)
}

func TestLimitDispatcherDisablesSpliceForLimitedUser(t *testing.T) {
	ld := newTestDispatcher()
	lim := rate.NewLimiter(rate.Inf, 1)
	ld.UpdateLimits(map[string]int{userEmail(1): 1}, nil, map[string]*rate.Limiter{userEmail(1): lim})
	if ld.speedLimiter(userEmail(1)) != lim {
		t.Fatal("expected limiter for limited user")
	}
	if ld.speedLimiter(userEmail(2)) != nil {
		t.Fatal("unexpected limiter for unknown user")
	}
}
