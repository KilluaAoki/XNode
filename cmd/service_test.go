package cmd

import "testing"

func TestDetectInitSystem(t *testing.T) {
	none := func(string) bool { return false }
	all := func(string) bool { return true }
	cases := []struct {
		goos   string
		hasDir func(string) bool
		hasCmd func(string) bool
		want   initSystem
	}{
		{"windows", all, all, initWindows},
		{"darwin", all, all, initLaunchd},
		{"linux", all, all, initSystemd},
		{"linux", none, all, initOpenRC},
		{"linux", none, none, initSystemd},
	}
	for _, c := range cases {
		if got := detectInitSystem(c.goos, c.hasDir, c.hasCmd); got != c.want {
			t.Fatalf("detectInitSystem(%s) = %s, want %s", c.goos, got, c.want)
		}
	}
}

func TestOpenRCState(t *testing.T) {
	cases := map[string]string{
		" * status: started\n": "active",
		" * status: stopped\n": "inactive",
		" * status: crashed\n": "failed",
		"":                     "unknown",
	}
	for in, want := range cases {
		if got := openrcState(in); got != want {
			t.Fatalf("openrcState(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestLaunchdState(t *testing.T) {
	running := "system/com.killuaaoki.xnode = {\n\tactive count = 1\n\tstate = running\n\tpid = 123\n}\n"
	if got := launchdState(running); got != "active" {
		t.Fatalf("launchdState(running) = %q", got)
	}
	waiting := "system/com.killuaaoki.xnode = {\n\tstate = not running\n}\n"
	if got := launchdState(waiting); got != "inactive" {
		t.Fatalf("launchdState(not running) = %q", got)
	}
	if got := launchdState(""); got != "unknown" {
		t.Fatalf("launchdState(empty) = %q", got)
	}
}

func TestOpenRCEnabled(t *testing.T) {
	cases := map[string]bool{
		"            local | default\n             xnode | default\n": true,
		"           xnoded | default\n":                               false,
		"":                                                            false,
	}
	for in, want := range cases {
		if got := openrcEnabled(in); got != want {
			t.Fatalf("openrcEnabled(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestLaunchdDisabled(t *testing.T) {
	cases := map[string]bool{
		"disabled services = {\n\t\"com.killuaaoki.xnode\" => disabled\n}\n": true,
		"disabled services = {\n\t\"com.killuaaoki.xnode\" => true\n}\n":     true,
		"disabled services = {\n\t\"com.killuaaoki.xnode\" => enabled\n}\n":  false,
		"disabled services = {\n\t\"com.apple.other\" => disabled\n}\n":      false,
		"": false,
	}
	for in, want := range cases {
		if got := launchdDisabled(in); got != want {
			t.Fatalf("launchdDisabled(%q) = %v, want %v", in, got, want)
		}
	}
}
