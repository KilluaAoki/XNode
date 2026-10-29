package core

import (
	"reflect"
	"testing"
)

func TestUserDiffTreatsUUIDChangeAsReplace(t *testing.T) {
	oldUsers := []UserSpec{{ID: 1, UUID: "a"}, {ID: 2, UUID: "b"}, {ID: 3, UUID: "c"}}
	newUsers := []UserSpec{{ID: 1, UUID: "a"}, {ID: 2, UUID: "b2"}, {ID: 4, UUID: "d"}}
	toAdd, toRemove := UserDiff(oldUsers, newUsers)
	if len(toAdd) != 2 || toAdd[0].UUID != "b2" || toAdd[1].UUID != "d" {
		t.Fatalf("toAdd = %+v", toAdd)
	}
	if len(toRemove) != 2 || toRemove[0].UUID != "b" || toRemove[1].UUID != "c" {
		t.Fatalf("toRemove = %+v", toRemove)
	}
}

func TestRealityShortIDs(t *testing.T) {
	cases := []struct {
		in   any
		want []string
	}{
		{nil, []string{""}},
		{"", []string{""}},
		{" ab12 ", []string{"ab12"}},
		{"ab, cd,,", []string{"ab", "cd"}},
		{[]any{}, []string{""}},
		{[]any{"", "ab", "ab", nil}, []string{"", "ab"}},
		{[]string{"cd"}, []string{"cd"}},
		{float64(1234), []string{"1234"}},
	}
	for _, c := range cases {
		if got := RealityShortIDs(c.in); !reflect.DeepEqual(got, c.want) {
			t.Fatalf("RealityShortIDs(%#v) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestSettingHelpers(t *testing.T) {
	s := map[string]any{"name": " example.com ", "null": nil, "port": "8443", "num": float64(443), "bad": "x", "big": 70000}
	if SettingString(s, "name") != "example.com" || SettingString(s, "null") != "" || SettingString(s, "missing") != "" {
		t.Fatal("SettingString mismatch")
	}
	for key, want := range map[string]int{"port": 8443, "num": 443, "bad": 0, "big": 0, "null": 0} {
		if got := SettingPort(s, key); got != want {
			t.Fatalf("SettingPort(%s) = %d, want %d", key, got, want)
		}
	}
}
