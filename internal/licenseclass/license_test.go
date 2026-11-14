package licenseclass

import (
	"testing"
	"time"
)

func TestLicenseKindMapping(t *testing.T) {
	cases := map[int32]string{0: "client", 1: "server", 2: "unknown", -1: "unknown", 99: "unknown"}
	for raw, want := range cases {
		if got := KindFromRaw(raw); got != want {
			t.Errorf("KindFromRaw(%d) = %q, want %q", raw, got, want)
		}
	}
}

func TestLicenseState(t *testing.T) {
	now := time.Date(2026, 11, 14, 12, 0, 0, 0, time.Local)
	future := now.Add(24 * time.Hour)
	past := now.Add(-24 * time.Hour)
	if got := StateFromWallClock(future, now); got != "active" {
		t.Errorf("future state = %q", got)
	}
	if got := StateFromWallClock(past, now); got != "expired" {
		t.Errorf("past state = %q", got)
	}
	if got := StateFromWallClock(time.Time{}, now); got != "unknown" {
		t.Errorf("zero state = %q", got)
	}
	if got := TermKind(true); got != "time_limited" {
		t.Errorf("term kind with expiry = %q", got)
	}
	if got := TermKind(false); got != "unknown" {
		t.Errorf("term kind without expiry = %q", got)
	}
}
