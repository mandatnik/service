package platform

import (
	"os"
	"path/filepath"
	"testing"
)

func TestExistingDataDir(t *testing.T) {
	base := t.TempDir()
	current, legacy := filepath.Join(base, "Mandatnik"), filepath.Join(base, "Telehack2026")
	if got := existingDataDir(base, "Mandatnik", "Telehack2026"); got != current {
		t.Fatal(got)
	}
	if err := os.Mkdir(legacy, 0700); err != nil {
		t.Fatal(err)
	}
	if got := existingDataDir(base, "Mandatnik", "Telehack2026"); got != legacy {
		t.Fatal(got)
	}
	if err := os.Mkdir(current, 0700); err != nil {
		t.Fatal(err)
	}
	if got := existingDataDir(base, "Mandatnik", "Telehack2026"); got != current {
		t.Fatal(got)
	}
}

func TestEnv(t *testing.T) {
	t.Setenv("TELEHACK_BRAND_TEST", "legacy")
	if got := Env("MANDATNIK_BRAND_TEST"); got != "legacy" {
		t.Fatal(got)
	}
	t.Setenv("MANDATNIK_BRAND_TEST", "current")
	if got := Env("MANDATNIK_BRAND_TEST"); got != "current" {
		t.Fatal(got)
	}
	t.Setenv("MANDATNIK_BRAND_TEST", "")
	if got := Env("MANDATNIK_BRAND_TEST"); got != "" {
		t.Fatal(got)
	}
}
