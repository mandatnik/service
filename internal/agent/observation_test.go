package agent

import (
	"os"
	"path/filepath"
	"testing"

	"telehack2026/internal/certparse"
)

func TestStripWhitespaceKeepsDERControlBytes(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "test-data", "certificates-2026-11-14", "certificates", "01-individual-valid.cer"))
	if err != nil {
		t.Fatal(err)
	}
	trimmed := stripWhitespace(raw)
	if len(trimmed) != len(raw) {
		t.Fatalf("DER length changed from %d to %d", len(raw), len(trimmed))
	}
	if _, err := certparse.Parse(trimmed); err != nil {
		t.Fatalf("trimmed DER no longer parses: %v", err)
	}
}
