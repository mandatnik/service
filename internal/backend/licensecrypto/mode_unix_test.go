//go:build !windows

package licensecrypto

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestKeyringRefusesLoosePermissions(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "keyring.json")
	if _, err := InitKeyring(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadKeyring(path); err == nil || !strings.Contains(err.Error(), "group/others") {
		t.Fatalf("loose permissions accepted: %v", err)
	}
}
