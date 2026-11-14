package agent

import (
	"os"
	"path/filepath"
	"testing"
)

func TestPurgeAgentStateRequiresExplicitPurge(t *testing.T) {
	dir := t.TempDir()
	identity := filepath.Join(dir, "identity.dpapi")
	if err := os.WriteFile(identity, []byte("protected identity"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := purgeAgentState(false, dir); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(identity); err != nil {
		t.Fatalf("ordinary uninstall removed identity: %v", err)
	}
	if err := purgeAgentState(true, dir); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatalf("explicit purge did not remove agent state: %v", err)
	}
}
