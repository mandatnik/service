package agent

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"telehack2026/internal/protocol"
)

func testProtect(data []byte) ([]byte, error) {
	out := make([]byte, base64.StdEncoding.EncodedLen(len(data)))
	base64.StdEncoding.Encode(out, data)
	return out, nil
}

func testUnprotect(data []byte) ([]byte, error) {
	out := make([]byte, base64.StdEncoding.DecodedLen(len(data)))
	n, err := base64.StdEncoding.Decode(out, data)
	if err != nil {
		return nil, err
	}
	return out[:n], nil
}

func withTestProtection(t *testing.T) {
	t.Helper()
	oldProtect, oldUnprotect := protectSecret, unprotectSecret
	protectSecret, unprotectSecret = testProtect, testUnprotect
	t.Cleanup(func() { protectSecret, unprotectSecret = oldProtect, oldUnprotect })
}

func TestTaskJournalAttemptsSurviveRestart(t *testing.T) {
	withTestProtection(t)
	path := filepath.Join(t.TempDir(), "task-journal.dpapi")
	journal, err := loadTaskJournalAt(path, nil)
	if err != nil {
		t.Fatal(err)
	}
	entry := &TaskJournalEntry{
		TaskID: protocol.NewUUID(), ItemID: protocol.NewUUID(), MachineID: protocol.NewUUID(),
		Kind: protocol.TaskKindInstallLicense, State: protocol.TaskStateQueued, DeliveryVersion: 1,
	}
	journal.Put(entry)
	if err := journal.BeginAttempt(entry, "fingerprint", "1234567890123456789012345", 1, true); err != nil {
		t.Fatal(err)
	}
	if entry.AttemptCount != 1 {
		t.Fatalf("attempt=%d", entry.AttemptCount)
	}
	reloaded, err := loadTaskJournalAt(path, nil)
	if err != nil {
		t.Fatal(err)
	}
	restored, ok := reloaded.Entry(entry.ItemID)
	if !ok || restored.AttemptCount != 1 || restored.OriginalValue != "1234567890123456789012345" {
		t.Fatalf("restored=%+v ok=%t", restored, ok)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "1234567890123456789012345") {
		t.Fatal("DPAPI-protected journal contains plaintext serial")
	}
	if _, err := os.Stat(path + ".plain"); err == nil {
		t.Fatal("unexpected plaintext journal")
	}
}

func TestTaskJournalCorruptionIsArchivedNotResetForReplay(t *testing.T) {
	withTestProtection(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "task-journal.dpapi")
	if err := os.WriteFile(path, []byte("not a journal"), 0o600); err != nil {
		t.Fatal(err)
	}
	journal, err := loadTaskJournalAt(path, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !journal.Corrupt() {
		t.Fatal("corruption was not marked")
	}
	matches, err := filepath.Glob(filepath.Join(dir, "task-journal.corrupt-*.dpapi"))
	if err != nil || len(matches) != 1 {
		t.Fatalf("archived files=%v err=%v", matches, err)
	}
	reloaded, err := loadTaskJournalAt(path, nil)
	if err != nil || !reloaded.Corrupt() {
		t.Fatalf("corruption marker was lost across restart: %v", err)
	}
}

func TestEncryptionIdentityRotationAndReinstall(t *testing.T) {
	withTestProtection(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "encryption.dpapi")
	identity := &Identity{UUID: protocol.NewUUID(), InstallationID: protocol.NewUUID()}
	ring, err := loadOrCreateEncryptionIdentity(identity, path)
	if err != nil {
		t.Fatal(err)
	}
	oldID := ring.ActiveID()
	oldKey := ring.Key(oldID)
	if oldKey == nil {
		t.Fatal("old key missing")
	}
	newID, err := ring.Rotate()
	if err != nil {
		t.Fatal(err)
	}
	if newID == oldID || ring.Key(oldID) == nil {
		t.Fatal("rotation dropped the old key or reused the id")
	}
	loaded, err := loadOrCreateEncryptionIdentity(identity, path)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.ActiveID() != newID || loaded.Key(oldID) == nil {
		t.Fatal("rotation did not survive reload")
	}
	// A new installation must not inherit the previous key ring.
	other := &Identity{UUID: protocol.NewUUID(), InstallationID: protocol.NewUUID()}
	fresh, err := loadOrCreateEncryptionIdentity(other, path)
	if err != nil {
		t.Fatal(err)
	}
	if fresh.ActiveID() == newID || fresh.Key(newID) != nil {
		t.Fatal("new installation inherited the old encryption key")
	}
}

func TestJournalDueRespectsNextAttempt(t *testing.T) {
	withTestProtection(t)
	journal, err := loadTaskJournalAt(filepath.Join(t.TempDir(), "journal.dpapi"), nil)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	entry := &TaskJournalEntry{ItemID: protocol.NewUUID(), State: protocol.TaskStateRetryWait,
		NextAttemptAt: now.Add(time.Minute).Format(time.RFC3339Nano)}
	journal.Put(entry)
	if due := journal.Due(now); len(due) != 0 {
		t.Fatalf("future retry was due: %d", len(due))
	}
	if due := journal.Due(now.Add(2 * time.Minute)); len(due) != 1 {
		t.Fatalf("due retry missing: %d", len(due))
	}
	// Acknowledging the retry_wait result must not disable the next attempt.
	entry.Acknowledged = true
	journal.Put(entry)
	if due := journal.Due(now.Add(2 * time.Minute)); len(due) != 1 {
		t.Fatalf("acknowledged retry_wait was skipped: %d", len(due))
	}
}
