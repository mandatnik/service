package agent

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"mandatnik/internal/platform"
	"mandatnik/internal/protocol"
)

const taskJournalMagic = "THJ1"

// TaskJournalEntry survives restarts and stores the exact attempt intent before
// any registry write. The DPAPI-protected file may contain the previous license
// value needed for rollback; it is never written to state.json or logs.
type TaskJournalEntry struct {
	TaskID              string                       `json:"task_id"`
	ItemID              string                       `json:"item_id"`
	MachineID           string                       `json:"machine_id"`
	RegistrationID      int64                        `json:"registration_id"`
	Kind                string                       `json:"kind"`
	State               string                       `json:"state"`
	ReasonCode          string                       `json:"reason_code,omitempty"`
	DeliveryVersion     int                          `json:"delivery_version"`
	AttemptCount        int                          `json:"attempt_count"`
	NextAttemptAt       string                       `json:"next_attempt_at,omitempty"`
	ClaimUntil          string                       `json:"claim_until,omitempty"`
	ResultVersion       int                          `json:"result_version"`
	LicenseID           string                       `json:"license_id,omitempty"`
	AssignedFingerprint string                       `json:"assigned_fingerprint,omitempty"`
	OriginalValue       string                       `json:"original_value,omitempty"`
	OriginalValueType   uint32                       `json:"original_value_type,omitempty"`
	OriginalPresent     bool                         `json:"original_present,omitempty"`
	OriginalSaved       bool                         `json:"original_saved,omitempty"`
	ReportID            string                       `json:"report_id,omitempty"`
	PendingResult       *protocol.TaskResult         `json:"pending_result,omitempty"`
	DeliveryAcked       bool                         `json:"delivery_acked,omitempty"`
	Acknowledged        bool                         `json:"acknowledged,omitempty"`
	LastError           string                       `json:"last_error,omitempty"`
	ReadOnlyOnly        bool                         `json:"read_only_only,omitempty"`
	CreatedAt           string                       `json:"created_at,omitempty"`
	UpdatedAt           string                       `json:"updated_at"`
	SanitizedEvents     []protocol.TaskProgressEvent `json:"sanitized_events,omitempty"`
}

type TaskJournal struct {
	Version   int                          `json:"version"`
	CorruptAt string                       `json:"corrupt_at,omitempty"`
	Entries   map[string]*TaskJournalEntry `json:"entries"`
	path      string
	saveMu    sync.Mutex
}

func taskJournalPath() string { return filepath.Join(platform.AgentDir(), "task-journal.dpapi") }

// LoadTaskJournal returns a usable journal even after corruption, but sets
// CorruptAt and archives the damaged file. The caller must then prohibit
// modifying license writes until reconciliation.
func LoadTaskJournal(logger *Logger) (*TaskJournal, error) {
	return loadTaskJournalAt(taskJournalPath(), logger)
}

func loadTaskJournalAt(path string, logger *Logger) (*TaskJournal, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return &TaskJournal{Version: 1, Entries: map[string]*TaskJournalEntry{}, path: path}, nil
		}
		return nil, err
	}
	if !bytes.HasPrefix(raw, []byte(taskJournalMagic)) {
		return corruptJournal(path, logger, "unknown journal format")
	}
	plain, err := unprotectSecret(raw[len(taskJournalMagic):])
	if err != nil {
		return corruptJournal(path, logger, "DPAPI unprotect failed")
	}
	if err := protocol.RejectDuplicateKeys(plain); err != nil {
		return corruptJournal(path, logger, "duplicate JSON keys")
	}
	var journal TaskJournal
	decoder := json.NewDecoder(bytes.NewReader(plain))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&journal); err != nil {
		return corruptJournal(path, logger, "journal JSON is invalid")
	}
	if journal.Version != 1 {
		return corruptJournal(path, logger, "unsupported journal version")
	}
	if journal.Entries == nil {
		journal.Entries = map[string]*TaskJournalEntry{}
	}
	journal.path = path
	return &journal, nil
}

func corruptJournal(path string, logger *Logger, reason string) (*TaskJournal, error) {
	archive := filepath.Join(filepath.Dir(path), "task-journal.corrupt-"+time.Now().UTC().Format("20060102T150405")+".dpapi")
	if err := os.Rename(path, archive); err != nil {
		if logger != nil {
			logger.Logf("task journal is corrupt and could not be archived: code=journal_corrupted")
		}
		return nil, fmt.Errorf("task journal is corrupt: %s", reason)
	}
	if logger != nil {
		logger.Logf("task journal archived after corruption: code=journal_corrupted reason=%s", reason)
	}
	journal := &TaskJournal{Version: 1, CorruptAt: time.Now().UTC().Format(time.RFC3339Nano), Entries: map[string]*TaskJournalEntry{}, path: path}
	if err := journal.save(); err != nil {
		return nil, err
	}
	return journal, nil
}

func (j *TaskJournal) save() error {
	if j == nil {
		return fmt.Errorf("nil task journal")
	}
	j.saveMu.Lock()
	defer j.saveMu.Unlock()
	if j.Version == 0 {
		j.Version = 1
	}
	if j.Entries == nil {
		j.Entries = map[string]*TaskJournalEntry{}
	}
	plain, err := json.Marshal(j)
	if err != nil {
		return err
	}
	protected, err := protectSecret(plain)
	if err != nil {
		return err
	}
	data := append([]byte(taskJournalMagic), protected...)
	if err := writeFileAtomic(j.path, data, 0o600); err != nil {
		return err
	}
	return securePath(j.path)
}

func (j *TaskJournal) Corrupt() bool { return j != nil && j.CorruptAt != "" }

// DataCorrupt reports that this entry was accepted while the durable journal
// was damaged. License writes remain disabled for it until read-only
// reconciliation succeeds.
func (e *TaskJournalEntry) DataCorrupt() bool { return e != nil && e.ReadOnlyOnly }

func (j *TaskJournal) Entry(itemID string) (*TaskJournalEntry, bool) {
	if j == nil {
		return nil, false
	}
	entry, ok := j.Entries[itemID]
	return entry, ok
}

func (j *TaskJournal) Put(entry *TaskJournalEntry) {
	if j.Entries == nil {
		j.Entries = map[string]*TaskJournalEntry{}
	}
	entry.UpdatedAt = time.Now().UTC().Format(time.RFC3339Nano)
	j.Entries[entry.ItemID] = entry
}

func (j *TaskJournal) Due(now time.Time) []*TaskJournalEntry {
	var due []*TaskJournalEntry
	for _, entry := range j.Entries {
		if entry.PendingResult != nil {
			due = append(due, entry)
			continue
		}
		if protocol.IsTerminalTaskState(entry.State) {
			continue
		}
		if entry.Acknowledged && entry.State != protocol.TaskStateRetryWait && entry.State != "report_queued" {
			continue
		}
		if entry.NextAttemptAt != "" {
			next, err := time.Parse(time.RFC3339Nano, entry.NextAttemptAt)
			if err == nil && now.Before(next) {
				continue
			}
		}
		due = append(due, entry)
	}
	sort.Slice(due, func(i, j int) bool {
		if due[i].NextAttemptAt != due[j].NextAttemptAt {
			return due[i].NextAttemptAt < due[j].NextAttemptAt
		}
		return due[i].ItemID < due[j].ItemID
	})
	return due
}

func (j *TaskJournal) PendingResults() []*TaskJournalEntry {
	var out []*TaskJournalEntry
	for _, entry := range j.Entries {
		if entry.PendingResult != nil && !entry.Acknowledged {
			out = append(out, entry)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].UpdatedAt < out[j].UpdatedAt })
	return out
}

func (j *TaskJournal) BeginAttempt(entry *TaskJournalEntry, assignedFingerprint, originalValue string, originalType uint32, originalPresent bool) error {
	entry.AttemptCount++
	entry.State = "write_intent"
	entry.AssignedFingerprint = assignedFingerprint
	entry.OriginalValue = originalValue
	entry.OriginalValueType = originalType
	entry.OriginalPresent = originalPresent
	entry.OriginalSaved = true
	entry.UpdatedAt = time.Now().UTC().Format(time.RFC3339Nano)
	j.Put(entry)
	return j.save()
}

func (j *TaskJournal) Complete(entry *TaskJournalEntry, result *protocol.TaskResult) error {
	entry.State = result.State
	entry.ReasonCode = result.ReasonCode
	entry.PendingResult = result
	entry.ResultVersion = result.ResultVersion
	if entry.ResultVersion < 1 {
		entry.ResultVersion = 1
	}
	entry.UpdatedAt = time.Now().UTC().Format(time.RFC3339Nano)
	j.Put(entry)
	return j.save()
}

func (j *TaskJournal) Acknowledge(itemID string) error {
	entry, ok := j.Entries[itemID]
	if !ok {
		return nil
	}
	entry.Acknowledged = true
	entry.PendingResult = nil
	entry.OriginalValue = ""
	entry.OriginalValueType = 0
	entry.OriginalSaved = false
	entry.UpdatedAt = time.Now().UTC().Format(time.RFC3339Nano)
	return j.save()
}
