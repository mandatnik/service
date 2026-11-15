package agent

import (
	"context"
	"mandatnik/internal/protocol"
	"testing"
)

func TestRunDueIgnoresPreviouslyQueuedActivation(t *testing.T) {
	entry := &TaskJournalEntry{ItemID: "retired-install", Kind: protocol.TaskKindInstallLicense, State: protocol.TaskStateQueued}
	journal := &TaskJournal{Entries: map[string]*TaskJournalEntry{entry.ItemID: entry}}
	// No runtime, collector or native executor: retired entries must never reach them.
	tasks := &taskRuntime{journal: journal}
	tasks.RunDue(context.Background())
	if entry.State != protocol.TaskStateQueued || entry.AttemptCount != 0 {
		t.Fatal("retired activation was executed")
	}
}
