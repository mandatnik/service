package store

import (
	"testing"

	"telehack2026/internal/protocol"
)

func TestAggregateTaskStates(t *testing.T) {
	cases := []struct {
		name      string
		states    []string
		want      string
		attention bool
		unknown   int
	}{
		{"queued", []string{protocol.TaskStateQueued, protocol.TaskStateQueued}, protocol.TaskAggregateQueued, false, 0},
		{"running", []string{protocol.TaskStateSucceeded, protocol.TaskStateRunning}, protocol.TaskAggregateRunning, false, 0},
		{"unknown_requires_attention", []string{protocol.TaskStateSucceeded, protocol.TaskStateOutcomeUnknown}, protocol.TaskAggregateRequiresAttention, true, 1},
		{"unknown_while_running", []string{protocol.TaskStateOutcomeUnknown, protocol.TaskStateRunning}, protocol.TaskAggregateRunning, true, 1},
		{"completed", []string{protocol.TaskStateSucceeded, protocol.TaskStateSkipped}, protocol.TaskAggregateCompleted, false, 0},
		{"partial", []string{protocol.TaskStateSucceeded, protocol.TaskStateFailed}, protocol.TaskAggregatePartiallyFailed, false, 0},
		{"failed", []string{protocol.TaskStateFailed, protocol.TaskStateFailed}, protocol.TaskAggregateFailed, false, 0},
		{"canceled", []string{protocol.TaskStateCancelled, protocol.TaskStateCancelled}, protocol.TaskAggregateCancelled, false, 0},
		{"expired", []string{protocol.TaskStateExpired, protocol.TaskStateExpired}, protocol.TaskAggregateExpired, false, 0},
	}
	for _, test := range cases {
		got, attention, unknown := AggregateItems(test.states)
		if got != test.want || attention != test.attention || unknown != test.unknown {
			t.Errorf("%s: got=%s attention=%t unknown=%d", test.name, got, attention, unknown)
		}
	}
}

func TestTaskCountsAndTerminalSafety(t *testing.T) {
	counts := taskCountsFromStates([]string{
		protocol.TaskStateSucceeded, protocol.TaskStateSkipped, protocol.TaskStateFailed,
		protocol.TaskStateOutcomeUnknown, protocol.TaskStateCancelled, protocol.TaskStateExpired,
	})
	if counts.Total != 6 || counts.Succeeded != 1 || counts.Skipped != 1 || counts.Failed != 1 ||
		counts.OutcomeUnknown != 1 || counts.Cancelled != 1 || counts.Expired != 1 || counts.Finished != 6 {
		t.Fatalf("counts=%+v", counts)
	}
	if !protocol.IsTerminalTaskState(protocol.TaskStateOutcomeUnknown) {
		t.Fatal("outcome_unknown must be terminal for state transition safety")
	}
	if protocol.IsTerminalTaskState(protocol.TaskStateRunning) {
		t.Fatal("running must not be terminal")
	}
}
