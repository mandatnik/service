package agent

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"telehack2026/internal/protocol"
)

func validTestReport(t *testing.T, seq int64) protocol.Report {
	t.Helper()
	now := time.Now().UTC()
	return protocol.Report{
		ReportID: protocol.NewUUID(), ScanSeq: seq,
		CollectedAt: now.Format(time.RFC3339Nano), StartedAt: now.Format(time.RFC3339Nano), FinishedAt: now.Format(time.RFC3339Nano),
		AgentVersion: "test", Hostname: "WORKSTATION-1", Status: "complete", ProfilesComplete: true,
		Profiles: []protocol.ProfileResult{}, Sources: []protocol.SourceResult{},
		CSP: protocol.CSPResult{Scanned: true, Complete: true, Present: false, License: protocol.LicenseInfo{Kind: "unknown", State: "not_installed", TermKind: "unknown", IsTrial: "unknown"}},
	}
}

func TestQueueKeepsTwoNewest(t *testing.T) {
	dir := t.TempDir()
	queue := &Queue{dir: dir, protectFile: func(string) error { return nil }}
	base := time.Now().UTC()
	var ids []string
	for index := 0; index < 3; index++ {
		report := validTestReport(t, int64(index+1))
		ids = append(ids, report.ReportID)
		item := QueueItem{ReportID: report.ReportID, ScanSeq: report.ScanSeq, CollectedAt: report.CollectedAt, QueuedAt: base.Add(time.Duration(index) * time.Second).Format(time.RFC3339Nano), Report: report}
		evicted, err := queue.Add(item)
		if err != nil {
			t.Fatal(err)
		}
		if index < 2 && len(evicted) != 0 {
			t.Fatalf("unexpected eviction at %d: %v", index, evicted)
		}
		if index == 2 {
			if len(evicted) != 1 || evicted[0] != ids[0] {
				t.Fatalf("evicted = %v, want oldest %s", evicted, ids[0])
			}
		}
	}
	items, err := queue.Items()
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 2 || items[0].ReportID != ids[1] || items[1].ReportID != ids[2] {
		t.Fatalf("queue contents = %+v", items)
	}
	if err := queue.Remove(ids[1]); err != nil {
		t.Fatal(err)
	}
	if queue.Count() != 1 {
		t.Fatalf("count after remove = %d", queue.Count())
	}
}

func TestQueueArchivesCorruptItem(t *testing.T) {
	dir := t.TempDir()
	queue := &Queue{dir: dir, protectFile: func(string) error { return nil }}
	report := validTestReport(t, 1)
	if _, err := queue.Add(QueueItem{ReportID: report.ReportID, ScanSeq: 1, CollectedAt: report.CollectedAt, Report: report}); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "report-corrupt.json"), []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	items, err := queue.Items()
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 1 {
		t.Fatalf("valid item lost: %d", len(items))
	}
	entries, _ := os.ReadDir(dir)
	foundCorrupt := false
	for _, entry := range entries {
		if len(entry.Name()) > 8 && entry.Name()[:8] == "corrupt-" {
			foundCorrupt = true
		}
	}
	if !foundCorrupt {
		t.Fatal("corrupt item was not archived")
	}
}

func TestScanDue(t *testing.T) {
	now := time.Now().UTC()
	state := &State{}
	if !state.scanDue(now) {
		t.Fatal("initial state must scan")
	}
	state.LastScanSuccessAt = now.Format(time.RFC3339Nano)
	cfg := protocol.DefaultAgentConfig()
	state.Config = &cfg
	if state.scanDue(now.Add(12 * time.Hour)) {
		t.Fatal("scanned early")
	}
	if !state.scanDue(now.Add(25 * time.Hour)) {
		t.Fatal("did not scan after one day")
	}
}

func TestJobsLifecycle(t *testing.T) {
	jobs := &Jobs{Jobs: map[string]JobState{}}
	jobs.merge([]protocol.Job{{JobID: "job-1"}, {JobID: "job-2"}})
	if len(jobs.pendingIDs()) != 2 {
		t.Fatalf("pending = %v", jobs.pendingIDs())
	}
	jobs.markCompleted("report-1", jobs.pendingIDs())
	if jobs.hasPending() {
		t.Fatal("jobs still pending after completion")
	}
	acks := jobs.pendingAcks()
	if len(acks) != 2 || acks[0].Status != "completed" || acks[0].ReportID != "report-1" {
		t.Fatalf("acks = %+v", acks)
	}
	jobs.markReportEvicted("report-1")
	acks = jobs.pendingAcks()
	if acks[0].Status != "report_evicted" || acks[0].ReportID != "" {
		t.Fatalf("evicted ack = %+v", acks[0])
	}
	for _, ack := range acks {
		jobs.markAcked(ack.JobID)
	}
	if len(jobs.pendingAcks()) != 0 {
		t.Fatal("acks remain after markAcked")
	}
	// Acknowledged jobs must not be recreated as pending by a repeated sync.
	jobs.merge([]protocol.Job{{JobID: "job-1"}})
	if len(jobs.pendingIDs()) != 0 {
		t.Fatal("acked job was resurrected")
	}
}

func TestLoggerRotation(t *testing.T) {
	dir := t.TempDir()
	logger, err := OpenLogger(dir)
	if err != nil {
		t.Fatal(err)
	}
	logger.maxBytes = 2048
	logger.Logf("start")
	for index := 0; index < 100; index++ {
		logger.Logf("line %d: %s", index, "0123456789012345678901234567890123456789")
	}
	logger.Close()
	current, err := os.Stat(filepath.Join(dir, "current.txt"))
	if err != nil {
		t.Fatal(err)
	}
	previous, err := os.Stat(filepath.Join(dir, "previous.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if current.Size() > logger.maxBytes || previous.Size() > logger.maxBytes {
		t.Fatalf("log files exceed limit: current=%d previous=%d", current.Size(), previous.Size())
	}
}

func TestWriteFileAtomic(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	if err := writeFileAtomic(path, []byte(`{"a":1}`), 0o600); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var value map[string]int
	if err := json.Unmarshal(raw, &value); err != nil || value["a"] != 1 {
		t.Fatalf("atomic write content: %s %v", raw, err)
	}
}
