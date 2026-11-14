package agent

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"telehack2026/internal/protocol"
	"telehack2026/internal/version"
)

// taskRuntime owns the encrypted task channel, the durable local journal and
// the native install executor. It runs independently of the polling loop so a
// long scan/retry never stops server polling.
type taskRuntime struct {
	runtime    *agentRuntime
	journal    *TaskJournal
	encryption *EncryptionIdentity
	executor   InstallExecutor
	logger     *Logger
	state      *State
	queue      *Queue
	collector  Collector
	localMu    *sync.Mutex
	busy       atomic.Bool
	mu         sync.Mutex
	deliveries map[string]protocol.TaskItemDelivery
}

func newTaskRuntime(r *agentRuntime, journal *TaskJournal, encryption *EncryptionIdentity) *taskRuntime {
	return &taskRuntime{
		runtime: r, journal: journal, encryption: encryption, executor: newInstallExecutor(),
		logger: r.logger, state: r.state, queue: r.queue, collector: r.collector, localMu: &r.localMu,
		deliveries: map[string]protocol.TaskItemDelivery{},
	}
}

func (t *taskRuntime) identity() *Identity { return t.runtime.identity }

func (t *taskRuntime) logEvent(event, taskID, itemID string, attempt int, code string) {
	licenseID, machineID := "", ""
	if entry, ok := t.journal.Entry(itemID); ok {
		licenseID, machineID = entry.LicenseID, entry.MachineID
	}
	t.logger.Logf("task event=%s task_id=%s item_id=%s machine_id=%s license_id=%s attempt=%d code=%s",
		event, taskID, itemID, machineID, licenseID, attempt, code)
}

// Poll performs one task sync and delivery ACK/resend cycle. It is called from
// the independent polling goroutine.
func (t *taskRuntime) Poll(ctx context.Context) {
	if t == nil || t.runtime == nil || !t.runtime.registered || t.identity() == nil {
		return
	}
	t.flushPendingResults(ctx)
	response, result := t.runtime.client.taskSync(ctx, t.identity(), protocol.TaskQueueStatus{
		JournalCorrupt: t.journal.Corrupt(),
	}, agentOSVersion())
	if result.Error != nil {
		t.logger.Logf("task sync failed: status=%d code=%s message=%s", result.Status, result.Error.Code, result.Error.Message)
		return
	}
	for _, delivery := range response.Items {
		if err := t.acceptDelivery(ctx, delivery); err != nil {
			t.logger.Logf("task delivery rejected: item_id=%s code=%s", delivery.ItemID, safeCode(err))
		}
	}
	if t.journal.Corrupt() {
		_ = t.runtime.client.taskDiagnostic(ctx, t.identity(), protocol.TaskDiagnostic{
			Code: protocol.CodeJournalCorrupted, Message: "local task journal was damaged; writes are disabled until read-only reconciliation",
			OccurredAt: time.Now().UTC().Format(time.RFC3339Nano),
		}, agentOSVersion())
	}
	for id, entry := range t.journal.Entries {
		if entry.DeliveryAcked || entry.Acknowledged {
			continue
		}
		ack, ackResult := t.runtime.client.taskAck(ctx, t.identity(), id, entry.DeliveryVersion, agentOSVersion())
		if ackResult.Error != nil {
			if ackResult.Error.Code == protocol.CodeTaskConflict || ackResult.Error.Code == protocol.CodeTaskNotFound {
				entry.DeliveryAcked = true
				_ = t.journal.save()
			}
			continue
		}
		if ack.Accepted {
			entry.DeliveryAcked = true
			entry.State = ack.State
			_ = t.journal.save()
		}
	}
}

func safeCode(err error) string {
	if err == nil {
		return ""
	}
	text := strings.ReplaceAll(err.Error(), "\n", " ")
	if len(text) > 128 {
		return text[:128]
	}
	return text
}

func (t *taskRuntime) acceptDelivery(ctx context.Context, delivery protocol.TaskItemDelivery) error {
	if delivery.ItemID == "" || delivery.TaskID == "" || delivery.Kind == "" {
		return errors.New("delivery is incomplete")
	}
	t.runtime.stateMu.Lock()
	machineID := t.runtime.state.MachineID
	t.runtime.stateMu.Unlock()
	if delivery.MachineID != machineID {
		return errors.New("delivery machine does not match this registration")
	}
	if delivery.State != protocol.TaskStateQueued && delivery.State != protocol.TaskStateDelivered &&
		delivery.State != protocol.TaskStateRetryWait && delivery.State != protocol.TaskStateRunning &&
		delivery.State != protocol.TaskStateOutcomeUnknown {
		return errors.New("delivery state is not executable")
	}
	if t.encryption.Key(delivery.ParametersEnvelope.RecipientKeyID) == nil {
		return errors.New("delivery references an unknown encryption key")
	}
	now := time.Now().UTC()
	entry, exists := t.journal.Entry(delivery.ItemID)
	if !exists {
		entry = &TaskJournalEntry{ItemID: delivery.ItemID, CreatedAt: now.Format(time.RFC3339Nano)}
	}
	if exists && delivery.DeliveryVersion < entry.DeliveryVersion {
		return errors.New("stale delivery version")
	}
	if exists && delivery.DeliveryVersion == entry.DeliveryVersion && entry.Acknowledged {
		return nil
	}
	entry.TaskID = delivery.TaskID
	entry.MachineID = delivery.MachineID
	entry.RegistrationID = delivery.RegistrationID
	entry.Kind = delivery.Kind
	entry.DeliveryVersion = delivery.DeliveryVersion
	entry.State = delivery.State
	entry.LicenseID = delivery.LicenseID
	entry.AttemptCount = maxInt(entry.AttemptCount, delivery.AttemptCount)
	entry.ReadOnlyOnly = t.journal.Corrupt() && delivery.Kind == protocol.TaskKindInstallLicense
	if delivery.CancelRequested {
		entry.ReasonCode = "cancel_requested"
	}
	t.journal.Put(entry)
	if err := t.journal.save(); err != nil {
		// Do not ACK ciphertext that we could not durably store.
		return fmt.Errorf("persist delivery: %w", err)
	}
	t.mu.Lock()
	t.deliveries[delivery.ItemID] = delivery
	t.mu.Unlock()
	t.logEvent("received", entry.TaskID, entry.ItemID, entry.AttemptCount, "")
	ack, result := t.runtime.client.taskAck(ctx, t.identity(), entry.ItemID, entry.DeliveryVersion, agentOSVersion())
	if result.Error != nil {
		return nil
	}
	if ack.Accepted {
		entry.DeliveryAcked = true
		entry.State = ack.State
		_ = t.journal.save()
	}
	return nil
}

func (t *taskRuntime) flushPendingResults(ctx context.Context) {
	for _, entry := range t.journal.PendingResults() {
		if entry.PendingResult == nil {
			continue
		}
		t.sendResult(ctx, entry, *entry.PendingResult, false)
	}
}

// RunDue executes due journal entries. A separate atomic guard prevents two
// executor goroutines from touching the local machine simultaneously.
func (t *taskRuntime) RunDue(ctx context.Context) {
	if t == nil || t.busy.Swap(true) {
		return
	}
	defer t.busy.Store(false)
	for _, entry := range t.journal.Due(time.Now().UTC()) {
		if ctx.Err() != nil {
			return
		}
		if entry.PendingResult != nil {
			t.sendResult(ctx, entry, *entry.PendingResult, false)
			continue
		}
		if entry.State == protocol.TaskStateOutcomeUnknown || entry.ReadOnlyOnly {
			t.reconcile(ctx, entry)
			continue
		}
		switch entry.Kind {
		case protocol.TaskKindScan:
			t.executeScan(ctx, entry)
		case protocol.TaskKindInstallLicense:
			t.executeInstall(ctx, entry)
		}
	}
}

func (t *taskRuntime) executeScan(ctx context.Context, entry *TaskJournalEntry) {
	if entry.ReportID != "" {
		// A report was already queued. If it has left the queue, it was either
		// accepted or evicted; never claim success for an eviction.
		if t.queue.Contains(entry.ReportID) {
			return
		}
		if t.queue.Evicted(entry.ReportID) {
			t.finish(entry, protocol.TaskStateFailed, "report_evicted", "report was evicted before server acceptance", "no", nil)
			return
		}
		t.sendResult(context.Background(), entry, protocol.TaskResult{
			ItemID: entry.ItemID, DeliveryVersion: entry.DeliveryVersion, State: protocol.TaskStateSucceeded,
			ReportID: entry.ReportID, Modified: "no", ResultVersion: t.nextResultVersion(entry),
		}, false)
		return
	}
	claim, result := t.runtime.client.taskClaim(ctx, t.identity(), entry.ItemID, entry.DeliveryVersion, agentOSVersion())
	if result.Error != nil {
		t.setRetry(entry, 15*time.Second)
		return
	}
	if !claim.Granted {
		t.handleClaimDenied(entry, claim)
		return
	}
	entry.ClaimUntil = claim.ClaimUntil
	_ = t.journal.save()
	t.localMu.Lock()
	defer t.localMu.Unlock()
	if ctx.Err() != nil {
		return
	}
	started := time.Now()
	t.runtime.stateMu.Lock()
	cfg := t.state.EffectiveConfig().WithScheduleDefaults()
	t.runtime.stateMu.Unlock()
	collection, err := t.collector.Collect(ctx, cfg)
	if err != nil {
		t.finish(entry, protocol.TaskStateFailed, "scan_failed", "collection could not start", "no", nil)
		t.progress(ctx, entry, "precheck", "scan_failed", "", 0, time.Since(started))
		return
	}
	t.runtime.stateMu.Lock()
	seq := t.state.ScanSeq + 1
	t.state.ScanSeq = seq
	t.state.LastScanStartedAt = collection.StartedAt.UTC().Format(time.RFC3339Nano)
	t.runtime.stateMu.Unlock()
	report := BuildReport(collection, protocol.NewUUID(), seq, agentVersion())
	report.Hostname = t.identity().Hostname
	if err := protocol.ValidateReport(&report); err != nil {
		t.finish(entry, protocol.TaskStateFailed, "report_invalid", err.Message, "no", nil)
		return
	}
	item := QueueItem{
		ReportID: report.ReportID, ScanSeq: report.ScanSeq, CollectedAt: report.CollectedAt,
		QueuedAt: time.Now().UTC().Format(time.RFC3339Nano), TaskItemIDs: []string{entry.ItemID}, Report: report,
	}
	evicted, err := t.queue.Add(item)
	if err != nil {
		t.finish(entry, protocol.TaskStateFailed, "report_queue_failed", "could not queue report", "no", nil)
		return
	}
	for _, reportID := range evicted {
		t.reportEvicted(reportID)
	}
	entry.ReportID = report.ReportID
	entry.State = "report_queued"
	if err := t.journal.save(); err != nil {
		t.logger.Logf("task journal save failed after scan: item_id=%s", entry.ItemID)
	}
	t.runtime.stateMu.Lock()
	t.state.LastScanSuccessAt = report.FinishedAt
	t.state.LastReportID = report.ReportID
	_ = t.state.save()
	t.runtime.stateMu.Unlock()
	t.logEvent("write_finished", entry.TaskID, entry.ItemID, 0, "report_queued")
	t.progress(ctx, entry, "verification", "", "", 0, time.Since(started))
}

func (t *taskRuntime) executeInstall(ctx context.Context, entry *TaskJournalEntry) {
	delivery := t.currentDelivery(entry)
	if delivery == nil {
		// A restart may run the executor before the next task poll restores the
		// ciphertext. Wait; never turn missing delivery into a failure result.
		return
	}
	claim, result := t.runtime.client.taskClaim(ctx, t.identity(), entry.ItemID, entry.DeliveryVersion, agentOSVersion())
	if result.Error != nil {
		t.setRetry(entry, 15*time.Second)
		return
	}
	if !claim.Granted {
		t.handleClaimDenied(entry, claim)
		return
	}
	entry.ClaimUntil = claim.ClaimUntil
	_ = t.journal.save()
	params, err := t.decryptInstallParameters(*delivery)
	if err != nil {
		t.finish(entry, protocol.TaskStateFailed, "parameters_invalid", safeCode(err), "no", nil)
		return
	}
	if entry.LicenseID != "" && params.LicenseID != entry.LicenseID {
		t.finish(entry, protocol.TaskStateOutcomeUnknown, "assignment_mismatch", "delivered license does not match the journal reservation", "maybe", nil)
		return
	}
	if entry.AssignedFingerprint != "" && entry.AssignedFingerprint != fingerprintSerial(params.Serial) {
		t.finish(entry, protocol.TaskStateOutcomeUnknown, "assignment_mismatch", "journal assignment does not match the delivered key", "maybe", nil)
		return
	}
	if entry.DataCorrupt() {
		t.reconcile(ctx, entry)
		return
	}
	t.localMu.Lock()
	defer t.localMu.Unlock()
	snapshot, err := t.executor.Inspect(params.Serial, params.Pool)
	if err != nil {
		t.finishUnknownOrFailed(entry, snapshot, err, "precheck_failed")
		return
	}
	// Step 4: the assigned key is already installed and valid. This takes
	// priority over the "do not replace a purchased license" rule.
	if snapshot.SerialMatch && snapshot.License.State == "active" && licenseMatches(snapshot.License, params.Pool) {
		t.finish(entry, protocol.TaskStateSucceeded, "already_assigned", "assigned license is already installed", "no", &snapshot)
		return
	}
	// Step 5: another purchased license is protected, even on a retry.
	if snapshot.License.State == "active" && snapshot.License.IsTrial == "false" {
		t.finish(entry, protocol.TaskStateSkipped, "already_licensed", "another purchased license is active", "no", &snapshot)
		return
	}
	if snapshot.License.State == "active" && snapshot.License.IsTrial == "true" && !params.AllowTrialReplacement {
		t.finish(entry, protocol.TaskStateSkipped, "trial_replacement_not_confirmed", "trial replacement was not explicitly confirmed", "no", &snapshot)
		return
	}
	if snapshot.License.State == "active" && (snapshot.License.IsTrial == "" || snapshot.License.IsTrial == "unknown") {
		t.finish(entry, protocol.TaskStateOutcomeUnknown, "license_mode_unknown", "license exists but trial status is unknown", "no", &snapshot)
		return
	}
	if snapshot.License.State == "unknown" || snapshot.License.State == "" || snapshot.License.State == "error" {
		t.finish(entry, protocol.TaskStateOutcomeUnknown, "license_state_unknown", "license state cannot be determined; no write was attempted", "no", &snapshot)
		return
	}
	if snapshot.License.Kind != "" && snapshot.License.Kind != "unknown" && snapshot.License.Kind != params.Pool.LicenseKind {
		t.finish(entry, protocol.TaskStateFailed, "license_kind_mismatch", "installed CSP license kind is incompatible with the pool", "no", &snapshot)
		return
	}
	if entry.OriginalSaved && !normalizedEqual(snapshot.CurrentSerial, entry.OriginalValue) {
		t.finish(entry, protocol.TaskStateOutcomeUnknown, "external_change", "registry value changed outside this task", "maybe", &snapshot)
		return
	}
	if entry.AttemptCount >= protocol.TaskMaxAttempts {
		t.finish(entry, protocol.TaskStateOutcomeUnknown, "attempts_exhausted", "the third attempt limit is exhausted", "maybe", &snapshot)
		return
	}
	// Persist attempt intent before the write and flush the DPAPI journal.
	if err := t.journal.BeginAttempt(entry, fingerprintSerial(params.Serial), snapshot.CurrentSerial, snapshot.OriginalType, snapshot.OriginalPresent); err != nil {
		t.finish(entry, protocol.TaskStateFailed, "journal_write_failed", "attempt intent could not be persisted", "no", &snapshot)
		return
	}
	t.logEvent("attempt_intent", entry.TaskID, entry.ItemID, entry.AttemptCount, "")
	t.progress(ctx, entry, "attempt_intent", "", "", 0, 0)
	t.logEvent("write_started", entry.TaskID, entry.ItemID, entry.AttemptCount, "")
	if err := t.executor.Write(snapshot, params.Serial); err != nil {
		t.handleWriteError(ctx, entry, params, snapshot, err)
		return
	}
	t.logEvent("write_finished", entry.TaskID, entry.ItemID, entry.AttemptCount, "")
	verified, ok, verifyErr := t.executor.Verify(params.Serial, params.Pool)
	if verifyErr == nil && ok {
		t.finish(entry, protocol.TaskStateSucceeded, "", "assigned license is installed and valid", "yes", &verified)
		return
	}
	// A write success code is not proof. Decide whether rollback is safe and
	// whether the result is knowable.
	t.handleVerificationFailure(ctx, entry, params, snapshot, verified, verifyErr)
}

func (t *taskRuntime) handleWriteError(ctx context.Context, entry *TaskJournalEntry, params *protocol.InstallLicenseParameters, before InstallSnapshot, writeErr error) {
	after, inspectErr := t.executor.Inspect(params.Serial, params.Pool)
	if inspectErr != nil {
		t.finish(entry, protocol.TaskStateOutcomeUnknown, "write_error_unknown_state", safeCode(writeErr), "maybe", &before)
		return
	}
	if after.SerialMatch {
		verified, ok, _ := t.executor.Verify(params.Serial, params.Pool)
		if ok {
			t.finish(entry, protocol.TaskStateSucceeded, "", "write reported an error but the assigned license is valid", "yes", &verified)
			return
		}
	}
	if normalizedEqual(after.CurrentSerial, before.CurrentSerial) || before.CurrentSerial == "" {
		if entry.AttemptCount < protocol.TaskMaxAttempts {
			t.retry(entry, "write_failed", safeCode(writeErr))
		} else {
			t.finish(entry, protocol.TaskStateFailed, "write_not_started", safeCode(writeErr), "no", &after)
		}
		return
	}
	t.finish(entry, protocol.TaskStateOutcomeUnknown, "external_or_partial_change", "registry value changed unexpectedly", "maybe", &after)
}

func (t *taskRuntime) handleVerificationFailure(ctx context.Context, entry *TaskJournalEntry, params *protocol.InstallLicenseParameters, before, after InstallSnapshot, verifyErr error) {
	if normalizedEqual(after.CurrentSerial, params.Serial) {
		// Our value is still present. Restore the original only if the current
		// value is still ours; never overwrite an external update.
		restoreSource := before
		restoreSource.CurrentSerial = before.CurrentSerial
		if err := t.executor.Restore(restoreSource); err != nil {
			t.finish(entry, protocol.TaskStateOutcomeUnknown, "restore_failed", "verification failed and rollback could not be proven", "maybe", &after)
			return
		}
		restored, _, _ := t.executor.Verify(before.CurrentSerial, params.Pool)
		restoredOK := (!before.OriginalPresent && restored.CurrentSerial == "") ||
			(before.OriginalPresent && normalizedEqual(restored.CurrentSerial, before.CurrentSerial))
		if restoredOK {
			t.finish(entry, protocol.TaskStateFailed, "restore_verified", "license did not verify; original value was restored", "no", &restored)
			return
		}
		t.finish(entry, protocol.TaskStateOutcomeUnknown, "restore_unverified", "rollback could not be verified", "maybe", &restored)
		return
	}
	if normalizedEqual(after.CurrentSerial, before.CurrentSerial) {
		if entry.AttemptCount < protocol.TaskMaxAttempts {
			t.retry(entry, "verification_failed", "verification did not observe the assigned license")
			return
		}
		t.finish(entry, protocol.TaskStateFailed, "verification_failed", safeCode(verifyErr), "no", &after)
		return
	}
	t.finish(entry, protocol.TaskStateOutcomeUnknown, "external_change", "license value was changed by another actor", "maybe", &after)
}

func (t *taskRuntime) reconcile(ctx context.Context, entry *TaskJournalEntry) {
	delivery := t.currentDelivery(entry)
	if delivery == nil {
		return
	}
	if entry.Kind == protocol.TaskKindScan {
		t.executeScan(ctx, entry)
		return
	}
	params, err := t.decryptInstallParameters(*delivery)
	if err != nil {
		t.finish(entry, protocol.TaskStateOutcomeUnknown, "reconcile_parameters_invalid", safeCode(err), "maybe", nil)
		return
	}
	t.localMu.Lock()
	defer t.localMu.Unlock()
	snapshot, err := t.executor.Inspect(params.Serial, params.Pool)
	if err != nil {
		t.finish(entry, protocol.TaskStateOutcomeUnknown, "reconcile_failed", safeCode(err), "maybe", nil)
		return
	}
	if snapshot.SerialMatch && snapshot.License.State == "active" && licenseMatches(snapshot.License, params.Pool) {
		t.finish(entry, protocol.TaskStateSucceeded, "reconciled_installed", "read-only check found the assigned license installed", "no", &snapshot)
		return
	}
	// Read-only evidence cannot prove that a key was never applied earlier.
	// Keep the reservation and require an explicit administrator decision.
	t.finish(entry, protocol.TaskStateOutcomeUnknown, "reconcile_not_installed", "read-only check did not find the assigned license", "maybe", &snapshot)
}

func (t *taskRuntime) handleClaimDenied(entry *TaskJournalEntry, claim protocol.TaskClaimResponse) {
	switch claim.ReasonCode {
	case "retry_not_due":
		t.setRetry(entry, 30*time.Second)
	case "cancel_requested":
		entry.State = protocol.TaskStateCancelled
		entry.ReasonCode = "cancel_requested"
		_ = t.journal.save()
		t.sendResult(context.Background(), entry, protocol.TaskResult{
			ItemID: entry.ItemID, DeliveryVersion: entry.DeliveryVersion, State: protocol.TaskStateCancelled,
			ReasonCode: "cancel_requested", Modified: "no", ResultVersion: t.nextResultVersion(entry),
		}, false)
	case "cancel_requested_after_started":
		entry.State = protocol.TaskStateOutcomeUnknown
		entry.ReasonCode = "cancel_after_started"
		entry.ReadOnlyOnly = true
		_ = t.journal.save()
		t.reconcile(context.Background(), entry)
	case "reconcile_required":
		entry.State = protocol.TaskStateOutcomeUnknown
		_ = t.journal.save()
		t.reconcile(context.Background(), entry)
	case "attempt_limit":
		entry.State = protocol.TaskStateOutcomeUnknown
		entry.ReasonCode = "attempts_exhausted"
		_ = t.journal.save()
		t.sendResult(context.Background(), entry, protocol.TaskResult{
			ItemID: entry.ItemID, DeliveryVersion: entry.DeliveryVersion, State: protocol.TaskStateOutcomeUnknown,
			ReasonCode: "attempts_exhausted", Modified: "maybe", AttemptNo: entry.AttemptCount,
			ResultVersion: t.nextResultVersion(entry),
		}, false)
	case "task_expired":
		entry.State = protocol.TaskStateExpired
		_ = t.journal.save()
		t.sendResult(context.Background(), entry, protocol.TaskResult{
			ItemID: entry.ItemID, DeliveryVersion: entry.DeliveryVersion, State: protocol.TaskStateExpired,
			ReasonCode: "task_expired", Modified: "no", ResultVersion: t.nextResultVersion(entry),
		}, false)
	default:
		t.setRetry(entry, 30*time.Second)
	}
}

func (t *taskRuntime) retry(entry *TaskJournalEntry, reason, message string) {
	delay := protocol.TaskRetryDelayFirstSecond
	if entry.AttemptCount >= 2 {
		delay = protocol.TaskRetryDelaySecondSecond
	}
	entry.State = protocol.TaskStateRetryWait
	entry.ReasonCode = reason
	entry.NextAttemptAt = time.Now().UTC().Add(time.Duration(delay) * time.Second).Format(time.RFC3339Nano)
	_ = t.journal.save()
	t.sendResult(context.Background(), entry, protocol.TaskResult{
		ItemID: entry.ItemID, DeliveryVersion: entry.DeliveryVersion, State: protocol.TaskStateRetryWait,
		ReasonCode: reason, Message: truncateMessage(message), Modified: "no", AttemptNo: entry.AttemptCount,
		ResultVersion: t.nextResultVersion(entry),
	}, false)
}

func (t *taskRuntime) finish(entry *TaskJournalEntry, state, reason, message, modified string, snapshot *InstallSnapshot) {
	result := protocol.TaskResult{
		ItemID: entry.ItemID, DeliveryVersion: entry.DeliveryVersion, State: state,
		ReasonCode: reason, Message: truncateMessage(message), Modified: modified,
		AttemptNo: entry.AttemptCount, ResultVersion: t.nextResultVersion(entry),
	}
	if snapshot != nil {
		result.SerialMatch = snapshot.SerialMatch
		result.License = protocol.TaskLicenseState{
			Present: snapshot.Present, Complete: true, ProductVersion: snapshot.ProductVersion,
			Environment: snapshot.Environment, Kind: snapshot.License.Kind, KindRaw: snapshot.License.KindRaw,
			State: snapshot.License.State, TermKind: snapshot.License.TermKind, IsTrial: snapshot.License.IsTrial,
			ValidToRaw: snapshot.License.ValidToRaw, ValidToUTC: snapshot.License.ValidToUTC,
			TimeBasis: snapshot.License.TimeBasis, Source: snapshot.License.Source, ErrorCode: "",
		}
	}
	entry.State, entry.ReasonCode = state, reason
	if err := t.journal.Complete(entry, &result); err != nil {
		t.logger.Logf("task result not sent: journal persist failed item_id=%s code=journal_write_failed", entry.ItemID)
		entry.NextAttemptAt = time.Now().UTC().Add(30 * time.Second).Format(time.RFC3339Nano)
		_ = t.journal.save()
		return
	}
	t.sendResult(context.Background(), entry, result, true)
}

func (t *taskRuntime) finishUnknownOrFailed(entry *TaskJournalEntry, snapshot InstallSnapshot, err error, reason string) {
	modified := "no"
	state := protocol.TaskStateFailed
	if snapshot.Present {
		// A readable CSP that could not be classified is uncertainty, not a
		// definite failure.
		state = protocol.TaskStateOutcomeUnknown
		modified = "maybe"
	}
	t.finish(entry, state, reason, safeCode(err), modified, &snapshot)
}

func (t *taskRuntime) nextResultVersion(entry *TaskJournalEntry) int {
	entry.ResultVersion++
	if entry.ResultVersion < 1 {
		entry.ResultVersion = 1
	}
	return entry.ResultVersion
}

func (t *taskRuntime) sendResult(ctx context.Context, entry *TaskJournalEntry, result protocol.TaskResult, alreadyPersisted bool) {
	if !alreadyPersisted {
		if err := t.journal.Complete(entry, &result); err != nil {
			t.logger.Logf("task result not sent: journal persist failed item_id=%s code=journal_write_failed", entry.ItemID)
			return
		}
	}
	if result.ResultVersion <= 0 {
		result.ResultVersion = t.nextResultVersion(entry)
		if err := t.journal.Complete(entry, &result); err != nil {
			t.logger.Logf("task result not sent: journal version persist failed item_id=%s", entry.ItemID)
			return
		}
	}
	response, httpResult := t.runtime.client.taskResult(ctx, t.identity(), result, agentOSVersion())
	if httpResult.Error != nil {
		switch httpResult.Error.Code {
		case "network_error", protocol.CodeDatabase, protocol.CodeInternal:
			t.logEvent("result_persisted", entry.TaskID, entry.ItemID, entry.AttemptCount, httpResult.Error.Code)
			return
		case protocol.CodeTaskConflict, protocol.CodeTaskNotFound:
			t.logEvent("result_acknowledged", entry.TaskID, entry.ItemID, entry.AttemptCount, "resolved_by_server")
			_ = t.journal.Acknowledge(entry.ItemID)
			return
		default:
			t.logEvent("result_persisted", entry.TaskID, entry.ItemID, entry.AttemptCount, httpResult.Error.Code)
			return
		}
	}
	if response.Accepted {
		t.logEvent("result_acknowledged", entry.TaskID, entry.ItemID, entry.AttemptCount, response.State)
		_ = t.journal.Acknowledge(entry.ItemID)
	}
}

func (t *taskRuntime) progress(ctx context.Context, entry *TaskJournalEntry, eventType, eventCode, windowsError string, durationMs int64, duration time.Duration) {
	if duration.Milliseconds() > 0 {
		durationMs = duration.Milliseconds()
	}
	event := protocol.TaskProgressEvent{
		ItemID: entry.ItemID, AttemptNo: entry.AttemptCount, EventType: eventType, Stage: eventType,
		EventCode: eventCode, WindowsError: windowsError, DurationMillis: durationMs,
		OccurredAt: time.Now().UTC().Format(time.RFC3339Nano), DeliveryVersion: entry.DeliveryVersion,
	}
	t.runtime.client.taskProgress(ctx, t.identity(), event, agentOSVersion())
}

func (t *taskRuntime) setRetry(entry *TaskJournalEntry, delay time.Duration) {
	entry.NextAttemptAt = time.Now().UTC().Add(delay).Format(time.RFC3339Nano)
	_ = t.journal.save()
}

func (t *taskRuntime) currentDelivery(entry *TaskJournalEntry) *protocol.TaskItemDelivery {
	if entry == nil {
		return nil
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	delivery, ok := t.deliveries[entry.ItemID]
	if !ok {
		return nil
	}
	return &delivery
}

// decryptInstallParameters rebuilds the exact AAD from public delivery fields
// and decrypts the dedicated RSA envelope. It intentionally never logs
// plaintext parameters.
func (t *taskRuntime) decryptInstallParameters(delivery protocol.TaskItemDelivery) (*protocol.InstallLicenseParameters, error) {
	binding := protocol.TaskBinding{
		Protocol: protocol.TaskBindingProtocol, Purpose: "task_item_parameters",
		TaskID: delivery.TaskID, ItemID: delivery.ItemID, MachineID: delivery.MachineID,
		RegistrationID: delivery.RegistrationID, Kind: delivery.Kind,
		ParametersVersion: delivery.ParametersVersion, RecipientKeyID: delivery.ParametersEnvelope.RecipientKeyID,
		ExpiresAt: delivery.ExpiresAt,
	}
	key := t.encryption.Key(delivery.ParametersEnvelope.RecipientKeyID)
	if key == nil {
		return nil, errors.New("encryption key is not available")
	}
	plain, err := protocol.OpenTaskParameters(key, binding, delivery.ParametersEnvelope)
	if err != nil {
		return nil, err
	}
	kind, _, install, err := protocol.DecodeTaskParameters(plain)
	if err != nil {
		return nil, err
	}
	if kind != protocol.TaskKindInstallLicense || install == nil {
		return nil, errors.New("delivery is not an install_license item")
	}
	return install, nil
}

func licenseMatches(info protocol.LicenseInfo, pool protocol.LicensePoolSpec) bool {
	if info.State != "active" || info.Kind != pool.LicenseKind {
		return false
	}
	switch pool.Term {
	case protocol.PoolTermPerpetual:
		return info.TermKind == "perpetual"
	case protocol.PoolTermOneYear, protocol.PoolTermTwoYears:
		return info.TermKind == "time_limited"
	}
	return false
}

func fingerprintSerial(serial string) string {
	normalized := protocol.NormalizeSerial(serial)
	sum := sha256.Sum256([]byte(normalized))
	return hex.EncodeToString(sum[:])
}

func normalizedEqual(a, b string) bool {
	if a == "" && b == "" {
		return true
	}
	return protocol.NormalizeSerial(a) == protocol.NormalizeSerial(b)
}

func truncateMessage(value string) string {
	if len(value) <= protocol.MaxErrorBytes {
		return value
	}
	return value[:protocol.MaxErrorBytes]
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func agentVersion() string {
	return version.String()
}

// reportAccepted is called by the queue delivery path after the server accepts
// a report. It completes the linked scan task item without touching the
// two-report queue again.
func (t *taskRuntime) reportAccepted(reportID string, itemIDs []string) {
	for _, itemID := range itemIDs {
		entry, ok := t.journal.Entry(itemID)
		if !ok {
			continue
		}
		if entry.ReportID != "" && entry.ReportID != reportID {
			continue
		}
		entry.ReportID = reportID
		entry.State = protocol.TaskStateSucceeded
		_ = t.journal.save()
		t.sendResult(context.Background(), entry, protocol.TaskResult{
			ItemID: entry.ItemID, DeliveryVersion: entry.DeliveryVersion, State: protocol.TaskStateSucceeded,
			ReportID: reportID, Modified: "no", ResultVersion: t.nextResultVersion(entry),
		}, false)
	}
}

func (t *taskRuntime) reportEvicted(reportID string) {
	for _, entry := range t.journal.Entries {
		if entry.ReportID == reportID && entry.State != protocol.TaskStateSucceeded {
			t.finish(entry, protocol.TaskStateFailed, "report_evicted", "report was evicted from the two-item queue before delivery", "no", nil)
		}
	}
}

func (t *taskRuntime) reportRejected(reportID string, reason string) {
	for _, entry := range t.journal.Entries {
		if entry.ReportID == reportID && entry.State != protocol.TaskStateSucceeded {
			t.finish(entry, protocol.TaskStateFailed, "report_rejected", reason, "no", nil)
		}
	}
}

func (t *taskRuntime) encodedQueueStatus() json.RawMessage {
	raw, _ := json.Marshal(protocol.TaskQueueStatus{JournalCorrupt: t.journal.Corrupt()})
	return raw
}
