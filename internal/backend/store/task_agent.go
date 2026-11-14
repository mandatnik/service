package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	mssql "github.com/microsoft/go-mssqldb"
	"telehack2026/internal/backend/licensecrypto"
	"telehack2026/internal/protocol"
)

type agentTaskRow struct {
	ItemID          string
	TaskID          string
	MachineID       string
	RegistrationID  int64
	Kind            string
	State           string
	ReasonCode      string
	DeliveryVersion int
	EncryptionKeyID string
	EncryptedParams []byte
	LicenseID       string
	LicenseMask     string
	LicenseState    string
	AttemptCount    int
	NextAttemptAt   *time.Time
	StartedAt       *time.Time
	CompletedAt     *time.Time
	ResultVersion   int
	ScanReportID    string
	AllowTrial      bool
	TaskExpiresAt   time.Time
	TaskCancelAt    *time.Time
	ItemCancelAt    *time.Time
	ReconcileAt     *time.Time
	LegacyJobID     string
	PoolID          string
	PoolCSP         int
	PoolKind        string
	PoolTerm        string
}

func (s *Store) loadAgentTaskRowTx(ctx context.Context, tx *sql.Tx, itemID string, lock bool) (*agentTaskRow, *protocol.APIError) {
	lockHint := ""
	if lock {
		lockHint = " WITH (UPDLOCK,HOLDLOCK)"
	}
	var row agentTaskRow
	var itemIDValue, taskIDValue, machineIDValue mssql.UniqueIdentifier
	var license, legacy, scanReport, poolID mssql.NullUniqueIdentifier
	var encrypted []byte
	var reason, keyID, mask, licenseState, poolKind, poolTerm sql.NullString
	var poolCSP sql.NullInt64
	var next, started, completed, taskCancel, itemCancel, reconcile sql.NullTime
	var resultVersion sql.NullInt64
	err := tx.QueryRowContext(ctx, `
SELECT ti.item_id,ti.task_id,ti.machine_id,ti.registration_id,ti.kind,ti.state,COALESCE(ti.reason_code,''),
       ti.delivery_version,COALESCE(ti.encryption_key_id,''),ti.encrypted_parameters,ti.license_id,COALESCE(l.serial_mask,''),
       COALESCE(l.state,''),ti.attempt_count,ti.next_attempt_at,ti.started_at,ti.completed_at,ti.result_version,
       ti.scan_report_id,ti.allow_trial_replacement,t.expires_at,t.cancel_requested_at,ti.cancel_requested_at,
       ti.reconcile_requested_at,ti.legacy_job_id,l.pool_id,p.csp_major_version,p.license_kind,p.term
FROM dbo.task_items ti`+lockHint+`
JOIN dbo.tasks t ON t.task_id=ti.task_id
LEFT JOIN dbo.licenses l ON l.license_id=ti.license_id
LEFT JOIN dbo.license_pools p ON p.pool_id=l.pool_id
WHERE ti.item_id=@p1`, itemID).Scan(
		&itemIDValue, &taskIDValue, &machineIDValue, &row.RegistrationID, &row.Kind, &row.State, &reason,
		&row.DeliveryVersion, &keyID, &encrypted, &license, &mask, &licenseState, &row.AttemptCount,
		&next, &started, &completed, &resultVersion, &scanReport, &row.AllowTrial, &row.TaskExpiresAt,
		&taskCancel, &itemCancel, &reconcile, &legacy, &poolID, &poolCSP, &poolKind, &poolTerm)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, &protocol.APIError{Code: protocol.CodeTaskNotFound, Message: "task item not found"}
	}
	if err != nil {
		return nil, &protocol.APIError{Code: protocol.CodeDatabase, Message: "load task item"}
	}
	row.ItemID = uuidString(itemIDValue)
	row.TaskID = uuidString(taskIDValue)
	row.MachineID = uuidString(machineIDValue)
	row.ReasonCode = nullString(reason)
	row.EncryptionKeyID = nullString(keyID)
	row.EncryptedParams = encrypted
	row.LicenseID = nullUUIDString(license)
	row.LicenseMask = nullString(mask)
	row.LicenseState = nullString(licenseState)
	row.NextAttemptAt = nullTime(next)
	row.StartedAt = nullTime(started)
	row.CompletedAt = nullTime(completed)
	row.ScanReportID = nullUUIDString(scanReport)
	row.LegacyJobID = nullUUIDString(legacy)
	row.PoolID = nullUUIDString(poolID)
	row.PoolCSP = int(poolCSP.Int64)
	row.PoolKind = nullString(poolKind)
	row.PoolTerm = nullString(poolTerm)
	if resultVersion.Valid {
		row.ResultVersion = int(resultVersion.Int64)
	}
	if taskCancel.Valid {
		value := taskCancel.Time.UTC()
		row.TaskCancelAt = &value
	}
	if itemCancel.Valid {
		value := itemCancel.Time.UTC()
		row.ItemCancelAt = &value
	}
	if reconcile.Valid {
		value := reconcile.Time.UTC()
		row.ReconcileAt = &value
	}
	return &row, nil
}

// SyncAgentTasks delivers durable item metadata and reissues encrypted
// envelopes only for items that demonstrably have not started.
func (s *Store) SyncAgentTasks(ctx context.Context, identity *Identity) (*protocol.TaskSyncResponse, *protocol.APIError) {
	now := s.now()
	if apiErr := s.ExpireDueTasks(ctx); apiErr != nil {
		return nil, apiErr
	}
	rows, err := s.DB.QueryContext(ctx, `
SELECT ti.item_id FROM dbo.task_items ti
WHERE ti.machine_id=@p1 AND ti.registration_id=@p2 AND ti.state IN (N'queued',N'delivered',N'running',N'retry_wait',N'outcome_unknown')
ORDER BY ti.created_at,ti.item_id`, identity.MachineID, identity.RegistrationID)
	if err != nil {
		return nil, &protocol.APIError{Code: protocol.CodeDatabase, Message: "list agent task items"}
	}
	var ids []string
	for rows.Next() {
		var id mssql.UniqueIdentifier
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return nil, &protocol.APIError{Code: protocol.CodeDatabase, Message: "decode agent task item"}
		}
		ids = append(ids, uuidString(id))
	}
	rows.Close()
	response := &protocol.TaskSyncResponse{ServerTime: protocol.FormatTaskTime(now), Items: []protocol.TaskItemDelivery{}}
	for _, itemID := range ids {
		delivery, warning, apiErr := s.prepareAgentDelivery(ctx, identity, itemID, now)
		if apiErr != nil {
			return nil, apiErr
		}
		if warning != "" {
			response.Warnings = append(response.Warnings, warning)
		}
		if delivery != nil {
			response.Items = append(response.Items, *delivery)
		}
	}
	return response, nil
}

func (s *Store) prepareAgentDelivery(ctx context.Context, identity *Identity, itemID string, now time.Time) (*protocol.TaskItemDelivery, string, *protocol.APIError) {
	tx, err := s.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return nil, "", &protocol.APIError{Code: protocol.CodeDatabase, Message: "begin task delivery"}
	}
	defer tx.Rollback()
	row, apiErr := s.loadAgentTaskRowTx(ctx, tx, itemID, true)
	if apiErr != nil {
		return nil, "", apiErr
	}
	if row.MachineID != identity.MachineID || row.RegistrationID != identity.RegistrationID {
		return nil, "", &protocol.APIError{Code: protocol.CodeTaskNotFound, Message: "task item belongs to another installation"}
	}
	if protocol.IsTerminalTaskState(row.State) {
		return nil, "", nil
	}
	if !now.Before(row.TaskExpiresAt) {
		if row.StartedAt == nil && (row.State == protocol.TaskStateQueued || row.State == protocol.TaskStateDelivered) {
			if apiErr := s.expireItemTx(ctx, tx, row, now); apiErr != nil {
				return nil, "", apiErr
			}
			return nil, "", commitAPIError(tx.Commit())
		}
	}
	key, apiErr := s.activeAgentKey(ctx, tx, identity.MachineID)
	if apiErr != nil && apiErr.Code != protocol.CodeAgentKeyUnavailable {
		return nil, "", apiErr
	}
	if row.EncryptedParams == nil || (key != nil && row.EncryptionKeyID != key.KeyID && row.StartedAt == nil &&
		(row.State == protocol.TaskStateQueued || row.State == protocol.TaskStateDelivered || row.State == protocol.TaskStateRetryWait)) {
		if key == nil {
			return nil, "agent_encryption_key_missing", commitAPIError(tx.Commit())
		}
		apiErr := s.reissueEnvelopeTx(ctx, tx, row, key, now)
		if apiErr != nil {
			return nil, "", apiErr
		}
		if fresh, apiErr := s.loadAgentTaskRowTx(ctx, tx, itemID, false); apiErr == nil {
			row = fresh
		}
	}
	if row.EncryptedParams == nil {
		return nil, "task_parameters_unavailable", commitAPIError(tx.Commit())
	}
	envelope, err := protocol.DecodeEncryptedParameters(row.EncryptedParams)
	if err != nil {
		return nil, "task_parameters_corrupted", commitAPIError(tx.Commit())
	}
	if row.EncryptionKeyID == "" {
		row.EncryptionKeyID = envelope.RecipientKeyID
	}
	delivery := &protocol.TaskItemDelivery{
		TaskID: row.TaskID, ItemID: row.ItemID, MachineID: row.MachineID, RegistrationID: row.RegistrationID,
		Kind: row.Kind, State: row.State, DeliveryVersion: row.DeliveryVersion,
		EncryptionKeyID: row.EncryptionKeyID, ParametersVersion: protocol.ParametersVersionV1,
		ParametersEnvelope: envelope, CreatedAt: row.TaskExpiresAt.Add(-time.Duration(protocol.DefaultTaskTTLSeconds) * time.Second).UTC().Format(time.RFC3339Nano),
		ExpiresAt:          protocol.FormatTaskTime(row.TaskExpiresAt),
		CancelRequested:    row.TaskCancelAt != nil || row.ItemCancelAt != nil,
		ReconcileRequested: row.ReconcileAt != nil, AttemptCount: row.AttemptCount, LicenseID: row.LicenseID,
	}
	if err := tx.Commit(); err != nil {
		return nil, "", &protocol.APIError{Code: protocol.CodeDatabase, Message: "commit task delivery"}
	}
	return delivery, "", nil
}

func (s *Store) activeAgentKey(ctx context.Context, tx *sql.Tx, machineID string) (*agentKey, *protocol.APIError) {
	var key agentKey
	var keyID string
	err := tx.QueryRowContext(ctx, `
SELECT r.registration_id,k.key_id,k.public_key_pem
FROM dbo.registrations r
JOIN dbo.agent_encryption_keys k ON k.registration_id=r.registration_id AND k.active=1 AND k.revoked_at IS NULL
WHERE r.machine_id=@p1 AND r.state=N'active'`, machineID).Scan(&key.RegistrationID, &keyID, &key.PublicKeyPEM)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, &protocol.APIError{Code: protocol.CodeAgentKeyUnavailable, Message: "agent has no active encryption key"}
	}
	if err != nil {
		return nil, &protocol.APIError{Code: protocol.CodeDatabase, Message: "load agent encryption key"}
	}
	key.KeyID = keyID
	return &key, nil
}

func (s *Store) reissueEnvelopeTx(ctx context.Context, tx *sql.Tx, row *agentTaskRow, key *agentKey, now time.Time) *protocol.APIError {
	publicKey, err := protocol.ParseTaskPublicKeyPEM(key.PublicKeyPEM)
	if err != nil {
		return &protocol.APIError{Code: protocol.CodeAgentKeyUnavailable, Message: "agent encryption key is invalid"}
	}
	var plaintext []byte
	switch row.Kind {
	case protocol.TaskKindScan:
		plaintext, _ = json.Marshal(protocol.ScanParameters{Kind: protocol.TaskKindScan, Options: protocol.ScanOptions{Force: true}})
	case protocol.TaskKindInstallLicense:
		if row.LicenseID == "" || row.PoolID == "" {
			return &protocol.APIError{Code: protocol.CodeTaskConflict, Message: "install item lost its license reservation"}
		}
		if s.LicenseKeyring == nil {
			return &protocol.APIError{Code: protocol.CodeLicenseUnavailable, Message: "license key material is unavailable"}
		}
		var sealed []byte
		if err := tx.QueryRowContext(ctx, `SELECT encrypted_serial FROM dbo.licenses WHERE license_id=@p1`, row.LicenseID).Scan(&sealed); err != nil {
			return &protocol.APIError{Code: protocol.CodeDatabase, Message: "load reserved license"}
		}
		aad, err := licensecrypto.LicenseAAD(licensecrypto.LicenseBinding{
			LicenseID: row.LicenseID, PoolID: row.PoolID, CSPMajorVersion: row.PoolCSP,
			LicenseKind: row.PoolKind, Term: row.PoolTerm,
		})
		if err != nil {
			return &protocol.APIError{Code: protocol.CodeInternal, Message: "bind license encryption"}
		}
		serial, err := s.LicenseKeyring.Decrypt(sealed, aad)
		if err != nil {
			return &protocol.APIError{Code: protocol.CodeLicenseUnavailable, Message: "decrypt reserved license"}
		}
		plaintext, _ = json.Marshal(protocol.InstallLicenseParameters{
			Kind: protocol.TaskKindInstallLicense, LicenseID: row.LicenseID, Serial: serial,
			Pool:                  protocol.LicensePoolSpec{PoolID: row.PoolID, CSPMajorVersion: row.PoolCSP, LicenseKind: row.PoolKind, Term: row.PoolTerm},
			AllowTrialReplacement: row.AllowTrial,
		})
	default:
		return &protocol.APIError{Code: protocol.CodeTaskConflict, Message: "unknown task kind"}
	}
	binding := protocol.TaskBinding{
		Protocol: protocol.TaskBindingProtocol, Purpose: "task_item_parameters",
		TaskID: row.TaskID, ItemID: row.ItemID, MachineID: row.MachineID, RegistrationID: row.RegistrationID,
		Kind: row.Kind, ParametersVersion: protocol.ParametersVersionV1,
		RecipientKeyID: key.KeyID, ExpiresAt: protocol.FormatTaskTime(row.TaskExpiresAt),
	}
	envelope, err := protocol.SealTaskParameters(publicKey, binding, plaintext)
	if err != nil {
		return &protocol.APIError{Code: protocol.CodeInternal, Message: "encrypt task parameters"}
	}
	encoded, err := protocol.EncodeEncryptedParameters(envelope)
	if err != nil {
		return &protocol.APIError{Code: protocol.CodeInternal, Message: "encode task parameters"}
	}
	version := row.DeliveryVersion + 1
	_, err = tx.ExecContext(ctx, `
UPDATE dbo.task_items SET encryption_key_id=@p1,encrypted_parameters=@p2,delivery_version=@p3,updated_at=@p4
WHERE item_id=@p5`, key.KeyID, encoded, version, now, row.ItemID)
	if err != nil {
		return &protocol.APIError{Code: protocol.CodeDatabase, Message: "update task envelope"}
	}
	row.EncryptionKeyID = key.KeyID
	row.EncryptedParams = encoded
	row.DeliveryVersion = version
	return nil
}

func (s *Store) AckTaskDelivery(ctx context.Context, identity *Identity, itemID string, version int) (*protocol.TaskDeliveryAckResponse, *protocol.APIError) {
	tx, err := s.DB.BeginTx(ctx, &sql.TxOptions{})
	if err != nil {
		return nil, &protocol.APIError{Code: protocol.CodeDatabase, Message: "begin delivery ack"}
	}
	defer tx.Rollback()
	now := s.now()
	row, apiErr := s.loadAgentTaskRowTx(ctx, tx, itemID, true)
	if apiErr != nil {
		return nil, apiErr
	}
	if row.MachineID != identity.MachineID || row.RegistrationID != identity.RegistrationID {
		return nil, &protocol.APIError{Code: protocol.CodeTaskNotFound, Message: "task item belongs to another installation"}
	}
	if version < row.DeliveryVersion {
		return nil, &protocol.APIError{Code: protocol.CodeTaskConflict, Message: "stale delivery version"}
	}
	if version > row.DeliveryVersion {
		return nil, &protocol.APIError{Code: protocol.CodeTaskConflict, Message: "delivery version was not issued"}
	}
	if protocol.IsTerminalTaskState(row.State) {
		return &protocol.TaskDeliveryAckResponse{Accepted: true, ItemID: row.ItemID, State: row.State, Duplicate: true, ServerTime: protocol.FormatTaskTime(now)}, commitAPIError(tx.Commit())
	}
	if row.State == protocol.TaskStateQueued {
		if _, err := tx.ExecContext(ctx, `UPDATE dbo.task_items SET state=N'delivered',last_seen_at=@p1,updated_at=@p1 WHERE item_id=@p2`, now, row.ItemID); err != nil {
			return nil, &protocol.APIError{Code: protocol.CodeDatabase, Message: "mark item delivered"}
		}
		row.State = protocol.TaskStateDelivered
	} else {
		if _, err := tx.ExecContext(ctx, `UPDATE dbo.task_items SET last_seen_at=@p1,updated_at=@p1 WHERE item_id=@p2`, now, row.ItemID); err != nil {
			return nil, &protocol.APIError{Code: protocol.CodeDatabase, Message: "update item activity"}
		}
	}
	if sequence, err := s.nextSequenceTx(ctx, tx, row.ItemID); err == nil {
		_ = insertTaskEventTx(ctx, tx, row.ItemID, sequence, row.AttemptCount, "delivery_acked", map[string]any{"delivery_version": version}, now)
	}
	if err := tx.Commit(); err != nil {
		return nil, &protocol.APIError{Code: protocol.CodeDatabase, Message: "commit delivery ack"}
	}
	return &protocol.TaskDeliveryAckResponse{Accepted: true, ItemID: row.ItemID, State: row.State, ServerTime: protocol.FormatTaskTime(now)}, nil
}

func (s *Store) ClaimTaskItem(ctx context.Context, identity *Identity, itemID string, version int) (*protocol.TaskClaimResponse, *protocol.APIError) {
	tx, err := s.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return nil, &protocol.APIError{Code: protocol.CodeDatabase, Message: "begin task claim"}
	}
	defer tx.Rollback()
	now := s.now()
	row, apiErr := s.loadAgentTaskRowTx(ctx, tx, itemID, true)
	if apiErr != nil {
		return nil, apiErr
	}
	if row.MachineID != identity.MachineID || row.RegistrationID != identity.RegistrationID {
		return nil, &protocol.APIError{Code: protocol.CodeTaskNotFound, Message: "task item belongs to another installation"}
	}
	if version != row.DeliveryVersion {
		return nil, &protocol.APIError{Code: protocol.CodeTaskConflict, Message: "claim must reference the delivered version"}
	}
	deny := func(code, reason string) (*protocol.TaskClaimResponse, *protocol.APIError) {
		_ = tx.Commit()
		return &protocol.TaskClaimResponse{Granted: false, ItemID: row.ItemID, State: row.State, ReasonCode: reason, ServerTime: protocol.FormatTaskTime(now)}, nil
	}
	if protocol.IsTerminalTaskState(row.State) {
		return deny(protocol.CodeTaskClaimDenied, "item_terminal")
	}
	if row.State == protocol.TaskStateOutcomeUnknown {
		return deny(protocol.CodeTaskClaimDenied, "reconcile_required")
	}
	if row.TaskCancelAt != nil || row.ItemCancelAt != nil {
		if row.StartedAt == nil && (row.State == protocol.TaskStateQueued || row.State == protocol.TaskStateDelivered || row.State == protocol.TaskStateRetryWait) {
			if apiErr := s.cancelItemTx(ctx, tx, row, "cancel_requested", now); apiErr != nil {
				return nil, apiErr
			}
			row.State = protocol.TaskStateCancelled
			return deny(protocol.CodeTaskClaimDenied, "cancel_requested")
		}
		return deny(protocol.CodeTaskClaimDenied, "cancel_requested_after_started")
	}
	if !now.Before(row.TaskExpiresAt) {
		if row.StartedAt == nil {
			if apiErr := s.expireItemTx(ctx, tx, row, now); apiErr != nil {
				return nil, apiErr
			}
			row.State = protocol.TaskStateExpired
		}
		return deny(protocol.CodeTaskExpired, "task_expired")
	}
	if row.NextAttemptAt != nil && now.Before(*row.NextAttemptAt) {
		return deny(protocol.CodeTaskClaimDenied, "retry_not_due")
	}
	if row.AttemptCount >= protocol.TaskMaxAttempts {
		return deny(protocol.CodeTaskClaimDenied, "attempt_limit")
	}
	if row.Kind == protocol.TaskKindInstallLicense && row.LicenseID != "" {
		var state string
		err := tx.QueryRowContext(ctx, `SELECT state FROM dbo.licenses WITH (UPDLOCK,HOLDLOCK) WHERE license_id=@p1`, row.LicenseID).Scan(&state)
		if errors.Is(err, sql.ErrNoRows) {
			return deny(protocol.CodeTaskClaimDenied, "license_missing")
		}
		if err != nil {
			return nil, &protocol.APIError{Code: protocol.CodeDatabase, Message: "load reserved license"}
		}
		if state != protocol.LicenseStateReserved && state != protocol.LicenseStateOutcomeUnknown {
			return deny(protocol.CodeTaskClaimDenied, "license_not_reserved")
		}
	}
	claimUntil := now.Add(time.Duration(protocol.TaskClaimTTLSeconds) * time.Second)
	if claimUntil.After(row.TaskExpiresAt) {
		claimUntil = row.TaskExpiresAt
	}
	if !claimUntil.After(now) {
		return deny(protocol.CodeTaskExpired, "task_expired")
	}
	_, err = tx.ExecContext(ctx, `
UPDATE dbo.task_items SET state=N'running',started_at=COALESCE(started_at,@p1),claim_expires_at=@p2,last_seen_at=@p1,updated_at=@p1
WHERE item_id=@p3`, now, claimUntil, row.ItemID)
	if err != nil {
		return nil, &protocol.APIError{Code: protocol.CodeDatabase, Message: "grant task claim"}
	}
	if sequence, err := s.nextSequenceTx(ctx, tx, row.ItemID); err == nil {
		_ = insertTaskEventTx(ctx, tx, row.ItemID, sequence, row.AttemptCount, "start_authorized", map[string]any{"claim_until": protocol.FormatTaskTime(claimUntil)}, now)
	}
	if err := tx.Commit(); err != nil {
		return nil, &protocol.APIError{Code: protocol.CodeDatabase, Message: "commit task claim"}
	}
	return &protocol.TaskClaimResponse{Granted: true, ItemID: row.ItemID, State: protocol.TaskStateRunning,
		ClaimUntil: protocol.FormatTaskTime(claimUntil), ServerTime: protocol.FormatTaskTime(now)}, nil
}

var allowedTaskEvents = map[string]bool{
	"received": true, "decrypted": true, "precheck": true, "start_authorized": true,
	"attempt_intent": true, "write_started": true, "write_finished": true,
	"verification": true, "rollback": true, "retry_scheduled": true, "skipped": true,
	"cancelled": true, "expired": true, "result_persisted": true,
	"result_acknowledged": true, "reconciliation": true, "journal_corrupted": true,
	"delivery_acked": true, "created": true, "result": true,
}

func (s *Store) TaskProgress(ctx context.Context, identity *Identity, event protocol.TaskProgressEvent) *protocol.APIError {
	if err := protocol.ValidateProgressEvent(&event); err != nil {
		return &protocol.APIError{Code: protocol.CodeInvalidJSON, Message: err.Error()}
	}
	event.Stage = redactSerialLike(event.Stage)
	event.EventCode = redactSerialLike(event.EventCode)
	event.WindowsError = redactSerialLike(event.WindowsError)
	if !allowedTaskEvents[event.EventType] {
		return &protocol.APIError{Code: protocol.CodeInvalidJSON, Message: "unsupported task event type"}
	}
	tx, err := s.DB.BeginTx(ctx, &sql.TxOptions{})
	if err != nil {
		return &protocol.APIError{Code: protocol.CodeDatabase, Message: "begin task progress"}
	}
	defer tx.Rollback()
	row, apiErr := s.loadAgentTaskRowTx(ctx, tx, event.ItemID, true)
	if apiErr != nil {
		return apiErr
	}
	if row.MachineID != identity.MachineID || row.RegistrationID != identity.RegistrationID {
		return &protocol.APIError{Code: protocol.CodeTaskNotFound, Message: "task item belongs to another installation"}
	}
	now := s.now()
	if event.EventType == "attempt_intent" {
		if event.AttemptNo < 1 || event.AttemptNo > protocol.TaskMaxAttempts {
			return &protocol.APIError{Code: protocol.CodeTaskConflict, Message: "attempt number exceeds the limit"}
		}
		if event.AttemptNo > row.AttemptCount {
			if _, err := tx.ExecContext(ctx, `UPDATE dbo.task_items SET attempt_count=@p1,last_progress_at=@p2,updated_at=@p2 WHERE item_id=@p3`,
				event.AttemptNo, now, row.ItemID); err != nil {
				return &protocol.APIError{Code: protocol.CodeDatabase, Message: "persist attempt counter"}
			}
		}
	} else {
		if _, err := tx.ExecContext(ctx, `UPDATE dbo.task_items SET last_progress_at=@p1,updated_at=@p1 WHERE item_id=@p2`, now, row.ItemID); err != nil {
			return &protocol.APIError{Code: protocol.CodeDatabase, Message: "update task progress"}
		}
	}
	sequence, err := s.nextSequenceTx(ctx, tx, row.ItemID)
	if err != nil {
		return &protocol.APIError{Code: protocol.CodeDatabase, Message: "reserve event sequence"}
	}
	details := map[string]any{
		"stage": event.Stage, "event_code": event.EventCode, "windows_error": event.WindowsError,
		"duration_ms": event.DurationMillis, "occurred_at": event.OccurredAt,
	}
	if err := insertTaskEventTx(ctx, tx, row.ItemID, sequence, event.AttemptNo, event.EventType, details, now); err != nil {
		return &protocol.APIError{Code: protocol.CodeDatabase, Message: "record task progress"}
	}
	if err := tx.Commit(); err != nil {
		return &protocol.APIError{Code: protocol.CodeDatabase, Message: "commit task progress"}
	}
	return nil
}

func (s *Store) SubmitTaskResult(ctx context.Context, identity *Identity, result *protocol.TaskResult) (*protocol.TaskResultResponse, *protocol.APIError) {
	if err := protocol.ValidateTaskResult(result); err != nil {
		return nil, &protocol.APIError{Code: protocol.CodeInvalidJSON, Message: err.Error()}
	}
	result.Message = redactSerialLike(result.Message)
	tx, err := s.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return nil, &protocol.APIError{Code: protocol.CodeDatabase, Message: "begin task result"}
	}
	defer tx.Rollback()
	now := s.now()
	row, apiErr := s.loadAgentTaskRowTx(ctx, tx, result.ItemID, true)
	if apiErr != nil {
		return nil, apiErr
	}
	if row.MachineID != identity.MachineID || row.RegistrationID != identity.RegistrationID {
		return nil, &protocol.APIError{Code: protocol.CodeTaskNotFound, Message: "task item belongs to another installation"}
	}
	if result.DeliveryVersion < row.DeliveryVersion {
		return nil, &protocol.APIError{Code: protocol.CodeTaskConflict, Message: "result references a stale delivery version"}
	}
	if result.DeliveryVersion > row.DeliveryVersion {
		return nil, &protocol.APIError{Code: protocol.CodeTaskConflict, Message: "result references an unknown delivery version"}
	}
	if result.ResultVersion <= row.ResultVersion {
		if row.State == result.State || protocol.IsTerminalTaskState(row.State) {
			return &protocol.TaskResultResponse{Accepted: true, ItemID: row.ItemID, State: row.State, Duplicate: true, ServerTime: protocol.FormatTaskTime(now)}, commitAPIError(tx.Commit())
		}
		return nil, &protocol.APIError{Code: protocol.CodeTaskConflict, Message: "result version is stale"}
	}
	if protocol.IsTerminalTaskState(row.State) {
		if row.State == result.State {
			return &protocol.TaskResultResponse{Accepted: true, ItemID: row.ItemID, State: row.State, Duplicate: true, ServerTime: protocol.FormatTaskTime(now)}, commitAPIError(tx.Commit())
		}
		// A final success must not be overwritten by a late negative event.
		return nil, &protocol.APIError{Code: protocol.CodeTaskConflict, Message: "item already has a terminal result"}
	}
	if result.AttemptNo > row.AttemptCount {
		if _, err := tx.ExecContext(ctx, `UPDATE dbo.task_items SET attempt_count=@p1,updated_at=@p2 WHERE item_id=@p3`,
			result.AttemptNo, now, row.ItemID); err != nil {
			return nil, &protocol.APIError{Code: protocol.CodeDatabase, Message: "persist final attempt counter"}
		}
		row.AttemptCount = result.AttemptNo
	}

	nextState := result.State
	reason := result.ReasonCode
	if nextState == protocol.TaskStateSucceeded {
		if row.Kind == protocol.TaskKindScan {
			if result.ReportID == "" {
				return nil, &protocol.APIError{Code: protocol.CodeReportRequired, Message: "scan success requires an accepted report_id"}
			}
			var reportMachine mssql.UniqueIdentifier
			err := tx.QueryRowContext(ctx, `SELECT machine_id FROM dbo.reports WHERE report_id=@p1`, result.ReportID).Scan(&reportMachine)
			if errors.Is(err, sql.ErrNoRows) {
				return nil, &protocol.APIError{Code: protocol.CodeReportRequired, Message: "scan report was not accepted"}
			}
			if err != nil {
				return nil, &protocol.APIError{Code: protocol.CodeDatabase, Message: "load scan report"}
			}
			if uuidString(reportMachine) != row.MachineID {
				return nil, &protocol.APIError{Code: protocol.CodeReportInvalid, Message: "scan report belongs to another machine"}
			}
			if _, err := tx.ExecContext(ctx, `UPDATE dbo.task_items SET scan_report_id=@p1 WHERE item_id=@p2`, result.ReportID, row.ItemID); err != nil {
				return nil, &protocol.APIError{Code: protocol.CodeDatabase, Message: "link scan report"}
			}
		} else {
			if !result.SerialMatch || result.License.State != "active" {
				return nil, &protocol.APIError{Code: protocol.CodeSerialProofRequired, Message: "success requires a verified active assigned license"}
			}
			if result.License.Kind != row.PoolKind {
				return nil, &protocol.APIError{Code: protocol.CodeSerialProofRequired, Message: "installed license kind does not match the pool"}
			}
			if !termMatches(row.PoolTerm, result.License.TermKind) {
				return nil, &protocol.APIError{Code: protocol.CodeSerialProofRequired, Message: "installed license term does not match the pool"}
			}
			if row.LicenseID == "" {
				return nil, &protocol.APIError{Code: protocol.CodeTaskConflict, Message: "item has no reserved license"}
			}
			if apiErr := s.markLicenseUsedTx(ctx, tx, row.LicenseID, row.ItemID, row.MachineID, result, now); apiErr != nil {
				return nil, apiErr
			}
			nextState = protocol.TaskStateSucceeded
		}
	}

	completed := protocol.IsTerminalTaskState(nextState)
	var completedAt any
	if completed {
		completedAt = now
	}
	reasonValue := any(nil)
	if reason != "" {
		reasonValue = reason
	}
	sanitized, _ := json.Marshal(result)
	_, err = tx.ExecContext(ctx, `
UPDATE dbo.task_items SET state=@p1,reason_code=@p2,result_version=@p3,sanitized_result=@p4,
 completed_at=@p5,last_seen_at=@p6,updated_at=@p6,
 cancel_requested_at=CASE WHEN @p1 IN (N'succeeded',N'skipped') THEN cancel_requested_at ELSE cancel_requested_at END
WHERE item_id=@p7`, nextState, reasonValue, result.ResultVersion, string(sanitized), completedAt, now, row.ItemID)
	if err != nil {
		return nil, &protocol.APIError{Code: protocol.CodeDatabase, Message: "store task result"}
	}

	switch nextState {
	case protocol.TaskStateRetryWait:
		if result.AttemptNo < 1 || result.AttemptNo >= protocol.TaskMaxAttempts {
			return nil, &protocol.APIError{Code: protocol.CodeTaskConflict, Message: "retry attempt number is out of range"}
		}
		delay := protocol.TaskRetryDelayFirstSecond
		if result.AttemptNo >= 2 {
			delay = protocol.TaskRetryDelaySecondSecond
		}
		next := now.Add(time.Duration(delay) * time.Second)
		if _, err := tx.ExecContext(ctx, `UPDATE dbo.task_items SET next_attempt_at=@p1,attempt_count=@p2 WHERE item_id=@p3`,
			next, result.AttemptNo, row.ItemID); err != nil {
			return nil, &protocol.APIError{Code: protocol.CodeDatabase, Message: "schedule retry"}
		}
	case protocol.TaskStateSkipped:
		if result.Modified == "no" {
			_ = s.releaseLicenseTx(ctx, tx, row, "skipped_no_change", now)
		}
	case protocol.TaskStateFailed:
		if isInvalidSerialReason(result.ReasonCode) {
			_ = s.blockLicenseTx(ctx, tx, row, result.ReasonCode, now)
		} else if result.Modified == "no" && safeReleaseReason(result.ReasonCode) {
			_ = s.releaseLicenseTx(ctx, tx, row, result.ReasonCode, now)
		} else if result.Modified == "yes" || result.Modified == "maybe" || row.StartedAt != nil {
			nextState = protocol.TaskStateOutcomeUnknown
			_ = s.markLicenseUnknownTx(ctx, tx, row, result.ReasonCode, now)
		} else {
			_ = s.releaseLicenseTx(ctx, tx, row, result.ReasonCode, now)
		}
	case protocol.TaskStateOutcomeUnknown:
		_ = s.markLicenseUnknownTx(ctx, tx, row, result.ReasonCode, now)
	case protocol.TaskStateCancelled:
		if result.Modified == "no" && row.StartedAt == nil {
			_ = s.releaseLicenseTx(ctx, tx, row, "cancelled_no_change", now)
		} else if result.Modified == "no" {
			nextState = protocol.TaskStateOutcomeUnknown
			_ = s.markLicenseUnknownTx(ctx, tx, row, "cancel_after_started", now)
		} else {
			nextState = protocol.TaskStateOutcomeUnknown
			_ = s.markLicenseUnknownTx(ctx, tx, row, "cancel_after_possible_change", now)
		}
	case protocol.TaskStateExpired:
		if result.Modified == "no" && row.StartedAt == nil {
			_ = s.releaseLicenseTx(ctx, tx, row, "expired_no_change", now)
		} else if result.Modified == "no" {
			nextState = protocol.TaskStateOutcomeUnknown
			_ = s.markLicenseUnknownTx(ctx, tx, row, "expired_after_started", now)
		} else {
			nextState = protocol.TaskStateOutcomeUnknown
			_ = s.markLicenseUnknownTx(ctx, tx, row, "expired_after_possible_change", now)
		}
	}
	if nextState != result.State {
		if _, err := tx.ExecContext(ctx, `UPDATE dbo.task_items SET state=@p1 WHERE item_id=@p2`, nextState, row.ItemID); err != nil {
			return nil, &protocol.APIError{Code: protocol.CodeDatabase, Message: "update final task state"}
		}
	}
	if err := s.updateLegacyJobTx(ctx, tx, row, nextState, result, now); err != nil {
		return nil, &protocol.APIError{Code: protocol.CodeDatabase, Message: "update linked job"}
	}
	sequence, err := s.nextSequenceTx(ctx, tx, row.ItemID)
	if err == nil {
		_ = insertTaskEventTx(ctx, tx, row.ItemID, sequence, result.AttemptNo, "result",
			map[string]any{"state": nextState, "reason_code": result.ReasonCode, "modified": result.Modified, "license_id": row.LicenseID}, now)
	}
	for _, event := range result.SanitizedLog {
		sequence, err := s.nextSequenceTx(ctx, tx, row.ItemID)
		if err != nil {
			break
		}
		details := map[string]any{"stage": event.Stage, "event_code": event.EventCode, "windows_error": event.WindowsError, "duration_ms": event.DurationMillis, "occurred_at": event.OccurredAt}
		_ = insertTaskEventTx(ctx, tx, row.ItemID, sequence, event.AttemptNo, event.EventType, details, now)
	}
	if err := tx.Commit(); err != nil {
		return nil, &protocol.APIError{Code: protocol.CodeDatabase, Message: "commit task result"}
	}
	return &protocol.TaskResultResponse{Accepted: true, ItemID: row.ItemID, State: nextState, ServerTime: protocol.FormatTaskTime(now)}, nil
}

func termMatches(poolTerm, observed string) bool {
	switch poolTerm {
	case protocol.PoolTermPerpetual:
		return observed == "perpetual"
	case protocol.PoolTermOneYear, protocol.PoolTermTwoYears:
		return observed == "time_limited"
	default:
		return false
	}
}

func isInvalidSerialReason(reason string) bool {
	switch reason {
	case "invalid_serial", "license_incompatible", "serial_format_invalid":
		return true
	}
	return false
}

func safeReleaseReason(reason string) bool {
	switch reason {
	case "already_licensed", "trial_replacement_not_confirmed", "precheck_failed", "precheck_not_started",
		"write_not_started", "restore_verified", "invalid_target", "csp_not_installed", "license_kind_mismatch",
		"csp_major_mismatch", "cancelled_before_write", "expired_before_write", "not_checked":
		return true
	}
	return false
}

func (s *Store) markLicenseUsedTx(ctx context.Context, tx *sql.Tx, licenseID, itemID, machineID string, result *protocol.TaskResult, now time.Time) *protocol.APIError {
	resultExec, err := tx.ExecContext(ctx, `
UPDATE dbo.licenses SET state=N'used',used_at=@p1,updated_at=@p1,assigned_task_item_id=@p2,assigned_machine_id=@p3
WHERE license_id=@p4 AND state IN (N'reserved',N'outcome_unknown')`, now, itemID, machineID, licenseID)
	if err != nil {
		return &protocol.APIError{Code: protocol.CodeDatabase, Message: "mark license used"}
	}
	if affected, _ := resultExec.RowsAffected(); affected == 0 {
		var state string
		_ = tx.QueryRowContext(ctx, `SELECT state FROM dbo.licenses WHERE license_id=@p1`, licenseID).Scan(&state)
		if state != protocol.LicenseStateUsed {
			return &protocol.APIError{Code: protocol.CodeTaskConflict, Message: "license is not reserved for this item"}
		}
	}
	_, _ = tx.ExecContext(ctx, `
UPDATE dbo.license_assignments SET state=N'used' WHERE license_id=@p1 AND task_item_id=@p2 AND released_at IS NULL`, licenseID, itemID)
	_, _ = tx.ExecContext(ctx, `
INSERT INTO dbo.license_events(license_id,pool_id,kind,actor,details_json,created_at)
SELECT @p1,pool_id,N'license_used',N'agent',@p2,@p3 FROM dbo.licenses WHERE license_id=@p1`,
		licenseID, string(mustJSON(map[string]any{"task_item_id": itemID, "machine_id": machineID, "license_state": result.License.State, "term_kind": result.License.TermKind})), now)
	return nil
}

func (s *Store) markLicenseUnknownTx(ctx context.Context, tx *sql.Tx, row *agentTaskRow, reason string, now time.Time) *protocol.APIError {
	if row.LicenseID == "" {
		return nil
	}
	_, _ = tx.ExecContext(ctx, `
UPDATE dbo.licenses SET state=CASE WHEN state=N'used' THEN state ELSE N'outcome_unknown' END,
 last_error_code=@p1,updated_at=@p2 WHERE license_id=@p3`, truncate(reason, 128), now, row.LicenseID)
	_, _ = tx.ExecContext(ctx, `
UPDATE dbo.license_assignments SET state=CASE WHEN state=N'used' THEN state ELSE N'outcome_unknown' END
WHERE license_id=@p1 AND task_item_id=@p2 AND released_at IS NULL`, row.LicenseID, row.ItemID)
	_, _ = tx.ExecContext(ctx, `
INSERT INTO dbo.license_events(license_id,pool_id,kind,actor,details_json,created_at)
SELECT @p1,pool_id,N'license_outcome_unknown',N'agent',@p2,@p3 FROM dbo.licenses WHERE license_id=@p1`,
		row.LicenseID, string(mustJSON(map[string]any{"task_item_id": row.ItemID, "reason_code": reason})), now)
	return nil
}

func (s *Store) blockLicenseTx(ctx context.Context, tx *sql.Tx, row *agentTaskRow, reason string, now time.Time) *protocol.APIError {
	if row.LicenseID == "" {
		return nil
	}
	_, _ = tx.ExecContext(ctx, `
UPDATE dbo.licenses SET state=N'blocked',last_error_code=@p1,assigned_machine_id=NULL,assigned_task_item_id=NULL,updated_at=@p2
WHERE license_id=@p3`, truncate(reason, 128), now, row.LicenseID)
	_, _ = tx.ExecContext(ctx, `
UPDATE dbo.license_assignments SET state=N'released',released_at=@p1,released_reason=N'invalid_serial'
WHERE license_id=@p2 AND task_item_id=@p3 AND released_at IS NULL`, now, row.LicenseID, row.ItemID)
	_, _ = tx.ExecContext(ctx, `
INSERT INTO dbo.license_events(license_id,pool_id,kind,actor,details_json,created_at)
SELECT @p1,pool_id,N'license_blocked_by_result',N'agent',@p2,@p3 FROM dbo.licenses WHERE license_id=@p1`,
		row.LicenseID, string(mustJSON(map[string]any{"task_item_id": row.ItemID, "reason_code": reason})), now)
	return nil
}

func (s *Store) releaseLicenseTx(ctx context.Context, tx *sql.Tx, row *agentTaskRow, reason string, now time.Time) *protocol.APIError {
	if row.LicenseID == "" {
		return nil
	}
	result, err := tx.ExecContext(ctx, `
UPDATE dbo.licenses SET state=N'available',assigned_machine_id=NULL,assigned_task_item_id=NULL,reserved_at=NULL,last_error_code=NULL,updated_at=@p1
WHERE license_id=@p2 AND state=N'reserved'`, now, row.LicenseID)
	if err != nil {
		return &protocol.APIError{Code: protocol.CodeDatabase, Message: "release license"}
	}
	if affected, _ := result.RowsAffected(); affected == 0 {
		return nil
	}
	_, _ = tx.ExecContext(ctx, `
UPDATE dbo.license_assignments SET state=N'released',released_at=@p1,released_reason=@p2
WHERE license_id=@p3 AND task_item_id=@p4 AND released_at IS NULL`, now, truncate(reason, 128), row.LicenseID, row.ItemID)
	_, _ = tx.ExecContext(ctx, `
INSERT INTO dbo.license_events(license_id,pool_id,kind,actor,details_json,created_at)
SELECT @p1,pool_id,N'license_released',N'agent',@p2,@p3 FROM dbo.licenses WHERE license_id=@p1`,
		row.LicenseID, string(mustJSON(map[string]any{"task_item_id": row.ItemID, "reason_code": reason})), now)
	return nil
}

func (s *Store) updateLegacyJobTx(ctx context.Context, tx *sql.Tx, row *agentTaskRow, state string, result *protocol.TaskResult, now time.Time) error {
	if row.LegacyJobID == "" {
		return nil
	}
	jobState := "failed"
	switch state {
	case protocol.TaskStateSucceeded:
		jobState = "completed"
	case protocol.TaskStateSkipped:
		jobState = "completed"
	case protocol.TaskStateCancelled:
		jobState = "canceled"
	case protocol.TaskStateExpired:
		jobState = "canceled"
	}
	var report any
	if result.ReportID != "" {
		report = result.ReportID
	}
	_, err := tx.ExecContext(ctx, `
UPDATE dbo.jobs SET state=@p1,completed_at=@p2,acknowledged_at=@p2,report_id=COALESCE(@p3,report_id),message=@p4
WHERE job_id=@p5 AND state IN (N'pending',N'delivered')`,
		jobState, now, report, truncate(result.ReasonCode, 1024), row.LegacyJobID)
	return err
}

func (s *Store) ExpireDueTasks(ctx context.Context) *protocol.APIError {
	rows, err := s.DB.QueryContext(ctx, `SELECT task_id FROM dbo.tasks WHERE expires_at<=@p1`, s.now())
	if err != nil {
		return &protocol.APIError{Code: protocol.CodeDatabase, Message: "list expired tasks"}
	}
	var ids []string
	for rows.Next() {
		var id mssql.UniqueIdentifier
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return &protocol.APIError{Code: protocol.CodeDatabase, Message: "decode expired task"}
		}
		ids = append(ids, uuidString(id))
	}
	rows.Close()
	for _, id := range ids {
		if apiErr := s.expireTask(ctx, id); apiErr != nil {
			return apiErr
		}
	}
	return nil
}

func (s *Store) expireTask(ctx context.Context, taskID string) *protocol.APIError {
	now := s.now()
	tx, err := s.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return &protocol.APIError{Code: protocol.CodeDatabase, Message: "begin task expiry"}
	}
	defer tx.Rollback()
	var expires time.Time
	err = tx.QueryRowContext(ctx, `SELECT expires_at FROM dbo.tasks WITH (UPDLOCK,HOLDLOCK) WHERE task_id=@p1`, taskID).Scan(&expires)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return &protocol.APIError{Code: protocol.CodeDatabase, Message: "load task expiry"}
	}
	if now.Before(expires) {
		return nil
	}
	rows, err := tx.QueryContext(ctx, `
SELECT item_id FROM dbo.task_items WITH (UPDLOCK,HOLDLOCK)
WHERE task_id=@p1 AND state IN (N'queued',N'delivered',N'retry_wait')`, taskID)
	if err != nil {
		return &protocol.APIError{Code: protocol.CodeDatabase, Message: "load expiring items"}
	}
	var itemIDs []string
	for rows.Next() {
		var id mssql.UniqueIdentifier
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return &protocol.APIError{Code: protocol.CodeDatabase, Message: "decode expiring item"}
		}
		itemIDs = append(itemIDs, uuidString(id))
	}
	rows.Close()
	for _, itemID := range itemIDs {
		row, apiErr := s.loadAgentTaskRowTx(ctx, tx, itemID, true)
		if apiErr != nil {
			return apiErr
		}
		if row.StartedAt == nil {
			if apiErr := s.expireItemTx(ctx, tx, row, now); apiErr != nil {
				return apiErr
			}
		}
	}
	return commitAPIError(tx.Commit())
}

func (s *Store) expireItemTx(ctx context.Context, tx *sql.Tx, row *agentTaskRow, now time.Time) *protocol.APIError {
	if _, err := tx.ExecContext(ctx, `
UPDATE dbo.task_items SET state=N'expired',reason_code=N'task_expired',completed_at=@p1,updated_at=@p1
WHERE item_id=@p2`, now, row.ItemID); err != nil {
		return &protocol.APIError{Code: protocol.CodeDatabase, Message: "expire task item"}
	}
	if apiErr := s.releaseLicenseTx(ctx, tx, row, "expired_before_start", now); apiErr != nil {
		return apiErr
	}
	if sequence, err := s.nextSequenceTx(ctx, tx, row.ItemID); err == nil {
		_ = insertTaskEventTx(ctx, tx, row.ItemID, sequence, row.AttemptCount, "expired", map[string]any{"reason_code": "task_expired"}, now)
	}
	_, _ = s.updateLegacyJobTxWithState(ctx, tx, row, "canceled", now)
	return nil
}

func (s *Store) updateLegacyJobTxWithState(ctx context.Context, tx *sql.Tx, row *agentTaskRow, state string, now time.Time) (sql.Result, error) {
	if row.LegacyJobID == "" {
		return nil, nil
	}
	return tx.ExecContext(ctx, `UPDATE dbo.jobs SET state=@p1,completed_at=@p2,acknowledged_at=@p2 WHERE job_id=@p3 AND state IN (N'pending',N'delivered')`,
		state, now, row.LegacyJobID)
}

func (s *Store) cancelItemTx(ctx context.Context, tx *sql.Tx, row *agentTaskRow, reason string, now time.Time) *protocol.APIError {
	if _, err := tx.ExecContext(ctx, `
UPDATE dbo.task_items SET state=N'cancelled',reason_code=@p1,completed_at=@p2,updated_at=@p2 WHERE item_id=@p3`,
		truncate(reason, 128), now, row.ItemID); err != nil {
		return &protocol.APIError{Code: protocol.CodeDatabase, Message: "cancel task item"}
	}
	if apiErr := s.releaseLicenseTx(ctx, tx, row, reason, now); apiErr != nil {
		return apiErr
	}
	if sequence, err := s.nextSequenceTx(ctx, tx, row.ItemID); err == nil {
		_ = insertTaskEventTx(ctx, tx, row.ItemID, sequence, row.AttemptCount, "cancelled", map[string]any{"reason_code": reason}, now)
	}
	_, _ = s.updateLegacyJobTxWithState(ctx, tx, row, "canceled", now)
	return nil
}

func (s *Store) CancelTask(ctx context.Context, taskID, admin string) (*TaskDetail, *protocol.APIError) {
	id, err := protocol.NormalizeUUID(taskID)
	if err != nil {
		return nil, &protocol.APIError{Code: protocol.CodeNotFound, Message: "invalid task id"}
	}
	tx, err := s.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return nil, &protocol.APIError{Code: protocol.CodeDatabase, Message: "begin task cancel"}
	}
	defer tx.Rollback()
	now := s.now()
	if _, err := tx.ExecContext(ctx, `UPDATE dbo.tasks SET cancel_requested_at=COALESCE(cancel_requested_at,@p1) WHERE task_id=@p2`, now, id); err != nil {
		return nil, &protocol.APIError{Code: protocol.CodeDatabase, Message: "request task cancel"}
	}
	rows, err := tx.QueryContext(ctx, `SELECT item_id FROM dbo.task_items WITH (UPDLOCK,HOLDLOCK) WHERE task_id=@p1 AND completed_at IS NULL`, id)
	if err != nil {
		return nil, &protocol.APIError{Code: protocol.CodeDatabase, Message: "load task items for cancel"}
	}
	var itemIDs []string
	for rows.Next() {
		var itemID mssql.UniqueIdentifier
		if err := rows.Scan(&itemID); err != nil {
			rows.Close()
			return nil, &protocol.APIError{Code: protocol.CodeDatabase, Message: "decode cancel item"}
		}
		itemIDs = append(itemIDs, uuidString(itemID))
	}
	rows.Close()
	for _, itemID := range itemIDs {
		row, apiErr := s.loadAgentTaskRowTx(ctx, tx, itemID, true)
		if apiErr != nil {
			return nil, apiErr
		}
		if row.StartedAt == nil && (row.State == protocol.TaskStateQueued || row.State == protocol.TaskStateDelivered || row.State == protocol.TaskStateRetryWait) {
			if apiErr := s.cancelItemTx(ctx, tx, row, "task_cancelled", now); apiErr != nil {
				return nil, apiErr
			}
		} else {
			_, _ = tx.ExecContext(ctx, `UPDATE dbo.task_items SET cancel_requested_at=COALESCE(cancel_requested_at,@p1),updated_at=@p1 WHERE item_id=@p2`, now, row.ItemID)
			if sequence, err := s.nextSequenceTx(ctx, tx, row.ItemID); err == nil {
				_ = insertTaskEventTx(ctx, tx, row.ItemID, sequence, row.AttemptCount, "cancel_requested", map[string]any{"admin": admin}, now)
			}
		}
	}
	if err := tx.Commit(); err != nil {
		return nil, &protocol.APIError{Code: protocol.CodeDatabase, Message: "commit task cancel"}
	}
	s.insertLicenseEvent(ctx, nil, nil, "task_cancel_requested", admin, map[string]any{"task_id": id})
	return s.TaskDetail(ctx, id)
}

func (s *Store) CancelTaskItem(ctx context.Context, itemID, admin string) (*TaskDetail, *protocol.APIError) {
	id, err := protocol.NormalizeUUID(itemID)
	if err != nil {
		return nil, &protocol.APIError{Code: protocol.CodeNotFound, Message: "invalid item id"}
	}
	tx, err := s.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return nil, &protocol.APIError{Code: protocol.CodeDatabase, Message: "begin item cancel"}
	}
	defer tx.Rollback()
	now := s.now()
	row, apiErr := s.loadAgentTaskRowTx(ctx, tx, id, true)
	if apiErr != nil {
		return nil, apiErr
	}
	if row.StartedAt == nil && (row.State == protocol.TaskStateQueued || row.State == protocol.TaskStateDelivered || row.State == protocol.TaskStateRetryWait) {
		if apiErr := s.cancelItemTx(ctx, tx, row, "item_cancelled", now); apiErr != nil {
			return nil, apiErr
		}
	} else if !protocol.IsTerminalTaskState(row.State) {
		if _, err := tx.ExecContext(ctx, `UPDATE dbo.task_items SET cancel_requested_at=COALESCE(cancel_requested_at,@p1),updated_at=@p1 WHERE item_id=@p2`, now, id); err != nil {
			return nil, &protocol.APIError{Code: protocol.CodeDatabase, Message: "request item cancel"}
		}
		if sequence, err := s.nextSequenceTx(ctx, tx, id); err == nil {
			_ = insertTaskEventTx(ctx, tx, id, sequence, row.AttemptCount, "cancel_requested", map[string]any{"admin": admin}, now)
		}
	}
	if err := tx.Commit(); err != nil {
		return nil, &protocol.APIError{Code: protocol.CodeDatabase, Message: "commit item cancel"}
	}
	s.insertLicenseEvent(ctx, nil, nil, "task_item_cancel_requested", admin, map[string]any{"item_id": id})
	return s.TaskDetail(ctx, row.TaskID)
}

func (s *Store) RequestReconcile(ctx context.Context, itemID, admin string) (*TaskDetail, *protocol.APIError) {
	id, err := protocol.NormalizeUUID(itemID)
	if err != nil {
		return nil, &protocol.APIError{Code: protocol.CodeNotFound, Message: "invalid item id"}
	}
	tx, err := s.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return nil, &protocol.APIError{Code: protocol.CodeDatabase, Message: "begin reconcile"}
	}
	defer tx.Rollback()
	row, apiErr := s.loadAgentTaskRowTx(ctx, tx, id, true)
	if apiErr != nil {
		return nil, apiErr
	}
	if row.State != protocol.TaskStateOutcomeUnknown && row.State != protocol.TaskStateFailed {
		return nil, &protocol.APIError{Code: protocol.CodeTaskConflict, Message: "read-only reconcile is only available for unknown or failed outcomes"}
	}
	now := s.now()
	if _, err := tx.ExecContext(ctx, `UPDATE dbo.task_items SET reconcile_requested_at=@p1,updated_at=@p1 WHERE item_id=@p2`, now, id); err != nil {
		return nil, &protocol.APIError{Code: protocol.CodeDatabase, Message: "request reconcile"}
	}
	if sequence, err := s.nextSequenceTx(ctx, tx, id); err == nil {
		_ = insertTaskEventTx(ctx, tx, id, sequence, row.AttemptCount, "reconciliation", map[string]any{"admin": admin, "mode": "read_only"}, now)
	}
	if err := tx.Commit(); err != nil {
		return nil, &protocol.APIError{Code: protocol.CodeDatabase, Message: "commit reconcile request"}
	}
	return s.TaskDetail(ctx, row.TaskID)
}

func (s *Store) RecordTaskDiagnostic(ctx context.Context, identity *Identity, diagnostic protocol.TaskDiagnostic) *protocol.APIError {
	message := truncate(redactSerialLike(diagnostic.Message), 1024)
	var details any
	if diagnostic.ItemID != "" {
		id, err := protocol.NormalizeUUID(diagnostic.ItemID)
		if err != nil {
			return &protocol.APIError{Code: protocol.CodeTaskNotFound, Message: "invalid item id"}
		}
		tx, err := s.DB.BeginTx(ctx, &sql.TxOptions{})
		if err != nil {
			return &protocol.APIError{Code: protocol.CodeDatabase, Message: "begin diagnostic"}
		}
		defer tx.Rollback()
		row, apiErr := s.loadAgentTaskRowTx(ctx, tx, id, true)
		if apiErr != nil {
			return apiErr
		}
		if row.MachineID != identity.MachineID || row.RegistrationID != identity.RegistrationID {
			return &protocol.APIError{Code: protocol.CodeTaskNotFound, Message: "task item belongs to another installation"}
		}
		sequence, err := s.nextSequenceTx(ctx, tx, id)
		if err != nil {
			return &protocol.APIError{Code: protocol.CodeDatabase, Message: "reserve diagnostic sequence"}
		}
		details = map[string]any{"code": diagnostic.Code, "message": message, "occurred_at": diagnostic.OccurredAt}
		if err := insertTaskEventTx(ctx, tx, id, sequence, row.AttemptCount, "journal_corrupted", details, s.now()); err != nil {
			return &protocol.APIError{Code: protocol.CodeDatabase, Message: "record diagnostic"}
		}
		if row.State != protocol.TaskStateOutcomeUnknown && row.State != protocol.TaskStateSucceeded && row.LicenseID != "" && row.StartedAt != nil {
			_, _ = tx.ExecContext(ctx, `UPDATE dbo.task_items SET state=N'outcome_unknown',reason_code=N'journal_corrupted',updated_at=@p1 WHERE item_id=@p2`, s.now(), id)
			_ = s.markLicenseUnknownTx(ctx, tx, row, "journal_corrupted", s.now())
		}
		if err := tx.Commit(); err != nil {
			return &protocol.APIError{Code: protocol.CodeDatabase, Message: "commit diagnostic"}
		}
		return nil
	}
	s.insertLicenseEvent(ctx, nil, nil, "agent_journal_corrupted", identity.UUID, map[string]any{"code": diagnostic.Code, "message": message})
	return nil
}

func nullUUIDOrEmpty(value mssql.NullUniqueIdentifier) string {
	return nullUUIDString(value)
}

func commitAPIError(err error) *protocol.APIError {
	if err != nil {
		return &protocol.APIError{Code: protocol.CodeDatabase, Message: "commit transaction"}
	}
	return nil
}

// CheckScanTaskClaim prevents older agents from starting retired activation jobs.
func (s *Store) CheckScanTaskClaim(ctx context.Context, identity *Identity, itemID string) *protocol.APIError {
	var kind string
	err := s.DB.QueryRowContext(ctx, `SELECT kind FROM dbo.task_items WHERE item_id=@p1 AND machine_id=@p2 AND registration_id=@p3`, itemID, identity.MachineID, identity.RegistrationID).Scan(&kind)
	if errors.Is(err, sql.ErrNoRows) {
		return &protocol.APIError{Code: protocol.CodeTaskNotFound, Message: "task item not found"}
	}
	if err != nil {
		return &protocol.APIError{Code: protocol.CodeDatabase, Message: "could not check task kind"}
	}
	if kind != protocol.TaskKindScan {
		return &protocol.APIError{Code: protocol.CodeTaskConflict, Message: "remote activation is disabled"}
	}
	return nil
}
