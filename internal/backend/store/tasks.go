package store

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	mssql "github.com/microsoft/go-mssqldb"
	"telehack2026/internal/activation"
	"telehack2026/internal/backend/licensecrypto"
	"telehack2026/internal/protocol"
)

type TaskCounts struct {
	Queued         int `json:"queued"`
	Delivered      int `json:"delivered"`
	Running        int `json:"running"`
	RetryWait      int `json:"retry_wait"`
	Succeeded      int `json:"succeeded"`
	Skipped        int `json:"skipped"`
	Failed         int `json:"failed"`
	OutcomeUnknown int `json:"outcome_unknown"`
	Cancelled      int `json:"cancelled"`
	Expired        int `json:"expired"`
	Total          int `json:"total"`
	Finished       int `json:"finished"`
}

type Task struct {
	ID                string          `json:"id"`
	Kind              string          `json:"kind"`
	State             string          `json:"state"`
	NeedsAttention    bool            `json:"needs_attention"`
	UnknownItems      int             `json:"unknown_items"`
	CreatedBy         string          `json:"created_by,omitempty"`
	CreatedAt         time.Time       `json:"created_at"`
	ExpiresAt         time.Time       `json:"expires_at"`
	CancelRequestedAt *time.Time      `json:"cancel_requested_at,omitempty"`
	PreviewID         string          `json:"preview_id,omitempty"`
	LegacyJobID       string          `json:"legacy_job_id,omitempty"`
	Selection         json.RawMessage `json:"selection,omitempty"`
	Counts            TaskCounts      `json:"counts"`
}

type TaskItem struct {
	ID                 string     `json:"id"`
	TaskID             string     `json:"task_id"`
	MachineID          string     `json:"machine_id"`
	MachineName        string     `json:"machine_name,omitempty"`
	Hostname           string     `json:"hostname,omitempty"`
	Kind               string     `json:"kind"`
	State              string     `json:"state"`
	ReasonCode         string     `json:"reason_code,omitempty"`
	DeliveryVersion    int        `json:"delivery_version"`
	EncryptionKeyID    string     `json:"encryption_key_id,omitempty"`
	LicenseID          string     `json:"license_id,omitempty"`
	LicenseMask        string     `json:"license_mask,omitempty"`
	AttemptCount       int        `json:"attempt_count"`
	NextAttemptAt      *time.Time `json:"next_attempt_at,omitempty"`
	StartedAt          *time.Time `json:"started_at,omitempty"`
	CompletedAt        *time.Time `json:"completed_at,omitempty"`
	LastSeenAt         *time.Time `json:"last_seen_at,omitempty"`
	ResultVersion      int        `json:"result_version,omitempty"`
	ScanReportID       string     `json:"scan_report_id,omitempty"`
	CancelRequested    bool       `json:"cancel_requested"`
	ReconcileRequested bool       `json:"reconcile_requested"`
	LegacyJobID        string     `json:"legacy_job_id,omitempty"`
	CreatedAt          time.Time  `json:"created_at"`
	UpdatedAt          time.Time  `json:"updated_at"`
}

type TaskDetail struct {
	Task  Task       `json:"task"`
	Items []TaskItem `json:"items"`
}

type TaskItemEvent struct {
	Sequence  int             `json:"sequence"`
	AttemptNo int             `json:"attempt_no"`
	EventType string          `json:"event_type"`
	Details   json.RawMessage `json:"details,omitempty"`
	CreatedAt time.Time       `json:"created_at"`
}

type TaskFilter struct {
	Kind      string
	State     string
	MachineID string
	From      string
	To        string
	Page      int
	PageSize  int
}

type CreateInstallTaskInput struct {
	PoolID         string   `json:"pool_id"`
	PreviewID      string   `json:"preview_id"`
	MachineIDs     []string `json:"machine_ids"`
	IdempotencyKey string   `json:"idempotency_key"`
}

type CreateScanTaskInput struct {
	MachineIDs     []string `json:"machine_ids"`
	GroupIDs       []string `json:"group_ids"`
	IdempotencyKey string   `json:"idempotency_key"`
}

func AggregateItems(states []string) (string, bool, int) {
	counts := map[string]int{}
	for _, state := range states {
		counts[state]++
	}
	total := len(states)
	if total == 0 {
		return protocol.TaskAggregateFailed, false, 0
	}
	active := counts[protocol.TaskStateQueued] + counts[protocol.TaskStateDelivered] +
		counts[protocol.TaskStateRunning] + counts[protocol.TaskStateRetryWait]
	unknown := counts[protocol.TaskStateOutcomeUnknown]
	success := counts[protocol.TaskStateSucceeded] + counts[protocol.TaskStateSkipped]
	if active == 0 && unknown > 0 {
		return protocol.TaskAggregateRequiresAttention, true, unknown
	}
	if active == 0 {
		if counts[protocol.TaskStateCancelled] == total {
			return protocol.TaskAggregateCancelled, false, unknown
		}
		if counts[protocol.TaskStateExpired] == total {
			return protocol.TaskAggregateExpired, false, unknown
		}
		if success == total {
			return protocol.TaskAggregateCompleted, false, unknown
		}
		if success > 0 {
			return protocol.TaskAggregatePartiallyFailed, unknown > 0, unknown
		}
		return protocol.TaskAggregateFailed, unknown > 0, unknown
	}
	started := counts[protocol.TaskStateRunning] + counts[protocol.TaskStateRetryWait] +
		counts[protocol.TaskStateSucceeded] + counts[protocol.TaskStateSkipped] +
		counts[protocol.TaskStateFailed] + counts[protocol.TaskStateOutcomeUnknown] +
		counts[protocol.TaskStateCancelled] + counts[protocol.TaskStateExpired]
	if started > 0 {
		return protocol.TaskAggregateRunning, unknown > 0, unknown
	}
	return protocol.TaskAggregateQueued, unknown > 0, unknown
}

func taskCountsFromStates(states []string) TaskCounts {
	var counts TaskCounts
	for _, state := range states {
		counts.Total++
		switch state {
		case protocol.TaskStateQueued:
			counts.Queued++
		case protocol.TaskStateDelivered:
			counts.Delivered++
		case protocol.TaskStateRunning:
			counts.Running++
		case protocol.TaskStateRetryWait:
			counts.RetryWait++
		case protocol.TaskStateSucceeded:
			counts.Succeeded++
			counts.Finished++
		case protocol.TaskStateSkipped:
			counts.Skipped++
			counts.Finished++
		case protocol.TaskStateFailed:
			counts.Failed++
			counts.Finished++
		case protocol.TaskStateOutcomeUnknown:
			counts.OutcomeUnknown++
			counts.Finished++
		case protocol.TaskStateCancelled:
			counts.Cancelled++
			counts.Finished++
		case protocol.TaskStateExpired:
			counts.Expired++
			counts.Finished++
		}
	}
	return counts
}

func (s *Store) CreateScanTask(ctx context.Context, input CreateScanTaskInput, admin string) (*TaskDetail, *protocol.APIError) {
	if err := validateIdempotencyKey(input.IdempotencyKey); err != nil {
		return nil, err
	}
	machines, apiErr := s.ResolveMachineSelection(ctx, input.MachineIDs, input.GroupIDs)
	if apiErr != nil {
		return nil, apiErr
	}
	digest := requestDigest(struct {
		Kind     string   `json:"kind"`
		Machines []string `json:"machine_ids"`
	}{protocol.TaskKindScan, machines})
	if existing, apiErr := s.existingIdempotentTask(ctx, input.IdempotencyKey, digest); apiErr != nil || existing != nil {
		if existing != nil {
			return s.TaskDetail(ctx, existing.ID)
		}
		return nil, apiErr
	}
	cfg, _, err := s.Config(ctx)
	if err != nil {
		return nil, &protocol.APIError{Code: protocol.CodeDatabase, Message: "load configuration"}
	}
	cfg = cfg.WithScheduleDefaults()
	ttl := time.Duration(cfg.TaskTTLSeconds) * time.Second
	if ttl <= 0 {
		ttl = time.Duration(protocol.DefaultTaskTTLSeconds) * time.Second
	}
	now := s.now()
	taskID := protocol.NewUUID()
	expires := now.Add(ttl)
	taskJSON, _ := json.Marshal(cfg)
	selectionJSON, _ := json.Marshal(map[string]any{"machine_ids": machines, "group_ids": input.GroupIDs})

	tx, err := s.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return nil, &protocol.APIError{Code: protocol.CodeDatabase, Message: "begin scan task"}
	}
	defer tx.Rollback()
	if apiErr := s.ensureIdempotencyFreeTx(ctx, tx, input.IdempotencyKey, digest); apiErr != nil {
		return nil, apiErr
	}
	_, err = tx.ExecContext(ctx, `
INSERT INTO dbo.tasks(task_id,kind,created_by,created_at,expires_at,settings_snapshot,selection_snapshot,idempotency_key,request_digest)
VALUES(@p1,N'scan',@p2,@p3,@p4,@p5,@p6,@p7,@p8)`,
		taskID, admin, now, expires, string(taskJSON), string(selectionJSON), input.IdempotencyKey, digest)
	if err != nil {
		if isDuplicateKey(err) {
			_ = tx.Rollback()
			return s.resolveIdempotentDuplicate(ctx, input.IdempotencyKey, digest)
		}
		return nil, &protocol.APIError{Code: protocol.CodeDatabase, Message: "create scan task"}
	}
	for _, machineID := range machines {
		registrationID, key, apiErr := s.agentKeyForTaskTx(ctx, tx, machineID)
		if apiErr != nil {
			if apiErr.Code == protocol.CodeAgentKeyUnavailable {
				// Old agents still receive this scan through the legacy jobs
				// channel. A capable agent without a key is a hard error.
				if capable, _ := s.machineCapableTx(ctx, tx, machineID); capable {
					return nil, apiErr
				}
			} else {
				return nil, apiErr
			}
		}
		itemID := protocol.NewUUID()
		jobID := protocol.NewUUID()
		var encrypted []byte
		var keyID any
		var deliveryVersion = 0
		if key != nil {
			params, _ := json.Marshal(protocol.ScanParameters{Kind: protocol.TaskKindScan, Options: protocol.ScanOptions{Force: true}})
			binding := protocol.TaskBinding{
				Protocol: protocol.TaskBindingProtocol, Purpose: "task_item_parameters", TaskID: taskID,
				ItemID: itemID, MachineID: machineID, RegistrationID: registrationID,
				Kind: protocol.TaskKindScan, ParametersVersion: protocol.ParametersVersionV1,
				RecipientKeyID: key.KeyID, ExpiresAt: protocol.FormatTaskTime(expires),
			}
			publicKey, parseErr := protocol.ParseTaskPublicKeyPEM(key.PublicKeyPEM)
			if parseErr != nil {
				return nil, &protocol.APIError{Code: protocol.CodeAgentKeyUnavailable, Message: "agent encryption key is invalid"}
			}
			envelope, sealErr := protocol.SealTaskParameters(publicKey, binding, params)
			if sealErr != nil {
				return nil, &protocol.APIError{Code: protocol.CodeInternal, Message: "encrypt scan parameters"}
			}
			encrypted, _ = protocol.EncodeEncryptedParameters(envelope)
			keyID = key.KeyID
			deliveryVersion = 1
		}
		_, err = tx.ExecContext(ctx, `
INSERT INTO dbo.task_items(item_id,task_id,machine_id,registration_id,kind,state,delivery_version,encryption_key_id,encrypted_parameters,created_at,updated_at,legacy_job_id)
VALUES(@p1,@p2,@p3,@p4,N'scan',@p5,@p6,@p7,@p8,@p9,@p9,@p10)`,
			itemID, taskID, machineID, registrationID, protocol.TaskStateQueued, deliveryVersion, keyID, nilIfNil(encrypted), now, jobID)
		if err != nil {
			if isDuplicateKey(err) {
				return nil, &protocol.APIError{Code: protocol.CodeMachineBusy, Message: "a machine already has an open item in this task"}
			}
			return nil, &protocol.APIError{Code: protocol.CodeDatabase, Message: "create scan task item"}
		}
		_, err = tx.ExecContext(ctx, `
INSERT INTO dbo.jobs(job_id,machine_id,kind,state,created_at,created_by,task_id,task_item_id)
VALUES(@p1,@p2,N'scan',N'pending',@p3,@p4,@p5,@p6)`,
			jobID, machineID, now, admin, taskID, itemID)
		if err != nil {
			return nil, &protocol.APIError{Code: protocol.CodeDatabase, Message: "create legacy scan job"}
		}
		if err := insertTaskEventTx(ctx, tx, itemID, 1, 0, "created", map[string]any{"kind": "scan"}, now); err != nil {
			return nil, &protocol.APIError{Code: protocol.CodeDatabase, Message: "record task event"}
		}
	}
	if err := tx.Commit(); err != nil {
		return nil, &protocol.APIError{Code: protocol.CodeDatabase, Message: "commit scan task"}
	}
	return s.TaskDetail(ctx, taskID)
}

func (s *Store) CreateInstallTask(ctx context.Context, input CreateInstallTaskInput, admin string) (*TaskDetail, *protocol.APIError) {
	if err := validateIdempotencyKey(input.IdempotencyKey); err != nil {
		return nil, err
	}
	poolID, err := protocol.NormalizeUUID(input.PoolID)
	if err != nil {
		return nil, &protocol.APIError{Code: protocol.CodeNotFound, Message: "invalid pool_id"}
	}
	previewID, err := protocol.NormalizeUUID(input.PreviewID)
	if err != nil {
		return nil, &protocol.APIError{Code: protocol.CodePreviewInvalid, Message: "invalid preview_id"}
	}
	selected, apiErr := normalizeSelection(input.MachineIDs)
	if apiErr != nil {
		return nil, apiErr
	}
	digest := requestDigest(struct {
		Kind     string   `json:"kind"`
		Pool     string   `json:"pool_id"`
		Preview  string   `json:"preview_id"`
		Machines []string `json:"machine_ids"`
	}{protocol.TaskKindInstallLicense, poolID, previewID, selected})
	if existing, apiErr := s.existingIdempotentTask(ctx, input.IdempotencyKey, digest); apiErr != nil || existing != nil {
		if existing != nil {
			return s.TaskDetail(ctx, existing.ID)
		}
		return nil, apiErr
	}
	cfg, _, cfgErr := s.Config(ctx)
	if cfgErr != nil {
		return nil, &protocol.APIError{Code: protocol.CodeDatabase, Message: "load configuration"}
	}
	cfg = cfg.WithScheduleDefaults()
	ttl := time.Duration(cfg.TaskTTLSeconds) * time.Second
	if ttl <= 0 {
		ttl = time.Duration(protocol.DefaultTaskTTLSeconds) * time.Second
	}
	now := s.now()
	tx, err := s.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return nil, &protocol.APIError{Code: protocol.CodeDatabase, Message: "begin install task"}
	}
	defer tx.Rollback()
	if apiErr := s.ensureIdempotencyFreeTx(ctx, tx, input.IdempotencyKey, digest); apiErr != nil {
		return nil, apiErr
	}
	preview, apiErr := s.loadPreviewTx(ctx, tx, previewID)
	if apiErr != nil {
		return nil, apiErr
	}
	if preview.PoolID != poolID || !now.Before(preview.ExpiresAt) {
		return nil, &protocol.APIError{Code: protocol.CodePreviewStale, Message: "preview expired or belongs to another pool"}
	}
	var pool LicensePool
	var poolIDValue mssql.UniqueIdentifier
	var archived sql.NullTime
	err = tx.QueryRowContext(ctx, `
SELECT pool_id,name,csp_major_version,license_kind,term,archived_at FROM dbo.license_pools WITH (UPDLOCK,HOLDLOCK) WHERE pool_id=@p1`, poolID).
		Scan(&poolIDValue, &pool.Name, &pool.CSPMajorVersion, &pool.LicenseKind, &pool.Term, &archived)
	pool.ID = uuidString(poolIDValue)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, &protocol.APIError{Code: protocol.CodeNotFound, Message: "license pool not found"}
	}
	if err != nil {
		return nil, &protocol.APIError{Code: protocol.CodeDatabase, Message: "load license pool"}
	}
	if archived.Valid {
		return nil, &protocol.APIError{Code: protocol.CodeConflict, Message: "pool is archived"}
	}
	if preview.Snapshot.Pool.ID != pool.ID || preview.Snapshot.Pool.CSPMajorVersion != pool.CSPMajorVersion ||
		preview.Snapshot.Pool.LicenseKind != pool.LicenseKind || preview.Snapshot.Pool.Term != pool.Term {
		return nil, &protocol.APIError{Code: protocol.CodePreviewStale, Message: "pool properties changed"}
	}
	snapshotByMachine := map[string]activation.Classification{}
	for _, machine := range preview.Snapshot.Machines {
		snapshotByMachine[machine.MachineID] = machine
	}
	// Recompute the current basis for every explicitly selected machine.
	facts, apiErr := s.loadMachineFacts(ctx, selected, preview.Snapshot.Pool, time.Duration(cfg.InventoryFreshnessSeconds)*time.Second, now)
	if apiErr != nil {
		return nil, apiErr
	}
	current := map[string]activation.Classification{}
	for _, machine := range facts {
		current[machine.MachineID] = activation.Classify(machine, preview.Snapshot.Pool)
	}
	for _, machineID := range selected {
		snapshot, ok := snapshotByMachine[machineID]
		if !ok {
			return nil, &protocol.APIError{Code: protocol.CodePreviewStale, Message: "selected machine was not part of the preview"}
		}
		nowClassification, ok := current[machineID]
		if !ok {
			return nil, &protocol.APIError{Code: protocol.CodePreviewStale, Message: "selected machine changed"}
		}
		if !sameProtectionBasis(snapshot, nowClassification) {
			return nil, &protocol.APIError{Code: protocol.CodePreviewStale, Message: "machine license state changed since preview"}
		}
		if !activation.SelectionAllowed(nowClassification) {
			return nil, &protocol.APIError{Code: protocol.CodeMachineNotEligible, Message: "machine is not eligible for installation"}
		}
	}

	// Serialize reservations across concurrent administrators. The filtered
	// unique indexes are the final backstop.
	var available int
	if err := tx.QueryRowContext(ctx, `
SELECT COUNT(1) FROM dbo.licenses WITH (UPDLOCK,HOLDLOCK)
WHERE pool_id=@p1 AND state=N'available'`, poolID).Scan(&available); err != nil {
		return nil, &protocol.APIError{Code: protocol.CodeDatabase, Message: "count available licenses"}
	}
	if available < len(selected) {
		return nil, &protocol.APIError{Code: protocol.CodeLicenseDeficit, Message: "not enough available license keys",
			Details: map[string]any{"needed": len(selected), "available": available}}
	}
	rows, err := tx.QueryContext(ctx, `
SELECT TOP (@p2) license_id,encrypted_serial FROM dbo.licenses WITH (UPDLOCK,HOLDLOCK)
WHERE pool_id=@p1 AND state=N'available' ORDER BY created_at,license_id`, poolID, len(selected))
	if err != nil {
		return nil, &protocol.APIError{Code: protocol.CodeDatabase, Message: "reserve license keys"}
	}
	type licenseRow struct {
		id     string
		sealed []byte
	}
	var licenses []licenseRow
	for rows.Next() {
		var item licenseRow
		var id mssql.UniqueIdentifier
		if err := rows.Scan(&id, &item.sealed); err != nil {
			rows.Close()
			return nil, &protocol.APIError{Code: protocol.CodeDatabase, Message: "decode reserved license"}
		}
		item.id = uuidString(id)
		licenses = append(licenses, item)
	}
	rows.Close()
	if len(licenses) != len(selected) {
		return nil, &protocol.APIError{Code: protocol.CodeLicenseDeficit, Message: "not enough available license keys",
			Details: map[string]any{"needed": len(selected), "available": len(licenses)}}
	}

	taskID := protocol.NewUUID()
	expires := now.Add(ttl)
	taskJSON, _ := json.Marshal(cfg)
	selectionJSON, _ := json.Marshal(map[string]any{
		"preview_id": previewID, "pool_id": poolID, "machine_ids": selected,
		"categories": current,
	})
	_, err = tx.ExecContext(ctx, `
INSERT INTO dbo.tasks(task_id,kind,created_by,created_at,expires_at,settings_snapshot,selection_snapshot,idempotency_key,request_digest,preview_id)
VALUES(@p1,N'install_license',@p2,@p3,@p4,@p5,@p6,@p7,@p8,@p9)`,
		taskID, admin, now, expires, string(taskJSON), string(selectionJSON), input.IdempotencyKey, digest, previewID)
	if err != nil {
		if isDuplicateKey(err) {
			_ = tx.Rollback()
			return s.resolveIdempotentDuplicate(ctx, input.IdempotencyKey, digest)
		}
		return nil, &protocol.APIError{Code: protocol.CodeDatabase, Message: "create install task"}
	}
	for index, machineID := range selected {
		classification := current[machineID]
		registrationID, key, apiErr := s.agentKeyForTaskTx(ctx, tx, machineID)
		if apiErr != nil {
			return nil, apiErr
		}
		publicKey, parseErr := protocol.ParseTaskPublicKeyPEM(key.PublicKeyPEM)
		if parseErr != nil {
			return nil, &protocol.APIError{Code: protocol.CodeAgentKeyUnavailable, Message: "agent encryption key is invalid"}
		}
		itemID := protocol.NewUUID()
		license := licenses[index]
		aad, err := licensecrypto.LicenseAAD(licensecrypto.LicenseBinding{
			LicenseID: license.id, PoolID: poolID, CSPMajorVersion: pool.CSPMajorVersion,
			LicenseKind: pool.LicenseKind, Term: pool.Term,
		})
		if err != nil {
			return nil, &protocol.APIError{Code: protocol.CodeInternal, Message: "bind license encryption"}
		}
		if s.LicenseKeyring == nil {
			return nil, &protocol.APIError{Code: protocol.CodeLicenseUnavailable, Message: "license key material is not available"}
		}
		serial, err := s.LicenseKeyring.Decrypt(license.sealed, aad)
		if err != nil {
			return nil, &protocol.APIError{Code: protocol.CodeLicenseUnavailable, Message: "license serial cannot be decrypted"}
		}
		params := protocol.InstallLicenseParameters{
			Kind: protocol.TaskKindInstallLicense, LicenseID: license.id, Serial: serial,
			Pool: protocol.LicensePoolSpec{
				PoolID: poolID, Name: pool.Name, CSPMajorVersion: pool.CSPMajorVersion,
				LicenseKind: pool.LicenseKind, Term: pool.Term,
			},
			AllowTrialReplacement: activation.AllowTrialReplacement(classification),
		}
		paramsJSON, _ := json.Marshal(params)
		binding := protocol.TaskBinding{
			Protocol: protocol.TaskBindingProtocol, Purpose: "task_item_parameters", TaskID: taskID,
			ItemID: itemID, MachineID: machineID, RegistrationID: registrationID,
			Kind: protocol.TaskKindInstallLicense, ParametersVersion: protocol.ParametersVersionV1,
			RecipientKeyID: key.KeyID, ExpiresAt: protocol.FormatTaskTime(expires),
		}
		envelope, sealErr := protocol.SealTaskParameters(publicKey, binding, paramsJSON)
		if sealErr != nil {
			return nil, &protocol.APIError{Code: protocol.CodeInternal, Message: "encrypt install parameters"}
		}
		encrypted, _ := protocol.EncodeEncryptedParameters(envelope)

		_, err = tx.ExecContext(ctx, `
INSERT INTO dbo.task_items(item_id,task_id,machine_id,registration_id,kind,state,reason_code,delivery_version,encryption_key_id,encrypted_parameters,license_id,allow_trial_replacement,created_at,updated_at)
VALUES(@p1,@p2,@p3,@p4,N'install_license',@p5,NULL,1,@p6,@p7,@p8,@p9,@p10,@p10)`,
			itemID, taskID, machineID, registrationID, protocol.TaskStateQueued, key.KeyID, encrypted, license.id, params.AllowTrialReplacement, now)
		if err != nil {
			if isDuplicateKey(err) {
				return nil, &protocol.APIError{Code: protocol.CodeMachineBusy, Message: "another license installation is already open for one of the selected machines"}
			}
			return nil, &protocol.APIError{Code: protocol.CodeDatabase, Message: "create install task item"}
		}
		resultExec, err := tx.ExecContext(ctx, `
UPDATE dbo.licenses SET state=N'reserved',assigned_machine_id=@p1,assigned_task_item_id=@p2,reserved_at=@p3,updated_at=@p3
WHERE license_id=@p4 AND state=N'available'`, machineID, itemID, now, license.id)
		if err != nil {
			return nil, &protocol.APIError{Code: protocol.CodeDatabase, Message: "reserve license key"}
		}
		if affected, _ := resultExec.RowsAffected(); affected == 0 {
			return nil, &protocol.APIError{Code: protocol.CodeLicenseDeficit, Message: "a license key was taken concurrently; nothing was reserved"}
		}
		if _, err := tx.ExecContext(ctx, `
INSERT INTO dbo.license_assignments(assignment_id,license_id,machine_id,task_item_id,state,created_at)
VALUES(@p1,@p2,@p3,@p4,N'reserved',@p5)`, protocol.NewUUID(), license.id, machineID, itemID, now); err != nil {
			return nil, &protocol.APIError{Code: protocol.CodeDatabase, Message: "record license assignment"}
		}
		_, _ = tx.ExecContext(ctx, `
INSERT INTO dbo.license_events(license_id,pool_id,kind,actor,details_json,created_at)
VALUES(@p1,@p2,N'license_reserved',@p3,@p4,@p5)`, license.id, poolID, admin,
			string(mustJSON(map[string]any{"task_item_id": itemID, "machine_id": machineID})), now)
		if err := insertTaskEventTx(ctx, tx, itemID, 1, 0, "created", map[string]any{
			"kind": "install_license", "license_id": license.id, "allow_trial_replacement": params.AllowTrialReplacement,
		}, now); err != nil {
			return nil, &protocol.APIError{Code: protocol.CodeDatabase, Message: "record task event"}
		}
	}
	if _, err := tx.ExecContext(ctx, `UPDATE dbo.previews SET consumed_at=@p1 WHERE preview_id=@p2`, now, previewID); err != nil {
		return nil, &protocol.APIError{Code: protocol.CodeDatabase, Message: "consume preview"}
	}
	if err := tx.Commit(); err != nil {
		return nil, &protocol.APIError{Code: protocol.CodeDatabase, Message: "commit install task"}
	}
	return s.TaskDetail(ctx, taskID)
}

type agentKey struct {
	RegistrationID int64
	KeyID          string
	PublicKeyPEM   string
}

func (s *Store) agentKeyForTaskTx(ctx context.Context, tx *sql.Tx, machineID string) (int64, *agentKey, *protocol.APIError) {
	var registrationID int64
	err := tx.QueryRowContext(ctx, `
SELECT TOP 1 registration_id FROM dbo.registrations WITH (UPDLOCK,HOLDLOCK)
WHERE machine_id=@p1 AND state=N'active' ORDER BY created_at DESC`, machineID).Scan(&registrationID)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, nil, &protocol.APIError{Code: protocol.CodeMachineNotEligible, Message: "machine has no active registration"}
	}
	if err != nil {
		return 0, nil, &protocol.APIError{Code: protocol.CodeDatabase, Message: "load active registration"}
	}
	var key agentKey
	var keyID string
	err = tx.QueryRowContext(ctx, `
SELECT key_id,public_key_pem FROM dbo.agent_encryption_keys WITH (UPDLOCK,HOLDLOCK)
WHERE machine_id=@p1 AND registration_id=@p2 AND active=1 AND revoked_at IS NULL`, machineID, registrationID).
		Scan(&keyID, &key.PublicKeyPEM)
	if errors.Is(err, sql.ErrNoRows) {
		return registrationID, nil, &protocol.APIError{Code: protocol.CodeAgentKeyUnavailable, Message: "agent has not registered a task encryption key"}
	}
	if err != nil {
		return registrationID, nil, &protocol.APIError{Code: protocol.CodeDatabase, Message: "load agent encryption key"}
	}
	key.RegistrationID = registrationID
	key.KeyID = keyID
	return registrationID, &key, nil
}

func (s *Store) machineCapableTx(ctx context.Context, tx *sql.Tx, machineID string) (bool, error) {
	var capable bool
	err := tx.QueryRowContext(ctx, `
SELECT CASE WHEN EXISTS(
  SELECT 1 FROM dbo.agent_capabilities c
  JOIN dbo.registrations r ON r.registration_id=c.registration_id
  WHERE r.machine_id=@p1 AND r.state=N'active' AND c.tasks_v1=1) THEN 1 ELSE 0 END`, machineID).Scan(&capable)
	return capable, err
}

func validateIdempotencyKey(value string) *protocol.APIError {
	value = strings.TrimSpace(value)
	if value == "" || len(value) > 128 || strings.ContainsRune(value, 0) {
		return &protocol.APIError{Code: protocol.CodeConfigInvalid, Message: "idempotency_key is required (1..128 characters)"}
	}
	return nil
}

func normalizeSelection(ids []string) ([]string, *protocol.APIError) {
	seen := map[string]bool{}
	var result []string
	for _, id := range ids {
		normalized, err := protocol.NormalizeUUID(id)
		if err != nil {
			return nil, &protocol.APIError{Code: protocol.CodeMachineNotEligible, Message: "invalid machine_id"}
		}
		if !seen[normalized] {
			seen[normalized] = true
			result = append(result, normalized)
		}
	}
	if len(result) == 0 {
		return nil, &protocol.APIError{Code: protocol.CodeMachineNotEligible, Message: "selection is empty"}
	}
	sort.Strings(result)
	return result, nil
}

func requestDigest(value any) string {
	raw, _ := json.Marshal(value)
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

func (s *Store) existingIdempotentTask(ctx context.Context, key, digest string) (*Task, *protocol.APIError) {
	var taskIDValue mssql.UniqueIdentifier
	var storedDigest string
	err := s.DB.QueryRowContext(ctx, `
SELECT task_id,request_digest FROM dbo.tasks WHERE idempotency_key=@p1`, key).Scan(&taskIDValue, &storedDigest)
	taskID := uuidString(taskIDValue)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, &protocol.APIError{Code: protocol.CodeDatabase, Message: "check idempotency key"}
	}
	if storedDigest != digest {
		return nil, &protocol.APIError{Code: protocol.CodeIdempotencyConflict, Message: "idempotency_key was already used with a different request"}
	}
	return &Task{ID: taskID}, nil
}

func (s *Store) ensureIdempotencyFreeTx(ctx context.Context, tx *sql.Tx, key, digest string) *protocol.APIError {
	var taskIDValue mssql.UniqueIdentifier
	var storedDigest string
	err := tx.QueryRowContext(ctx, `
SELECT task_id,request_digest FROM dbo.tasks WITH (UPDLOCK,HOLDLOCK) WHERE idempotency_key=@p1`, key).
		Scan(&taskIDValue, &storedDigest)
	taskID := uuidString(taskIDValue)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return &protocol.APIError{Code: protocol.CodeDatabase, Message: "check idempotency key"}
	}
	if storedDigest != digest {
		return &protocol.APIError{Code: protocol.CodeIdempotencyConflict, Message: "idempotency_key was already used with a different request"}
	}
	return &protocol.APIError{Code: protocol.CodeConflict, Message: "task already exists", Details: map[string]any{"task_id": taskID}}
}

// resolveIdempotentDuplicate handles the unique-index race where another
// transaction committed the same idempotency key after our pre-check.
func (s *Store) resolveIdempotentDuplicate(ctx context.Context, key, digest string) (*TaskDetail, *protocol.APIError) {
	existing, apiErr := s.existingIdempotentTask(ctx, key, digest)
	if apiErr != nil {
		return nil, apiErr
	}
	if existing == nil {
		return nil, &protocol.APIError{Code: protocol.CodeConflict, Message: "idempotency key raced with a different task"}
	}
	return s.TaskDetail(ctx, existing.ID)
}

func insertTaskEventTx(ctx context.Context, tx *sql.Tx, itemID string, sequence, attempt int, eventType string, details any, now time.Time) error {
	var detailsJSON any
	if details != nil {
		raw, err := json.Marshal(details)
		if err != nil {
			return err
		}
		detailsJSON = string(raw)
	}
	_, err := tx.ExecContext(ctx, `
INSERT INTO dbo.task_item_events(item_id,sequence,attempt_no,event_type,details_json,created_at)
VALUES(@p1,@p2,@p3,@p4,@p5,@p6)`, itemID, sequence, attempt, eventType, detailsJSON, now)
	return err
}

func (s *Store) nextSequenceTx(ctx context.Context, tx *sql.Tx, itemID string) (int, error) {
	var sequence int
	err := tx.QueryRowContext(ctx, `
SELECT ISNULL(MAX(sequence),0)+1 FROM dbo.task_item_events WITH (UPDLOCK,HOLDLOCK) WHERE item_id=@p1`, itemID).Scan(&sequence)
	return sequence, err
}

func mustJSON(value any) []byte {
	raw, _ := json.Marshal(value)
	return raw
}

func nilIfNil(value []byte) any {
	if value == nil {
		return nil
	}
	return value
}

func (s *Store) TaskDetail(ctx context.Context, taskID string) (*TaskDetail, *protocol.APIError) {
	id, err := protocol.NormalizeUUID(taskID)
	if err != nil {
		return nil, &protocol.APIError{Code: protocol.CodeNotFound, Message: "invalid task id"}
	}
	if apiErr := s.expireTask(ctx, id); apiErr != nil {
		return nil, apiErr
	}
	var task Task
	var selection string
	var cancel sql.NullTime
	var preview, legacy mssql.NullUniqueIdentifier
	var createdBy sql.NullString
	var taskIDValue mssql.UniqueIdentifier
	err = s.DB.QueryRowContext(ctx, `
SELECT task_id,kind,created_by,created_at,expires_at,selection_snapshot,preview_id,legacy_job_id,cancel_requested_at
FROM dbo.tasks WHERE task_id=@p1`, id).Scan(
		&taskIDValue, &task.Kind, &createdBy, &task.CreatedAt, &task.ExpiresAt, &selection, &preview, &legacy, &cancel)
	task.ID = uuidString(taskIDValue)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, &protocol.APIError{Code: protocol.CodeNotFound, Message: "task not found"}
	}
	if err != nil {
		return nil, &protocol.APIError{Code: protocol.CodeDatabase, Message: "load task"}
	}
	task.CreatedBy = nullString(createdBy)
	task.PreviewID = nullUUIDString(preview)
	task.LegacyJobID = nullUUIDString(legacy)
	if selection != "" {
		task.Selection = json.RawMessage(selection)
	}
	if cancel.Valid {
		value := cancel.Time.UTC()
		task.CancelRequestedAt = &value
	}
	items, apiErr := s.taskItems(ctx, id)
	if apiErr != nil {
		return nil, apiErr
	}
	states := make([]string, 0, len(items))
	for _, item := range items {
		states = append(states, item.State)
	}
	task.Counts = taskCountsFromStates(states)
	task.State, task.NeedsAttention, task.UnknownItems = AggregateItems(states)
	return &TaskDetail{Task: task, Items: items}, nil
}

func (s *Store) taskItems(ctx context.Context, taskID string) ([]TaskItem, *protocol.APIError) {
	rows, err := s.DB.QueryContext(ctx, `
SELECT ti.item_id,ti.task_id,ti.machine_id,m.display_name,COALESCE(r.hostname,''),ti.kind,ti.state,
       COALESCE(ti.reason_code,''),ti.delivery_version,COALESCE(ti.encryption_key_id,''),
       COALESCE(ti.license_id,'00000000-0000-0000-0000-000000000000'),COALESCE(l.serial_mask,''),
       ti.attempt_count,ti.next_attempt_at,ti.started_at,ti.completed_at,ti.last_seen_at,
       COALESCE(ti.result_version,0),COALESCE(ti.scan_report_id,'00000000-0000-0000-0000-000000000000'),
       ti.cancel_requested_at,ti.reconcile_requested_at,COALESCE(ti.legacy_job_id,'00000000-0000-0000-0000-000000000000'),
       ti.created_at,ti.updated_at
FROM dbo.task_items ti
JOIN dbo.machines m ON m.machine_id=ti.machine_id
LEFT JOIN dbo.registrations r ON r.registration_id=ti.registration_id
LEFT JOIN dbo.licenses l ON l.license_id=ti.license_id
WHERE ti.task_id=@p1 ORDER BY m.display_name,ti.item_id`, taskID)
	if err != nil {
		return nil, &protocol.APIError{Code: protocol.CodeDatabase, Message: "load task items"}
	}
	defer rows.Close()
	var items []TaskItem
	for rows.Next() {
		var item TaskItem
		var itemIDValue, taskIDValue, machine mssql.UniqueIdentifier
		var licenseID, scanReport, legacy mssql.NullUniqueIdentifier
		var next, started, completed, seen, cancel, reconcile sql.NullTime
		var keyID, reason, mask, machineName, hostname sql.NullString
		if err := rows.Scan(&itemIDValue, &taskIDValue, &machine, &machineName, &hostname, &item.Kind, &item.State,
			&reason, &item.DeliveryVersion, &keyID, &licenseID, &mask, &item.AttemptCount, &next, &started, &completed,
			&seen, &item.ResultVersion, &scanReport, &cancel, &reconcile, &legacy, &item.CreatedAt, &item.UpdatedAt); err != nil {
			return nil, &protocol.APIError{Code: protocol.CodeDatabase, Message: "decode task item"}
		}
		item.ID = uuidString(itemIDValue)
		item.TaskID = uuidString(taskIDValue)
		item.MachineID = uuidString(machine)
		item.MachineName = nullString(machineName)
		item.Hostname = nullString(hostname)
		item.ReasonCode = nullString(reason)
		item.EncryptionKeyID = nullString(keyID)
		item.LicenseID = nullUUIDString(licenseID)
		item.LicenseMask = nullString(mask)
		item.ScanReportID = nullUUIDString(scanReport)
		item.LegacyJobID = nullUUIDString(legacy)
		item.NextAttemptAt = nullTime(next)
		item.StartedAt = nullTime(started)
		item.CompletedAt = nullTime(completed)
		item.LastSeenAt = nullTime(seen)
		item.CancelRequested = cancel.Valid
		item.ReconcileRequested = reconcile.Valid
		items = append(items, item)
	}
	return items, nil
}

func (s *Store) ListTasks(ctx context.Context, filter TaskFilter) (Page[Task], error) {
	if apiErr := s.ExpireDueTasks(ctx); apiErr != nil {
		return Page[Task]{}, fmt.Errorf("expire tasks: %s", apiErr.Message)
	}
	page, pageSize := normalizePage(filter.Page, filter.PageSize)
	where := []string{"1=1"}
	args := []any{}
	add := func(format string, values ...any) {
		placeholders := make([]any, len(values))
		for i := range values {
			placeholders[i] = len(args) + i + 1
		}
		where = append(where, fmt.Sprintf(format, placeholders...))
		args = append(args, values...)
	}
	if filter.Kind != "" {
		add("t.kind=@p%d", filter.Kind)
	}
	if filter.MachineID != "" {
		add("EXISTS(SELECT 1 FROM dbo.task_items ti WHERE ti.task_id=t.task_id AND ti.machine_id=@p%d)", filter.MachineID)
	}
	if filter.From != "" {
		add("t.created_at>=@p%d", filter.From)
	}
	if filter.To != "" {
		add("t.created_at<=@p%d", filter.To)
	}
	rows, err := s.DB.QueryContext(ctx, `
SELECT t.task_id,t.kind,t.created_by,t.created_at,t.expires_at,t.selection_snapshot,t.preview_id,t.legacy_job_id,t.cancel_requested_at
FROM dbo.tasks t WHERE `+strings.Join(where, " AND ")+` ORDER BY t.created_at DESC`, args...)
	if err != nil {
		return Page[Task]{}, err
	}
	defer rows.Close()
	var all []Task
	for rows.Next() {
		var task Task
		var taskIDValue mssql.UniqueIdentifier
		var selection string
		var preview, legacy mssql.NullUniqueIdentifier
		var cancel sql.NullTime
		var createdBy sql.NullString
		if err := rows.Scan(&taskIDValue, &task.Kind, &createdBy, &task.CreatedAt, &task.ExpiresAt, &selection, &preview, &legacy, &cancel); err != nil {
			return Page[Task]{}, err
		}
		task.ID = uuidString(taskIDValue)
		task.CreatedBy = nullString(createdBy)
		task.PreviewID = nullUUIDString(preview)
		task.LegacyJobID = nullUUIDString(legacy)
		if selection != "" {
			task.Selection = json.RawMessage(selection)
		}
		if cancel.Valid {
			value := cancel.Time.UTC()
			task.CancelRequestedAt = &value
		}
		all = append(all, task)
	}
	if err := rows.Err(); err != nil {
		return Page[Task]{}, err
	}
	// One grouped query for all item states avoids N+1 task loads.
	stateRows, err := s.DB.QueryContext(ctx, `
SELECT task_id,state,COUNT(1) FROM dbo.task_items GROUP BY task_id,state`)
	if err != nil {
		return Page[Task]{}, err
	}
	states := map[string][]string{}
	for stateRows.Next() {
		var taskID string
		var state string
		var count int
		if err := stateRows.Scan(&taskID, &state, &count); err != nil {
			stateRows.Close()
			return Page[Task]{}, err
		}
		for i := 0; i < count; i++ {
			states[taskID] = append(states[taskID], state)
		}
	}
	stateRows.Close()
	var filtered []Task
	for _, task := range all {
		task.Counts = taskCountsFromStates(states[task.ID])
		task.State, task.NeedsAttention, task.UnknownItems = AggregateItems(states[task.ID])
		if filter.State != "" && task.State != filter.State {
			continue
		}
		filtered = append(filtered, task)
	}
	total := len(filtered)
	start := (page - 1) * pageSize
	if start > total {
		start = total
	}
	end := start + pageSize
	if end > total {
		end = total
	}
	return Page[Task]{Items: filtered[start:end], Page: page, PageSize: pageSize, Total: total}, nil
}

func (s *Store) TaskItemEvents(ctx context.Context, itemID string) ([]TaskItemEvent, *protocol.APIError) {
	id, err := protocol.NormalizeUUID(itemID)
	if err != nil {
		return nil, &protocol.APIError{Code: protocol.CodeNotFound, Message: "invalid item id"}
	}
	rows, err := s.DB.QueryContext(ctx, `
SELECT sequence,attempt_no,event_type,details_json,created_at FROM dbo.task_item_events
WHERE item_id=@p1 ORDER BY sequence`, id)
	if err != nil {
		return nil, &protocol.APIError{Code: protocol.CodeDatabase, Message: "load task events"}
	}
	defer rows.Close()
	var events []TaskItemEvent
	for rows.Next() {
		var event TaskItemEvent
		var details sql.NullString
		if err := rows.Scan(&event.Sequence, &event.AttemptNo, &event.EventType, &details, &event.CreatedAt); err != nil {
			return nil, &protocol.APIError{Code: protocol.CodeDatabase, Message: "decode task event"}
		}
		if details.Valid {
			event.Details = json.RawMessage(details.String)
		}
		events = append(events, event)
	}
	return events, nil
}
