package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"time"

	mssql "github.com/microsoft/go-mssqldb"
	"telehack2026/internal/protocol"
)

// SyncResult is the server response for polling configuration and jobs.
type SyncResult struct {
	Config     *protocol.AgentConfig
	ConfigHash string
	Jobs       []protocol.Job
	Warnings   []string
	ServerTime time.Time
}

// Sync records the request, returns pending jobs even when the configuration
// hash is unchanged, and marks delivered jobs as delivered. Delivered jobs
// remain returned until acknowledged so a lost response does not lose work.
func (s *Store) Sync(ctx context.Context, identity *Identity, request *protocol.SignedRequest, sourceIP net.IP, dnsStatus string) (*SyncResult, *protocol.APIError) {
	now := s.now()
	tx, err := s.DB.BeginTx(ctx, &sql.TxOptions{})
	if err != nil {
		return nil, &protocol.APIError{Code: protocol.CodeDatabase, Message: "begin sync transaction"}
	}
	defer tx.Rollback()

	if apiErr := recordRequest(ctx, tx, identity.UUID, request.Data.RequestID, protocol.PathSync, now); apiErr != nil {
		return nil, apiErr
	}
	if _, err := tx.ExecContext(ctx, `
UPDATE dbo.registrations SET last_seen_at=@p1, last_source_ip=@p2, last_dns_status=@p3, last_dns_checked_at=@p1
WHERE registration_id=@p4`, now, ipBytes(sourceIP), dnsStatus, identity.RegistrationID); err != nil {
		return nil, &protocol.APIError{Code: protocol.CodeDatabase, Message: "update registration activity"}
	}
	if _, err := tx.ExecContext(ctx, `UPDATE dbo.hostnames SET last_seen_at=@p1 WHERE hostname_norm=@p2`, now, identity.HostnameNorm); err != nil {
		return nil, &protocol.APIError{Code: protocol.CodeDatabase, Message: "update hostname activity"}
	}

	var capable bool
	if err := tx.QueryRowContext(ctx, `
SELECT CASE WHEN EXISTS(
  SELECT 1 FROM dbo.agent_capabilities c
  JOIN dbo.registrations r ON r.registration_id=c.registration_id
  WHERE r.machine_id=@p1 AND r.state=N'active' AND c.tasks_v1=1) THEN 1 ELSE 0 END`, identity.MachineID).Scan(&capable); err != nil {
		return nil, &protocol.APIError{Code: protocol.CodeDatabase, Message: "load agent task capability"}
	}
	rows, err := tx.QueryContext(ctx, `
SELECT j.job_id, j.kind, j.created_at FROM dbo.jobs j WITH (UPDLOCK, ROWLOCK)
WHERE j.machine_id=@p1 AND j.state IN (N'pending', N'delivered')
  AND (@p2=0 OR j.task_item_id IS NULL)
ORDER BY j.created_at`, identity.MachineID, capable)
	if err != nil {
		return nil, &protocol.APIError{Code: protocol.CodeDatabase, Message: "load jobs"}
	}
	var jobs []protocol.Job
	for rows.Next() {
		var jobID mssql.UniqueIdentifier
		var kind string
		var createdAt time.Time
		if err := rows.Scan(&jobID, &kind, &createdAt); err != nil {
			rows.Close()
			return nil, &protocol.APIError{Code: protocol.CodeDatabase, Message: "decode job"}
		}
		jobs = append(jobs, protocol.Job{JobID: uuidString(jobID), Kind: kind, CreatedAt: createdAt.UTC().Format(time.RFC3339Nano)})
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, &protocol.APIError{Code: protocol.CodeDatabase, Message: "iterate jobs"}
	}
	rows.Close()
	if jobs == nil {
		jobs = []protocol.Job{}
	}
	for _, job := range jobs {
		if _, err := tx.ExecContext(ctx, `
UPDATE dbo.jobs SET state=N'delivered', delivered_at=COALESCE(delivered_at,@p1), last_delivered_at=@p1
WHERE job_id=@p2 AND state IN (N'pending', N'delivered')`, now, job.JobID); err != nil {
			return nil, &protocol.APIError{Code: protocol.CodeDatabase, Message: "mark job delivered"}
		}
	}
	config, configErr := effectiveConfigTx(ctx, tx, identity.MachineID)
	if configErr != nil {
		return nil, &protocol.APIError{Code: protocol.CodeDatabase, Message: configErr.Error()}
	}
	if err := tx.Commit(); err != nil {
		return nil, &protocol.APIError{Code: protocol.CodeDatabase, Message: "commit sync"}
	}
	result := &SyncResult{ConfigHash: config.Hash, Jobs: jobs, ServerTime: now}
	if request.Data.ConfigHash == "" || request.Data.ConfigHash != config.Hash {
		cfg := config.Config
		result.Config = &cfg
	}
	if dnsStatus == "mismatch" || dnsStatus == "error" {
		result.Warnings = append(result.Warnings, "dns_unverified")
	}
	return result, nil
}

// AddJob creates a manual scan job and its unified task/item representation.
// Old agents continue to receive the job through sync; capable agents receive
// the linked task item through the encrypted task channel.
func (s *Store) AddJob(ctx context.Context, machineID, createdBy string) (string, error) {
	jobID := protocol.NewUUID()
	taskID := protocol.NewUUID()
	itemID := protocol.NewUUID()
	now := s.now()
	tx, err := s.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return "", fmt.Errorf("begin job transaction: %w", err)
	}
	defer tx.Rollback()
	var registrationID int64
	err = tx.QueryRowContext(ctx, `
SELECT TOP 1 registration_id FROM dbo.registrations WITH (UPDLOCK,HOLDLOCK)
WHERE machine_id=@p1 AND state=N'active' ORDER BY created_at DESC`, machineID).Scan(&registrationID)
	if errors.Is(err, sql.ErrNoRows) {
		return "", fmt.Errorf("machine has no active registration")
	}
	if err != nil {
		return "", fmt.Errorf("load active registration: %w", err)
	}
	selection, _ := json.Marshal(map[string]any{"source": "admin_job", "machine_ids": []string{machineID}})
	if _, err := tx.ExecContext(ctx, `
INSERT INTO dbo.tasks(task_id,kind,created_by,created_at,expires_at,settings_snapshot,selection_snapshot,legacy_job_id)
VALUES(@p1,N'scan',@p2,@p3,@p4,N'{}',@p5,@p6)`,
		taskID, createdBy, now, now.Add(time.Duration(protocol.DefaultTaskTTLSeconds)*time.Second), string(selection), jobID); err != nil {
		return "", fmt.Errorf("create task for job: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `
INSERT INTO dbo.task_items(item_id,task_id,machine_id,registration_id,kind,state,delivery_version,created_at,updated_at,legacy_job_id)
VALUES(@p1,@p2,@p3,@p4,N'scan',N'queued',0,@p5,@p5,@p6)`,
		itemID, taskID, machineID, registrationID, now, jobID); err != nil {
		return "", fmt.Errorf("create task item for job: %w", err)
	}
	_, err = tx.ExecContext(ctx, `
INSERT INTO dbo.jobs (job_id, machine_id, kind, state, created_at, created_by, task_id, task_item_id)
VALUES (@p1, @p2, N'scan', N'pending', @p3, @p4, @p5, @p6)`, jobID, machineID, now, createdBy, taskID, itemID)
	if err != nil {
		return "", fmt.Errorf("create job: %w", err)
	}
	if err := insertTaskEventTx(ctx, tx, itemID, 1, 0, "created", map[string]any{"kind": "scan", "source": "admin_job"}, now); err != nil {
		return "", fmt.Errorf("record job event: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return "", fmt.Errorf("commit job: %w", err)
	}
	return jobID, nil
}

// SetConfig validates and replaces the single configuration row. It is used by
// the future admin API and by acceptance tests; the version is incremented by
// the server, never trusted from the caller.
func (s *Store) SetConfig(ctx context.Context, cfg protocol.AgentConfig, updatedBy string) (protocol.AgentConfig, string, error) {
	if len(cfg.CertDirectories) > 0 || len(cfg.FolderPolicies) > 0 {
		return protocol.AgentConfig{}, "", fmt.Errorf("папки задаются только назначаемыми политиками")
	}

	tx, err := s.DB.BeginTx(ctx, &sql.TxOptions{})
	if err != nil {
		return protocol.AgentConfig{}, "", err
	}
	defer tx.Rollback()
	var currentVersion int
	if err := tx.QueryRowContext(ctx, `SELECT version FROM dbo.configs WITH (UPDLOCK, HOLDLOCK) WHERE config_id=1`).Scan(&currentVersion); err != nil {
		return protocol.AgentConfig{}, "", fmt.Errorf("read current config version: %w", err)
	}
	cfg.Version = currentVersion + 1
	if err := protocol.ValidateConfig(&cfg); err != nil {
		return protocol.AgentConfig{}, "", err
	}
	canonical, err := protocol.CanonicalConfig(cfg)
	if err != nil {
		return protocol.AgentConfig{}, "", err
	}
	hash, err := protocol.ConfigHash(cfg)
	if err != nil {
		return protocol.AgentConfig{}, "", err
	}
	if _, err := tx.ExecContext(ctx, `
UPDATE dbo.configs SET version=@p1, config_json=@p2, config_hash=@p3, updated_at=@p4, updated_by=@p5 WHERE config_id=1`,
		cfg.Version, string(canonical), hash, s.now(), updatedBy); err != nil {
		return protocol.AgentConfig{}, "", fmt.Errorf("update config: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return protocol.AgentConfig{}, "", err
	}
	return cfg, hash, nil
}
