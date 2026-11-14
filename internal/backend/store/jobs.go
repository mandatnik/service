package store

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"time"

	mssql "github.com/microsoft/go-mssqldb"
	"telehack2026/internal/protocol"
)

// AckJob records the terminal state of a manual job. It is idempotent for the
// same state/report and returns job_conflict for a different terminal result.
func (s *Store) AckJob(ctx context.Context, identity *Identity, request *protocol.SignedRequest) (*protocol.JobAckResponse, *protocol.APIError) {
	now := s.now()
	tx, err := s.DB.BeginTx(ctx, &sql.TxOptions{})
	if err != nil {
		return nil, &protocol.APIError{Code: protocol.CodeDatabase, Message: "begin job ack transaction"}
	}
	defer tx.Rollback()
	if apiErr := recordRequest(ctx, tx, identity.UUID, request.Data.RequestID, protocol.PathJobAck, now); apiErr != nil {
		return nil, apiErr
	}
	var machineID mssql.UniqueIdentifier
	var state string
	var reportID mssql.NullUniqueIdentifier
	var taskRegistration sql.NullInt64
	err = tx.QueryRowContext(ctx, `
SELECT j.machine_id, j.state, j.report_id, ti.registration_id
FROM dbo.jobs j WITH (UPDLOCK, HOLDLOCK)
LEFT JOIN dbo.task_items ti ON ti.item_id=j.task_item_id
WHERE j.job_id=@p1`,
		request.Data.JobID).Scan(&machineID, &state, &reportID, &taskRegistration)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, &protocol.APIError{Code: protocol.CodeNotFound, Message: "job not found"}
	}
	if err != nil {
		return nil, &protocol.APIError{Code: protocol.CodeDatabase, Message: "load job"}
	}
	if uuidString(machineID) != identity.MachineID {
		return nil, &protocol.APIError{Code: protocol.CodeNotFound, Message: "job belongs to another machine"}
	}
	if taskRegistration.Valid && taskRegistration.Int64 != identity.RegistrationID {
		return nil, &protocol.APIError{Code: protocol.CodeNotFound, Message: "job belongs to another installation"}
	}
	terminal := state == "completed" || state == "failed" || state == "report_evicted"
	if terminal {
		sameReport := request.Data.JobReportID == ""
		if reportID.Valid && request.Data.JobReportID != "" {
			sameReport = strings.EqualFold(uuidString(reportID.UUID), request.Data.JobReportID)
		}
		if state == request.Data.JobStatus && sameReport {
			if err := tx.Commit(); err != nil {
				return nil, &protocol.APIError{Code: protocol.CodeDatabase, Message: "commit duplicate job ack"}
			}
			return &protocol.JobAckResponse{Accepted: true, JobID: request.Data.JobID, State: state, Duplicate: true}, nil
		}
		return nil, &protocol.APIError{Code: protocol.CodeJobConflict, Message: "job already has a different terminal state"}
	}
	if state == "canceled" {
		return nil, &protocol.APIError{Code: protocol.CodeJobConflict, Message: "job was canceled"}
	}
	if request.Data.JobReportID != "" {
		var reportMachine mssql.UniqueIdentifier
		err := tx.QueryRowContext(ctx, `SELECT machine_id FROM dbo.reports WHERE report_id=@p1`, request.Data.JobReportID).Scan(&reportMachine)
		if errors.Is(err, sql.ErrNoRows) {
			return nil, &protocol.APIError{Code: protocol.CodeReportInvalid, Message: "job report does not exist"}
		}
		if err != nil {
			return nil, &protocol.APIError{Code: protocol.CodeDatabase, Message: "load job report"}
		}
		if uuidString(reportMachine) != identity.MachineID {
			return nil, &protocol.APIError{Code: protocol.CodeReportInvalid, Message: "job report belongs to another machine"}
		}
	}
	var jobReport any
	if request.Data.JobReportID != "" {
		jobReport = request.Data.JobReportID
	}
	_, err = tx.ExecContext(ctx, `
UPDATE dbo.jobs SET state=@p1, completed_at=@p2, acknowledged_at=@p2, report_id=@p3, message=@p4
WHERE job_id=@p5`, request.Data.JobStatus, now, jobReport, truncate(request.Data.JobMessage, 1024), request.Data.JobID)
	if err != nil {
		return nil, &protocol.APIError{Code: protocol.CodeDatabase, Message: "update job"}
	}
	_ = insertEvent(ctx, tx, identity.MachineID, identity.RegistrationID, jobReport, request.Data.RequestID,
		"job_acknowledged", "info", "manual job completed", map[string]any{"job_id": request.Data.JobID, "state": request.Data.JobStatus}, now)
	if apiErr := updateTaskItemFromJobAckTx(ctx, tx, request.Data.JobID, request.Data.JobStatus, request.Data.JobReportID, request.Data.JobMessage, now); apiErr != nil {
		return nil, apiErr
	}
	if err := tx.Commit(); err != nil {
		return nil, &protocol.APIError{Code: protocol.CodeDatabase, Message: "commit job ack"}
	}
	return &protocol.JobAckResponse{Accepted: true, JobID: request.Data.JobID, State: request.Data.JobStatus}, nil
}

func updateTaskItemFromJobAckTx(ctx context.Context, tx *sql.Tx, jobID, jobStatus, reportID, message string, now time.Time) *protocol.APIError {
	var itemID mssql.NullUniqueIdentifier
	err := tx.QueryRowContext(ctx, `SELECT task_item_id FROM dbo.jobs WITH (UPDLOCK,HOLDLOCK) WHERE job_id=@p1`, jobID).Scan(&itemID)
	if errors.Is(err, sql.ErrNoRows) || !itemID.Valid {
		if err == nil || errors.Is(err, sql.ErrNoRows) {
			return nil
		}
		return &protocol.APIError{Code: protocol.CodeDatabase, Message: "load linked task item"}
	}
	if err != nil {
		return &protocol.APIError{Code: protocol.CodeDatabase, Message: "load linked task item"}
	}
	id := uuidString(itemID.UUID)
	var itemState string
	var resultVersion sql.NullInt64
	err = tx.QueryRowContext(ctx, `SELECT state,result_version FROM dbo.task_items WITH (UPDLOCK,HOLDLOCK) WHERE item_id=@p1`, id).Scan(&itemState, &resultVersion)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return &protocol.APIError{Code: protocol.CodeDatabase, Message: "load task item for job ack"}
	}
	if itemState == protocol.TaskStateSucceeded && jobStatus != "completed" {
		return nil
	}
	if jobStatus == "completed" && reportID == "" {
		jobStatus = "failed"
		message = "report_required"
	}
	next := protocol.TaskStateFailed
	switch jobStatus {
	case "completed":
		next = protocol.TaskStateSucceeded
	case "report_evicted":
		next = protocol.TaskStateFailed
	}
	reason := ""
	if jobStatus != "completed" {
		reason = "legacy_job_" + jobStatus
	}
	var completed any
	if protocol.IsTerminalTaskState(next) {
		completed = now
	}
	var report any
	if reportID != "" {
		report = reportID
	}
	if _, err := tx.ExecContext(ctx, `
UPDATE dbo.task_items SET state=@p1,reason_code=@p2,completed_at=@p3,updated_at=@p3,last_seen_at=@p3,
 scan_report_id=COALESCE(@p4,scan_report_id) WHERE item_id=@p5`,
		next, nilIfEmpty(reason), completed, report, id); err != nil {
		return &protocol.APIError{Code: protocol.CodeDatabase, Message: "update linked task item"}
	}
	var sequence int
	if err := tx.QueryRowContext(ctx, `SELECT ISNULL(MAX(sequence),0)+1 FROM dbo.task_item_events WITH (UPDLOCK,HOLDLOCK) WHERE item_id=@p1`, id).Scan(&sequence); err == nil {
		_ = insertTaskEventTx(ctx, tx, id, sequence, 0, "legacy_job_ack", map[string]any{"job_id": jobID, "state": jobStatus, "message": truncate(message, 1024)}, now)
	}
	return nil
}

// BackfillLegacyJobs maps jobs that an older backend created after the
// migration was applied. It is safe to run repeatedly; only jobs without
// task_item_id and with an existing registration are mapped.
func (s *Store) BackfillLegacyJobs(ctx context.Context) error {
	_, err := s.DB.ExecContext(ctx, `
DECLARE @mapping TABLE (job_id UNIQUEIDENTIFIER PRIMARY KEY, task_id UNIQUEIDENTIFIER, item_id UNIQUEIDENTIFIER);
INSERT INTO @mapping(job_id, task_id, item_id)
SELECT j.job_id, NEWID(), NEWID() FROM dbo.jobs j
WHERE j.task_item_id IS NULL AND EXISTS (SELECT 1 FROM dbo.registrations r WHERE r.machine_id=j.machine_id);
INSERT INTO dbo.tasks(task_id,kind,created_by,created_at,expires_at,settings_snapshot,selection_snapshot,legacy_job_id)
SELECT m.task_id,N'scan',j.created_by,j.created_at,
 CASE WHEN j.state IN (N'pending',N'delivered') THEN DATEADD(SECOND,604800,SYSUTCDATETIME()) ELSE DATEADD(SECOND,604800,j.created_at) END,
 N'{}',N'{"source":"legacy_job_backfill"}',j.job_id
FROM dbo.jobs j JOIN @mapping m ON m.job_id=j.job_id;
INSERT INTO dbo.task_items(item_id,task_id,machine_id,registration_id,kind,state,reason_code,delivery_version,attempt_count,started_at,completed_at,scan_report_id,legacy_job_id,created_at,updated_at)
SELECT m.item_id,m.task_id,j.machine_id,
 COALESCE((SELECT TOP 1 r.registration_id FROM dbo.registrations r WHERE r.machine_id=j.machine_id AND r.state=N'active' ORDER BY r.created_at DESC),
          (SELECT TOP 1 r.registration_id FROM dbo.registrations r WHERE r.machine_id=j.machine_id ORDER BY r.created_at DESC)),
 N'scan',
 CASE j.state WHEN N'pending' THEN N'queued' WHEN N'delivered' THEN N'delivered' WHEN N'completed' THEN N'succeeded' WHEN N'canceled' THEN N'cancelled' ELSE N'failed' END,
 CASE j.state WHEN N'failed' THEN N'legacy_failed' WHEN N'report_evicted' THEN N'report_evicted' WHEN N'canceled' THEN N'legacy_cancelled' ELSE NULL END,
 0,0,
 CASE WHEN j.state IN (N'delivered',N'completed',N'failed',N'report_evicted',N'canceled') THEN j.created_at ELSE NULL END,
 CASE WHEN j.state IN (N'completed',N'failed',N'report_evicted',N'canceled') THEN COALESCE(j.completed_at,j.created_at) ELSE NULL END,
 j.report_id,j.job_id,j.created_at,COALESCE(j.completed_at,j.created_at)
FROM dbo.jobs j JOIN @mapping m ON m.job_id=j.job_id;
UPDATE j SET j.task_id=m.task_id,j.task_item_id=m.item_id FROM dbo.jobs j JOIN @mapping m ON m.job_id=j.job_id;
INSERT INTO dbo.task_item_events(item_id,sequence,attempt_no,event_type,details_json,created_at)
SELECT m.item_id,1,0,N'legacy_job_backfilled',(SELECT j.job_id AS job_id,j.state AS state FOR JSON PATH, WITHOUT_ARRAY_WRAPPER),j.created_at
FROM dbo.jobs j JOIN @mapping m ON m.job_id=j.job_id;`)
	return err
}

// PendingJobs reports jobs for a machine; used by acceptance checks.
func (s *Store) PendingJobs(ctx context.Context, machineID string) ([]protocol.Job, error) {
	rows, err := s.DB.QueryContext(ctx, `
SELECT job_id, kind, created_at FROM dbo.jobs WHERE machine_id=@p1 AND state IN (N'pending',N'delivered') ORDER BY created_at`, machineID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var jobs []protocol.Job
	for rows.Next() {
		var id mssql.UniqueIdentifier
		var kind string
		var created time.Time
		if err := rows.Scan(&id, &kind, &created); err != nil {
			return nil, err
		}
		jobs = append(jobs, protocol.Job{JobID: uuidString(id), Kind: kind, CreatedAt: created.UTC().Format(time.RFC3339Nano)})
	}
	return jobs, rows.Err()
}
