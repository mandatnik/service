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
	err = tx.QueryRowContext(ctx, `
SELECT machine_id, state, report_id FROM dbo.jobs WITH (UPDLOCK, HOLDLOCK) WHERE job_id=@p1`,
		request.Data.JobID).Scan(&machineID, &state, &reportID)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, &protocol.APIError{Code: protocol.CodeNotFound, Message: "job not found"}
	}
	if err != nil {
		return nil, &protocol.APIError{Code: protocol.CodeDatabase, Message: "load job"}
	}
	if uuidString(machineID) != identity.MachineID {
		return nil, &protocol.APIError{Code: protocol.CodeNotFound, Message: "job belongs to another machine"}
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
	if err := tx.Commit(); err != nil {
		return nil, &protocol.APIError{Code: protocol.CodeDatabase, Message: "commit job ack"}
	}
	return &protocol.JobAckResponse{Accepted: true, JobID: request.Data.JobID, State: request.Data.JobStatus}, nil
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
