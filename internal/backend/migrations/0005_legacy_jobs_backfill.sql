-- Backfill legacy jobs created by an older backend during a rolling upgrade or
-- by acceptance tools after migration 0004. Additive and repeatable: only jobs
-- without task_item_id are mapped.
IF OBJECT_ID(N'dbo.tasks', N'U') IS NOT NULL AND OBJECT_ID(N'dbo.task_items', N'U') IS NOT NULL
BEGIN
    DECLARE @mapping TABLE (job_id UNIQUEIDENTIFIER PRIMARY KEY, task_id UNIQUEIDENTIFIER, item_id UNIQUEIDENTIFIER);
    INSERT INTO @mapping(job_id, task_id, item_id)
    SELECT j.job_id, NEWID(), NEWID()
    FROM dbo.jobs j
    WHERE j.task_item_id IS NULL
      AND EXISTS (SELECT 1 FROM dbo.registrations r WHERE r.machine_id=j.machine_id);

    INSERT INTO dbo.tasks(task_id, kind, created_by, created_at, expires_at, settings_snapshot, selection_snapshot, legacy_job_id)
    SELECT m.task_id, N'scan', j.created_by, j.created_at,
           CASE WHEN j.state IN (N'pending',N'delivered') THEN DATEADD(SECOND, 604800, SYSUTCDATETIME())
                ELSE DATEADD(SECOND, 604800, j.created_at) END,
           N'{}', N'{"source":"legacy_job_backfill"}', j.job_id
    FROM dbo.jobs j JOIN @mapping m ON m.job_id=j.job_id;

    INSERT INTO dbo.task_items(item_id, task_id, machine_id, registration_id, kind, state, reason_code,
        delivery_version, attempt_count, started_at, completed_at, scan_report_id, legacy_job_id, created_at, updated_at)
    SELECT m.item_id, m.task_id, j.machine_id,
           COALESCE((SELECT TOP 1 r.registration_id FROM dbo.registrations r
                     WHERE r.machine_id=j.machine_id AND r.state=N'active' ORDER BY r.created_at DESC),
                    (SELECT TOP 1 r.registration_id FROM dbo.registrations r
                     WHERE r.machine_id=j.machine_id ORDER BY r.created_at DESC)),
           N'scan',
           CASE j.state WHEN N'pending' THEN N'queued' WHEN N'delivered' THEN N'delivered'
                WHEN N'completed' THEN N'succeeded' WHEN N'canceled' THEN N'cancelled' ELSE N'failed' END,
           CASE j.state WHEN N'failed' THEN N'legacy_failed' WHEN N'report_evicted' THEN N'report_evicted'
                WHEN N'canceled' THEN N'legacy_cancelled' ELSE NULL END,
           0, 0,
           CASE WHEN j.state IN (N'delivered',N'completed',N'failed',N'report_evicted',N'canceled') THEN j.created_at ELSE NULL END,
           CASE WHEN j.state IN (N'completed',N'failed',N'report_evicted',N'canceled') THEN COALESCE(j.completed_at,j.created_at) ELSE NULL END,
           j.report_id, j.job_id, j.created_at, COALESCE(j.completed_at,j.created_at)
    FROM dbo.jobs j JOIN @mapping m ON m.job_id=j.job_id;

    UPDATE j SET j.task_id=m.task_id, j.task_item_id=m.item_id
    FROM dbo.jobs j JOIN @mapping m ON m.job_id=j.job_id;

    INSERT INTO dbo.task_item_events(item_id, sequence, attempt_no, event_type, details_json, created_at)
    SELECT m.item_id, 1, 0, N'legacy_job_backfilled',
           (SELECT j.job_id AS job_id, j.state AS state FOR JSON PATH, WITHOUT_ARRAY_WRAPPER),
           j.created_at
    FROM dbo.jobs j JOIN @mapping m ON m.job_id=j.job_id;
END
GO
