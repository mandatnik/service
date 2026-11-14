-- Remote activation, license pools and the unified task model.
-- Additive only: no existing report, job, registration or user row is deleted.

IF COL_LENGTH('dbo.reports', 'profiles_complete') IS NULL
    ALTER TABLE dbo.reports ADD profiles_complete BIT NULL;
GO
IF COL_LENGTH('dbo.reports', 'personal_complete') IS NULL
    ALTER TABLE dbo.reports ADD personal_complete BIT NULL;
GO
IF COL_LENGTH('dbo.csp_states', 'environment') IS NULL
    ALTER TABLE dbo.csp_states ADD environment NVARCHAR(16) NULL;
GO
IF COL_LENGTH('dbo.jobs', 'task_id') IS NULL
    ALTER TABLE dbo.jobs ADD task_id UNIQUEIDENTIFIER NULL;
GO
IF COL_LENGTH('dbo.jobs', 'task_item_id') IS NULL
    ALTER TABLE dbo.jobs ADD task_item_id UNIQUEIDENTIFIER NULL;
GO

IF OBJECT_ID(N'dbo.agent_capabilities', N'U') IS NULL
BEGIN
    CREATE TABLE dbo.agent_capabilities (
        registration_id BIGINT NOT NULL CONSTRAINT PK_agent_capabilities PRIMARY KEY,
        capabilities_json NVARCHAR(MAX) NOT NULL,
        schedule_v2 BIT NOT NULL CONSTRAINT DF_agent_capabilities_schedule DEFAULT 0,
        tasks_v1 BIT NOT NULL CONSTRAINT DF_agent_capabilities_tasks DEFAULT 0,
        install_v1 BIT NOT NULL CONSTRAINT DF_agent_capabilities_install DEFAULT 0,
        updated_at DATETIME2(3) NOT NULL,
        CONSTRAINT FK_agent_capabilities_registration FOREIGN KEY (registration_id)
            REFERENCES dbo.registrations(registration_id)
    );
END
GO

IF OBJECT_ID(N'dbo.agent_encryption_keys', N'U') IS NULL
BEGIN
    CREATE TABLE dbo.agent_encryption_keys (
        encryption_key_pk BIGINT IDENTITY(1,1) NOT NULL CONSTRAINT PK_agent_encryption_keys PRIMARY KEY,
        key_id CHAR(64) NOT NULL,
        machine_id UNIQUEIDENTIFIER NOT NULL,
        registration_id BIGINT NOT NULL,
        public_key_pem NVARCHAR(MAX) NOT NULL,
        algorithm NVARCHAR(64) NOT NULL,
        bits INT NOT NULL,
        active BIT NOT NULL CONSTRAINT DF_agent_encryption_keys_active DEFAULT 1,
        created_at DATETIME2(3) NOT NULL,
        revoked_at DATETIME2(3) NULL,
        CONSTRAINT UQ_agent_encryption_keys_registration_key UNIQUE (registration_id, key_id),
        CONSTRAINT FK_agent_encryption_keys_machine FOREIGN KEY (machine_id) REFERENCES dbo.machines(machine_id),
        CONSTRAINT FK_agent_encryption_keys_registration FOREIGN KEY (registration_id) REFERENCES dbo.registrations(registration_id)
    );
    CREATE UNIQUE INDEX UQ_agent_encryption_keys_active
        ON dbo.agent_encryption_keys(machine_id) WHERE active = 1 AND revoked_at IS NULL;
END
GO

IF OBJECT_ID(N'dbo.license_pools', N'U') IS NULL
BEGIN
    CREATE TABLE dbo.license_pools (
        pool_id UNIQUEIDENTIFIER NOT NULL CONSTRAINT PK_license_pools PRIMARY KEY,
        name NVARCHAR(200) NOT NULL,
        csp_major_version INT NOT NULL,
        license_kind NVARCHAR(16) NOT NULL,
        term NVARCHAR(24) NOT NULL,
        archived_at DATETIME2(3) NULL,
        created_at DATETIME2(3) NOT NULL,
        created_by NVARCHAR(128) NULL,
        updated_at DATETIME2(3) NOT NULL,
        updated_by NVARCHAR(128) NULL,
        CONSTRAINT UQ_license_pools_name UNIQUE (name),
        CONSTRAINT CK_license_pools_csp CHECK (csp_major_version IN (4,5)),
        CONSTRAINT CK_license_pools_kind CHECK (license_kind IN (N'client',N'server')),
        CONSTRAINT CK_license_pools_term CHECK (term IN (N'one_year',N'two_years',N'perpetual'))
    );
END
GO

IF OBJECT_ID(N'dbo.licenses', N'U') IS NULL
BEGIN
    CREATE TABLE dbo.licenses (
        license_id UNIQUEIDENTIFIER NOT NULL CONSTRAINT PK_licenses PRIMARY KEY,
        pool_id UNIQUEIDENTIFIER NOT NULL,
        encrypted_serial VARBINARY(MAX) NOT NULL,
        encryption_key_id NVARCHAR(64) NOT NULL,
        serial_fingerprint BINARY(32) NOT NULL,
        serial_mask NVARCHAR(64) NOT NULL,
        state NVARCHAR(24) NOT NULL,
        assigned_machine_id UNIQUEIDENTIFIER NULL,
        assigned_task_item_id UNIQUEIDENTIFIER NULL,
        reserved_at DATETIME2(3) NULL,
        used_at DATETIME2(3) NULL,
        last_error_code NVARCHAR(128) NULL,
        created_at DATETIME2(3) NOT NULL,
        created_by NVARCHAR(128) NULL,
        updated_at DATETIME2(3) NOT NULL,
        CONSTRAINT UQ_licenses_fingerprint UNIQUE (serial_fingerprint),
        CONSTRAINT FK_licenses_pool FOREIGN KEY (pool_id) REFERENCES dbo.license_pools(pool_id),
        CONSTRAINT FK_licenses_machine FOREIGN KEY (assigned_machine_id) REFERENCES dbo.machines(machine_id),
        CONSTRAINT CK_licenses_state CHECK (state IN (N'available',N'reserved',N'used',N'outcome_unknown',N'blocked'))
    );
    CREATE INDEX IX_licenses_pool_state ON dbo.licenses(pool_id, state, created_at);
    CREATE INDEX IX_licenses_machine ON dbo.licenses(assigned_machine_id);
END
GO

IF OBJECT_ID(N'dbo.previews', N'U') IS NULL
BEGIN
    CREATE TABLE dbo.previews (
        preview_id UNIQUEIDENTIFIER NOT NULL CONSTRAINT PK_previews PRIMARY KEY,
        pool_id UNIQUEIDENTIFIER NOT NULL,
        created_by NVARCHAR(128) NULL,
        created_at DATETIME2(3) NOT NULL,
        expires_at DATETIME2(3) NOT NULL,
        request_digest CHAR(64) NOT NULL,
        snapshot_json NVARCHAR(MAX) NOT NULL,
        consumed_at DATETIME2(3) NULL,
        CONSTRAINT FK_previews_pool FOREIGN KEY (pool_id) REFERENCES dbo.license_pools(pool_id)
    );
    CREATE INDEX IX_previews_expires ON dbo.previews(expires_at);
END
GO

IF OBJECT_ID(N'dbo.tasks', N'U') IS NULL
BEGIN
    CREATE TABLE dbo.tasks (
        task_id UNIQUEIDENTIFIER NOT NULL CONSTRAINT PK_tasks PRIMARY KEY,
        kind NVARCHAR(32) NOT NULL,
        created_by NVARCHAR(128) NULL,
        created_at DATETIME2(3) NOT NULL,
        expires_at DATETIME2(3) NOT NULL,
        settings_snapshot NVARCHAR(MAX) NULL,
        selection_snapshot NVARCHAR(MAX) NULL,
        idempotency_key NVARCHAR(128) NULL,
        request_digest CHAR(64) NULL,
        preview_id UNIQUEIDENTIFIER NULL,
        cancel_requested_at DATETIME2(3) NULL,
        legacy_job_id UNIQUEIDENTIFIER NULL,
        CONSTRAINT CK_tasks_kind CHECK (kind IN (N'scan',N'install_license'))
    );
    CREATE UNIQUE INDEX UQ_tasks_idempotency ON dbo.tasks(idempotency_key) WHERE idempotency_key IS NOT NULL;
    CREATE INDEX IX_tasks_created ON dbo.tasks(created_at DESC);
END
GO

IF OBJECT_ID(N'dbo.task_items', N'U') IS NULL
BEGIN
    CREATE TABLE dbo.task_items (
        item_id UNIQUEIDENTIFIER NOT NULL CONSTRAINT PK_task_items PRIMARY KEY,
        task_id UNIQUEIDENTIFIER NOT NULL,
        machine_id UNIQUEIDENTIFIER NOT NULL,
        registration_id BIGINT NOT NULL,
        kind NVARCHAR(32) NOT NULL,
        state NVARCHAR(24) NOT NULL,
        reason_code NVARCHAR(128) NULL,
        delivery_version INT NOT NULL CONSTRAINT DF_task_items_delivery DEFAULT 1,
        encryption_key_id CHAR(64) NULL,
        encrypted_parameters VARBINARY(MAX) NULL,
        license_id UNIQUEIDENTIFIER NULL,
        allow_trial_replacement BIT NOT NULL CONSTRAINT DF_task_items_trial DEFAULT 0,
        attempt_count INT NOT NULL CONSTRAINT DF_task_items_attempts DEFAULT 0,
        next_attempt_at DATETIME2(3) NULL,
        started_at DATETIME2(3) NULL,
        completed_at DATETIME2(3) NULL,
        last_seen_at DATETIME2(3) NULL,
        result_version INT NULL,
        sanitized_result NVARCHAR(MAX) NULL,
        scan_report_id UNIQUEIDENTIFIER NULL,
        claim_expires_at DATETIME2(3) NULL,
        cancel_requested_at DATETIME2(3) NULL,
        reconcile_requested_at DATETIME2(3) NULL,
        last_progress_at DATETIME2(3) NULL,
        legacy_job_id UNIQUEIDENTIFIER NULL,
        created_at DATETIME2(3) NOT NULL,
        updated_at DATETIME2(3) NOT NULL,
        CONSTRAINT UQ_task_items_task_machine UNIQUE (task_id, machine_id),
        CONSTRAINT FK_task_items_task FOREIGN KEY (task_id) REFERENCES dbo.tasks(task_id),
        CONSTRAINT FK_task_items_machine FOREIGN KEY (machine_id) REFERENCES dbo.machines(machine_id),
        CONSTRAINT FK_task_items_registration FOREIGN KEY (registration_id) REFERENCES dbo.registrations(registration_id),
        CONSTRAINT FK_task_items_license FOREIGN KEY (license_id) REFERENCES dbo.licenses(license_id),
        CONSTRAINT CK_task_items_kind CHECK (kind IN (N'scan',N'install_license')),
        CONSTRAINT CK_task_items_state CHECK (state IN (N'queued',N'delivered',N'running',N'retry_wait',N'succeeded',N'skipped',N'failed',N'outcome_unknown',N'cancelled',N'expired'))
    );
    CREATE INDEX IX_task_items_machine_state ON dbo.task_items(machine_id, state, created_at);
    CREATE INDEX IX_task_items_task ON dbo.task_items(task_id, state);
    CREATE INDEX IX_task_items_due ON dbo.task_items(state, next_attempt_at);
    CREATE UNIQUE INDEX UQ_task_items_one_open_install
        ON dbo.task_items(machine_id) WHERE license_id IS NOT NULL AND completed_at IS NULL;
END
GO

IF OBJECT_ID(N'dbo.task_item_events', N'U') IS NULL
BEGIN
    CREATE TABLE dbo.task_item_events (
        event_id BIGINT IDENTITY(1,1) NOT NULL CONSTRAINT PK_task_item_events PRIMARY KEY,
        item_id UNIQUEIDENTIFIER NOT NULL,
        sequence INT NOT NULL,
        attempt_no INT NOT NULL CONSTRAINT DF_task_item_events_attempt DEFAULT 0,
        event_type NVARCHAR(64) NOT NULL,
        details_json NVARCHAR(MAX) NULL,
        created_at DATETIME2(3) NOT NULL,
        CONSTRAINT UQ_task_item_events_sequence UNIQUE (item_id, sequence),
        CONSTRAINT FK_task_item_events_item FOREIGN KEY (item_id) REFERENCES dbo.task_items(item_id)
    );
    CREATE INDEX IX_task_item_events_item ON dbo.task_item_events(item_id, sequence);
END
GO

IF OBJECT_ID(N'dbo.license_assignments', N'U') IS NULL
BEGIN
    CREATE TABLE dbo.license_assignments (
        assignment_id UNIQUEIDENTIFIER NOT NULL CONSTRAINT PK_license_assignments PRIMARY KEY,
        license_id UNIQUEIDENTIFIER NOT NULL,
        machine_id UNIQUEIDENTIFIER NOT NULL,
        task_item_id UNIQUEIDENTIFIER NOT NULL,
        state NVARCHAR(24) NOT NULL,
        created_at DATETIME2(3) NOT NULL,
        released_at DATETIME2(3) NULL,
        released_reason NVARCHAR(128) NULL,
        CONSTRAINT FK_license_assignments_license FOREIGN KEY (license_id) REFERENCES dbo.licenses(license_id),
        CONSTRAINT FK_license_assignments_machine FOREIGN KEY (machine_id) REFERENCES dbo.machines(machine_id),
        CONSTRAINT FK_license_assignments_item FOREIGN KEY (task_item_id) REFERENCES dbo.task_items(item_id),
        CONSTRAINT CK_license_assignments_state CHECK (state IN (N'reserved',N'used',N'outcome_unknown',N'released'))
    );
    CREATE UNIQUE INDEX UQ_license_assignments_license_open
        ON dbo.license_assignments(license_id) WHERE released_at IS NULL;
    CREATE UNIQUE INDEX UQ_license_assignments_machine_reserved
        ON dbo.license_assignments(machine_id) WHERE released_at IS NULL AND state = N'reserved';
END
GO

IF OBJECT_ID(N'dbo.license_events', N'U') IS NULL
BEGIN
    CREATE TABLE dbo.license_events (
        event_id BIGINT IDENTITY(1,1) NOT NULL CONSTRAINT PK_license_events PRIMARY KEY,
        license_id UNIQUEIDENTIFIER NULL,
        pool_id UNIQUEIDENTIFIER NULL,
        kind NVARCHAR(64) NOT NULL,
        actor NVARCHAR(128) NULL,
        details_json NVARCHAR(MAX) NULL,
        created_at DATETIME2(3) NOT NULL,
        CONSTRAINT FK_license_events_license FOREIGN KEY (license_id) REFERENCES dbo.licenses(license_id),
        CONSTRAINT FK_license_events_pool FOREIGN KEY (pool_id) REFERENCES dbo.license_pools(pool_id)
    );
    CREATE INDEX IX_license_events_created ON dbo.license_events(created_at DESC);
END
GO

IF OBJECT_ID(N'dbo.certificate_observation_bindings', N'U') IS NULL
BEGIN
    CREATE TABLE dbo.certificate_observation_bindings (
        binding_id BIGINT IDENTITY(1,1) NOT NULL CONSTRAINT PK_certificate_observation_bindings PRIMARY KEY,
        observation_id BIGINT NOT NULL,
        binding_index INT NOT NULL,
        provider_name NVARCHAR(512) NULL,
        provider_api NVARCHAR(16) NULL,
        provider_type INT NULL,
        key_spec INT NULL,
        binding_state NVARCHAR(16) NOT NULL,
        provider_owner NVARCHAR(16) NOT NULL,
        attribution_source NVARCHAR(128) NULL,
        attribution_version NVARCHAR(64) NULL,
        private_key_state NVARCHAR(24) NOT NULL,
        metadata_error_code NVARCHAR(128) NULL,
        observed_at DATETIME2(3) NULL,
        CONSTRAINT UQ_observation_bindings UNIQUE (observation_id, binding_index),
        CONSTRAINT FK_observation_bindings_observation FOREIGN KEY (observation_id)
            REFERENCES dbo.certificate_observations(observation_id)
    );
    CREATE INDEX IX_observation_bindings_owner ON dbo.certificate_observation_bindings(observation_id, provider_owner, binding_state);
END
GO

-- Preserve historical jobs as tasks. Pending/delivered rows remain deliverable
-- by their original agent through the legacy jobs channel; capable agents get
-- the same item through the encrypted task channel.
IF NOT EXISTS (SELECT 1 FROM dbo.tasks WHERE legacy_job_id IS NOT NULL)
BEGIN
    DECLARE @mapping TABLE (job_id UNIQUEIDENTIFIER PRIMARY KEY, task_id UNIQUEIDENTIFIER, item_id UNIQUEIDENTIFIER);
    INSERT INTO @mapping(job_id, task_id, item_id)
    SELECT j.job_id, NEWID(), NEWID() FROM dbo.jobs j;

    INSERT INTO dbo.tasks(task_id, kind, created_by, created_at, expires_at, settings_snapshot, selection_snapshot, legacy_job_id)
    SELECT m.task_id, N'scan', j.created_by, j.created_at,
           CASE WHEN j.state IN (N'pending',N'delivered') THEN DATEADD(SECOND, 604800, SYSUTCDATETIME())
                ELSE DATEADD(SECOND, 604800, j.created_at) END,
           N'{}', N'{"source":"legacy_job"}', j.job_id
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
           j.report_id,
           j.job_id, j.created_at, COALESCE(j.completed_at,j.created_at)
    FROM dbo.jobs j JOIN @mapping m ON m.job_id=j.job_id;

    UPDATE j SET j.task_id=m.task_id, j.task_item_id=m.item_id
    FROM dbo.jobs j JOIN @mapping m ON m.job_id=j.job_id;

    INSERT INTO dbo.task_item_events(item_id, sequence, attempt_no, event_type, details_json, created_at)
    SELECT m.item_id, 1, 0, N'legacy_job_imported',
           (SELECT j.job_id AS job_id, j.state AS state FOR JSON PATH, WITHOUT_ARRAY_WRAPPER),
           j.created_at
    FROM dbo.jobs j JOIN @mapping m ON m.job_id=j.job_id;
END
GO

IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name=N'IX_jobs_task_item' AND object_id=OBJECT_ID(N'dbo.jobs'))
    CREATE INDEX IX_jobs_task_item ON dbo.jobs(task_item_id);
GO
