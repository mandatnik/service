-- Agent installation lifecycle: confirmation queue, atomic replacement,
-- historical-card archiving and scan epochs across installations.
-- Additive only: existing machines, registrations, reports, users, groups,
-- policies and events are preserved.

IF COL_LENGTH('dbo.machines', 'archived_at') IS NULL
    ALTER TABLE dbo.machines ADD archived_at DATETIME2(3) NULL;
GO
IF COL_LENGTH('dbo.machines', 'archived_by') IS NULL
    ALTER TABLE dbo.machines ADD archived_by NVARCHAR(320) NULL;
GO
IF COL_LENGTH('dbo.machines', 'archive_reason') IS NULL
    ALTER TABLE dbo.machines ADD archive_reason NVARCHAR(1024) NULL;
GO
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = N'IX_machines_archived' AND object_id = OBJECT_ID(N'dbo.machines'))
    CREATE INDEX IX_machines_archived ON dbo.machines(archived_at) INCLUDE (display_name);
GO

-- scan_epoch distinguishes installations of one machine when both start their
-- local scan_seq at 1. Existing rows belong to epoch 0.
IF COL_LENGTH('dbo.registrations', 'scan_epoch') IS NULL
    ALTER TABLE dbo.registrations ADD scan_epoch INT NOT NULL CONSTRAINT DF_registrations_scan_epoch DEFAULT 0;
GO
IF COL_LENGTH('dbo.reports', 'scan_epoch') IS NULL
    ALTER TABLE dbo.reports ADD scan_epoch INT NOT NULL CONSTRAINT DF_reports_scan_epoch DEFAULT 0;
GO
IF COL_LENGTH('dbo.source_states', 'last_scan_epoch') IS NULL
    ALTER TABLE dbo.source_states ADD last_scan_epoch INT NOT NULL CONSTRAINT DF_source_states_epoch DEFAULT 0;
GO
IF COL_LENGTH('dbo.csp_states', 'last_scan_epoch') IS NULL
    ALTER TABLE dbo.csp_states ADD last_scan_epoch INT NOT NULL CONSTRAINT DF_csp_states_epoch DEFAULT 0;
GO
IF COL_LENGTH('dbo.certificate_observations', 'last_scan_epoch') IS NULL
    ALTER TABLE dbo.certificate_observations ADD last_scan_epoch INT NOT NULL CONSTRAINT DF_observations_epoch DEFAULT 0;
GO

-- A replaced installation is deliberately distinct from an administrative
-- revoke or a signed rename. The old registration stays in history.
IF EXISTS (SELECT 1 FROM sys.check_constraints WHERE name = N'CK_registrations_state' AND parent_object_id = OBJECT_ID(N'dbo.registrations'))
    ALTER TABLE dbo.registrations DROP CONSTRAINT CK_registrations_state;
GO
ALTER TABLE dbo.registrations
    ADD CONSTRAINT CK_registrations_state CHECK (state IN (N'active', N'renamed', N'revoked', N'replaced'));
GO

-- One machine must never have two active registrations. Fail explicitly if a
-- pre-existing deployment already violates this invariant; silently choosing
-- a winner would hide history and could grant the wrong installation access.
IF EXISTS (
    SELECT 1 FROM dbo.registrations WHERE state = N'active'
    GROUP BY machine_id HAVING COUNT(*) > 1
)
    THROW 51001, N'duplicate active registrations exist; resolve them before applying 0008_agent_installations.sql', 1;
GO
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = N'UQ_registrations_one_active' AND object_id = OBJECT_ID(N'dbo.registrations'))
    CREATE UNIQUE INDEX UQ_registrations_one_active ON dbo.registrations(machine_id) WHERE state = N'active';
GO

IF OBJECT_ID(N'dbo.agent_install_requests', N'U') IS NULL
BEGIN
    CREATE TABLE dbo.agent_install_requests (
        request_id UNIQUEIDENTIFIER NOT NULL CONSTRAINT PK_agent_install_requests PRIMARY KEY,
        uuid UNIQUEIDENTIFIER NOT NULL,
        hostname NVARCHAR(253) NOT NULL,
        hostname_norm NVARCHAR(253) NOT NULL,
        public_key_pem NVARCHAR(MAX) NOT NULL,
        public_key_sha256 CHAR(64) NOT NULL,
        state NVARCHAR(16) NOT NULL CONSTRAINT DF_agent_install_requests_state DEFAULT N'pending',
        request_version INT NOT NULL CONSTRAINT DF_agent_install_requests_version DEFAULT 1,
        first_seen_at DATETIME2(3) NOT NULL,
        last_seen_at DATETIME2(3) NOT NULL,
        last_source_ip VARBINARY(16) NULL,
        last_dns_status NVARCHAR(16) NULL,
        agent_version NVARCHAR(128) NULL,
        os_version NVARCHAR(128) NULL,
        architecture NVARCHAR(32) NULL,
        resolved_machine_id UNIQUEIDENTIFIER NULL,
        resolved_registration_id BIGINT NULL,
        decided_by NVARCHAR(320) NULL,
        decided_at DATETIME2(3) NULL,
        decision_note NVARCHAR(1024) NULL,
        created_at DATETIME2(3) NOT NULL,
        updated_at DATETIME2(3) NOT NULL,
        CONSTRAINT UQ_agent_install_requests_uuid UNIQUE (uuid),
        CONSTRAINT CK_agent_install_requests_state CHECK (state IN (N'pending', N'replaced', N'separated', N'rejected')),
        CONSTRAINT FK_agent_install_requests_machine FOREIGN KEY (resolved_machine_id) REFERENCES dbo.machines(machine_id),
        CONSTRAINT FK_agent_install_requests_registration FOREIGN KEY (resolved_registration_id) REFERENCES dbo.registrations(registration_id)
    );
    CREATE INDEX IX_agent_install_requests_state_seen ON dbo.agent_install_requests(state, last_seen_at DESC);
    CREATE INDEX IX_agent_install_requests_hostname ON dbo.agent_install_requests(hostname_norm);
END
GO
