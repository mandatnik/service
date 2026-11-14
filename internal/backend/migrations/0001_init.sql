-- Telehack 2026 application schema, SQL Server 2019.
-- All timestamps are UTC (DATETIME2(3)). UUIDs are UNIQUEIDENTIFIER.
-- The application database is never master; bootstrap creates it separately.

IF OBJECT_ID(N'dbo.machines', N'U') IS NULL
BEGIN
    CREATE TABLE dbo.machines (
        machine_id UNIQUEIDENTIFIER NOT NULL CONSTRAINT PK_machines PRIMARY KEY DEFAULT NEWID(),
        display_name NVARCHAR(253) NOT NULL,
        created_at DATETIME2(3) NOT NULL,
        updated_at DATETIME2(3) NOT NULL
    );
END
GO

IF OBJECT_ID(N'dbo.registrations', N'U') IS NULL
BEGIN
    CREATE TABLE dbo.registrations (
        registration_id BIGINT IDENTITY(1,1) NOT NULL CONSTRAINT PK_registrations PRIMARY KEY,
        machine_id UNIQUEIDENTIFIER NOT NULL,
        uuid UNIQUEIDENTIFIER NOT NULL,
        hostname NVARCHAR(253) NOT NULL,
        hostname_norm NVARCHAR(253) NOT NULL,
        public_key_pem NVARCHAR(MAX) NOT NULL,
        public_key_sha256 CHAR(64) NOT NULL,
        state NVARCHAR(16) NOT NULL CONSTRAINT DF_registrations_state DEFAULT N'active',
        agent_version NVARCHAR(128) NULL,
        os_version NVARCHAR(128) NULL,
        architecture NVARCHAR(32) NULL,
        previous_registration_id BIGINT NULL,
        replaced_by_registration_id BIGINT NULL,
        created_at DATETIME2(3) NOT NULL,
        last_seen_at DATETIME2(3) NULL,
        last_source_ip VARBINARY(16) NULL,
        last_dns_status NVARCHAR(16) NULL,
        last_dns_checked_at DATETIME2(3) NULL,
        revoked_at DATETIME2(3) NULL,
        CONSTRAINT UQ_registrations_uuid UNIQUE (uuid),
        CONSTRAINT FK_registrations_machine FOREIGN KEY (machine_id) REFERENCES dbo.machines(machine_id),
        CONSTRAINT FK_registrations_previous FOREIGN KEY (previous_registration_id) REFERENCES dbo.registrations(registration_id),
        CONSTRAINT FK_registrations_replaced_by FOREIGN KEY (replaced_by_registration_id) REFERENCES dbo.registrations(registration_id),
        CONSTRAINT CK_registrations_state CHECK (state IN (N'active', N'renamed', N'revoked'))
    );
    CREATE INDEX IX_registrations_machine ON dbo.registrations(machine_id, state);
    CREATE INDEX IX_registrations_hostname ON dbo.registrations(hostname_norm);
    CREATE INDEX IX_registrations_key ON dbo.registrations(public_key_sha256);
END
GO

IF OBJECT_ID(N'dbo.hostnames', N'U') IS NULL
BEGIN
    CREATE TABLE dbo.hostnames (
        hostname_norm NVARCHAR(253) NOT NULL CONSTRAINT PK_hostnames PRIMARY KEY,
        display_name NVARCHAR(253) NOT NULL,
        owner_registration_id BIGINT NULL,
        owner_machine_id UNIQUEIDENTIFIER NULL,
        reserved_at DATETIME2(3) NOT NULL,
        last_seen_at DATETIME2(3) NULL,
        CONSTRAINT FK_hostnames_registration FOREIGN KEY (owner_registration_id) REFERENCES dbo.registrations(registration_id),
        CONSTRAINT FK_hostnames_machine FOREIGN KEY (owner_machine_id) REFERENCES dbo.machines(machine_id)
    );
END
GO

IF OBJECT_ID(N'dbo.machine_users', N'U') IS NULL
BEGIN
    CREATE TABLE dbo.machine_users (
        machine_user_id BIGINT IDENTITY(1,1) NOT NULL CONSTRAINT PK_machine_users PRIMARY KEY,
        machine_id UNIQUEIDENTIFIER NOT NULL,
        sid NVARCHAR(184) NOT NULL,
        name NVARCHAR(256) NOT NULL,
        profile_path NVARCHAR(1024) NULL,
        present BIT NOT NULL CONSTRAINT DF_machine_users_present DEFAULT 1,
        loaded BIT NOT NULL CONSTRAINT DF_machine_users_loaded DEFAULT 0,
        first_seen_at DATETIME2(3) NOT NULL,
        last_seen_at DATETIME2(3) NOT NULL,
        last_report_id UNIQUEIDENTIFIER NULL,
        CONSTRAINT UQ_machine_users_sid UNIQUE (machine_id, sid),
        CONSTRAINT FK_machine_users_machine FOREIGN KEY (machine_id) REFERENCES dbo.machines(machine_id)
    );
    CREATE INDEX IX_machine_users_machine ON dbo.machine_users(machine_id, present);
END
GO

IF OBJECT_ID(N'dbo.certificates', N'U') IS NULL
BEGIN
    CREATE TABLE dbo.certificates (
        sha256 CHAR(64) NOT NULL CONSTRAINT PK_certificates PRIMARY KEY,
        der VARBINARY(MAX) NOT NULL,
        serial_hex NVARCHAR(256) NULL,
        serial_number NVARCHAR(256) NULL,
        subject NVARCHAR(MAX) NULL,
        issuer NVARCHAR(MAX) NULL,
        issuer_hash BINARY(32) NULL,
        owner_cn NVARCHAR(512) NULL,
        inn NVARCHAR(64) NULL,
        snils NVARCHAR(64) NULL,
        public_key_bits INT NULL,
        signature_algorithm NVARCHAR(128) NULL,
        embedded_license NVARCHAR(16) NULL,
        not_before DATETIME2(3) NULL,
        not_after DATETIME2(3) NULL,
        parse_error NVARCHAR(2048) NULL,
        created_at DATETIME2(3) NOT NULL,
        updated_at DATETIME2(3) NOT NULL
    );
    CREATE INDEX IX_certificates_serial ON dbo.certificates(serial_hex);
    CREATE INDEX IX_certificates_issuer_hash ON dbo.certificates(issuer_hash);
    CREATE INDEX IX_certificates_not_after ON dbo.certificates(not_after);
END
GO

IF OBJECT_ID(N'dbo.reports', N'U') IS NULL
BEGIN
    CREATE TABLE dbo.reports (
        report_id UNIQUEIDENTIFIER NOT NULL CONSTRAINT PK_reports PRIMARY KEY,
        machine_id UNIQUEIDENTIFIER NOT NULL,
        registration_id BIGINT NOT NULL,
        scan_seq BIGINT NOT NULL,
        collected_at DATETIME2(3) NOT NULL,
        received_at DATETIME2(3) NOT NULL,
        status NVARCHAR(16) NOT NULL,
        applied BIT NOT NULL,
        applied_sources INT NOT NULL CONSTRAINT DF_reports_applied_sources DEFAULT 0,
        payload_sha256 CHAR(64) NOT NULL,
        payload_json NVARCHAR(MAX) NOT NULL,
        source_ip VARBINARY(16) NULL,
        dns_status NVARCHAR(16) NULL,
        CONSTRAINT UQ_reports_registration_seq UNIQUE (registration_id, scan_seq),
        CONSTRAINT FK_reports_machine FOREIGN KEY (machine_id) REFERENCES dbo.machines(machine_id),
        CONSTRAINT FK_reports_registration FOREIGN KEY (registration_id) REFERENCES dbo.registrations(registration_id)
    );
    CREATE INDEX IX_reports_machine_collected ON dbo.reports(machine_id, collected_at);
END
GO

IF OBJECT_ID(N'dbo.jobs', N'U') IS NULL
BEGIN
    CREATE TABLE dbo.jobs (
        job_id UNIQUEIDENTIFIER NOT NULL CONSTRAINT PK_jobs PRIMARY KEY,
        machine_id UNIQUEIDENTIFIER NOT NULL,
        kind NVARCHAR(32) NOT NULL,
        state NVARCHAR(16) NOT NULL,
        created_at DATETIME2(3) NOT NULL,
        created_by NVARCHAR(128) NULL,
        delivered_at DATETIME2(3) NULL,
        last_delivered_at DATETIME2(3) NULL,
        completed_at DATETIME2(3) NULL,
        acknowledged_at DATETIME2(3) NULL,
        report_id UNIQUEIDENTIFIER NULL,
        message NVARCHAR(1024) NULL,
        CONSTRAINT CK_jobs_state CHECK (state IN (N'pending', N'delivered', N'completed', N'failed', N'report_evicted', N'canceled')),
        CONSTRAINT FK_jobs_machine FOREIGN KEY (machine_id) REFERENCES dbo.machines(machine_id),
        CONSTRAINT FK_jobs_report FOREIGN KEY (report_id) REFERENCES dbo.reports(report_id)
    );
    CREATE INDEX IX_jobs_machine_state ON dbo.jobs(machine_id, state, created_at);
END
GO

IF OBJECT_ID(N'dbo.certificate_observations', N'U') IS NULL
BEGIN
    CREATE TABLE dbo.certificate_observations (
        observation_id BIGINT IDENTITY(1,1) NOT NULL CONSTRAINT PK_certificate_observations PRIMARY KEY,
        machine_id UNIQUEIDENTIFIER NOT NULL,
        machine_user_id BIGINT NULL,
        source_type NVARCHAR(16) NOT NULL,
        source_key NVARCHAR(1024) NOT NULL,
        source_scope_hash BINARY(32) NOT NULL,
        observation_key_hash BINARY(32) NOT NULL,
        file_path NVARCHAR(1024) NULL,
        certificate_sha256 CHAR(64) NOT NULL,
        active BIT NOT NULL CONSTRAINT DF_observations_active DEFAULT 1,
        first_seen_at DATETIME2(3) NOT NULL,
        last_seen_at DATETIME2(3) NOT NULL,
        removed_at DATETIME2(3) NULL,
        last_report_id UNIQUEIDENTIFIER NOT NULL,
        last_scan_seq BIGINT NOT NULL,
        CONSTRAINT UQ_observations_source_cert UNIQUE (machine_id, observation_key_hash, certificate_sha256),
        CONSTRAINT FK_observations_machine FOREIGN KEY (machine_id) REFERENCES dbo.machines(machine_id),
        CONSTRAINT FK_observations_user FOREIGN KEY (machine_user_id) REFERENCES dbo.machine_users(machine_user_id),
        CONSTRAINT FK_observations_cert FOREIGN KEY (certificate_sha256) REFERENCES dbo.certificates(sha256),
        CONSTRAINT FK_observations_report FOREIGN KEY (last_report_id) REFERENCES dbo.reports(report_id)
    );
    CREATE INDEX IX_observations_machine_source ON dbo.certificate_observations(machine_id, source_type, active);
    CREATE INDEX IX_observations_cert ON dbo.certificate_observations(certificate_sha256);
    CREATE INDEX IX_observations_user ON dbo.certificate_observations(machine_user_id);
END
GO

IF OBJECT_ID(N'dbo.machine_user_certificates', N'U') IS NULL
BEGIN
    CREATE TABLE dbo.machine_user_certificates (
        machine_user_id BIGINT NOT NULL,
        certificate_sha256 CHAR(64) NOT NULL,
        active BIT NOT NULL CONSTRAINT DF_user_certificates_active DEFAULT 1,
        first_seen_at DATETIME2(3) NOT NULL,
        last_seen_at DATETIME2(3) NOT NULL,
        last_report_id UNIQUEIDENTIFIER NOT NULL,
        CONSTRAINT PK_machine_user_certificates PRIMARY KEY (machine_user_id, certificate_sha256),
        CONSTRAINT FK_user_certificates_user FOREIGN KEY (machine_user_id) REFERENCES dbo.machine_users(machine_user_id),
        CONSTRAINT FK_user_certificates_cert FOREIGN KEY (certificate_sha256) REFERENCES dbo.certificates(sha256),
        CONSTRAINT FK_user_certificates_report FOREIGN KEY (last_report_id) REFERENCES dbo.reports(report_id)
    );
    CREATE INDEX IX_user_certificates_cert ON dbo.machine_user_certificates(certificate_sha256, active);
END
GO

IF OBJECT_ID(N'dbo.source_states', N'U') IS NULL
BEGIN
    CREATE TABLE dbo.source_states (
        machine_id UNIQUEIDENTIFIER NOT NULL,
        source_type NVARCHAR(16) NOT NULL,
        source_key NVARCHAR(1024) NOT NULL,
        source_key_hash BINARY(32) NOT NULL,
        last_scan_seq BIGINT NOT NULL,
        last_report_id UNIQUEIDENTIFIER NOT NULL,
        last_complete BIT NOT NULL,
        last_collected_at DATETIME2(3) NOT NULL,
        updated_at DATETIME2(3) NOT NULL,
        CONSTRAINT PK_source_states PRIMARY KEY (machine_id, source_key_hash),
        CONSTRAINT FK_source_states_machine FOREIGN KEY (machine_id) REFERENCES dbo.machines(machine_id)
    );
END
GO

IF OBJECT_ID(N'dbo.csp_states', N'U') IS NULL
BEGIN
    CREATE TABLE dbo.csp_states (
        machine_id UNIQUEIDENTIFIER NOT NULL CONSTRAINT PK_csp_states PRIMARY KEY,
        scanned BIT NOT NULL,
        complete BIT NOT NULL,
        present BIT NOT NULL,
        product_version NVARCHAR(128) NULL,
        core_version NVARCHAR(128) NULL,
        license_kind NVARCHAR(16) NULL,
        license_kind_raw NVARCHAR(64) NULL,
        license_kind_source NVARCHAR(128) NULL,
        license_state NVARCHAR(16) NULL,
        valid_to_raw NVARCHAR(128) NULL,
        valid_to_utc DATETIME2(3) NULL,
        time_basis NVARCHAR(32) NULL,
        term_kind NVARCHAR(32) NULL,
        is_trial NVARCHAR(8) NULL,
        source NVARCHAR(128) NULL,
        error NVARCHAR(2048) NULL,
        products_json NVARCHAR(MAX) NULL,
        last_report_id UNIQUEIDENTIFIER NULL,
        last_scan_seq BIGINT NOT NULL,
        collected_at DATETIME2(3) NOT NULL,
        updated_at DATETIME2(3) NOT NULL,
        last_attempt_at DATETIME2(3) NOT NULL,
        last_attempt_error NVARCHAR(2048) NULL,
        CONSTRAINT FK_csp_states_machine FOREIGN KEY (machine_id) REFERENCES dbo.machines(machine_id)
    );
END
GO

IF OBJECT_ID(N'dbo.configs', N'U') IS NULL
BEGIN
    CREATE TABLE dbo.configs (
        config_id INT NOT NULL CONSTRAINT PK_configs PRIMARY KEY,
        version INT NOT NULL,
        config_json NVARCHAR(MAX) NOT NULL,
        config_hash CHAR(64) NOT NULL,
        updated_at DATETIME2(3) NOT NULL,
        updated_by NVARCHAR(128) NULL
    );
END
GO

IF NOT EXISTS (SELECT 1 FROM dbo.configs WHERE config_id = 1)
BEGIN
    INSERT INTO dbo.configs (config_id, version, config_json, config_hash, updated_at, updated_by)
    VALUES (1, 1,
        N'{"cert_directories":[],"max_file_bytes":10485760,"max_files":2000,"recursive":true,"scan_interval_days":1,"version":1}',
        'cffcf637b56587e88b3745a671ed6161f71ba83450184229352bcdd9ffad52c3',
        SYSUTCDATETIME(), N'migration');
END
GO

IF OBJECT_ID(N'dbo.events', N'U') IS NULL
BEGIN
    CREATE TABLE dbo.events (
        event_id BIGINT IDENTITY(1,1) NOT NULL CONSTRAINT PK_events PRIMARY KEY,
        machine_id UNIQUEIDENTIFIER NULL,
        registration_id BIGINT NULL,
        report_id UNIQUEIDENTIFIER NULL,
        request_id UNIQUEIDENTIFIER NULL,
        kind NVARCHAR(64) NOT NULL,
        severity NVARCHAR(16) NOT NULL,
        message NVARCHAR(1024) NOT NULL,
        details_json NVARCHAR(MAX) NULL,
        created_at DATETIME2(3) NOT NULL,
        CONSTRAINT FK_events_machine FOREIGN KEY (machine_id) REFERENCES dbo.machines(machine_id),
        CONSTRAINT FK_events_registration FOREIGN KEY (registration_id) REFERENCES dbo.registrations(registration_id),
        CONSTRAINT FK_events_report FOREIGN KEY (report_id) REFERENCES dbo.reports(report_id)
    );
    CREATE INDEX IX_events_machine_created ON dbo.events(machine_id, created_at);
END
GO

IF OBJECT_ID(N'dbo.request_ids', N'U') IS NULL
BEGIN
    CREATE TABLE dbo.request_ids (
        identity_uuid UNIQUEIDENTIFIER NOT NULL,
        request_id UNIQUEIDENTIFIER NOT NULL,
        endpoint NVARCHAR(128) NOT NULL,
        used_at DATETIME2(3) NOT NULL,
        CONSTRAINT PK_request_ids PRIMARY KEY (identity_uuid, request_id)
    );
    CREATE INDEX IX_request_ids_used ON dbo.request_ids(used_at);
END
GO

IF OBJECT_ID(N'dbo.administrators', N'U') IS NULL
BEGIN
    CREATE TABLE dbo.administrators (
        admin_id BIGINT IDENTITY(1,1) NOT NULL CONSTRAINT PK_administrators PRIMARY KEY,
        username NVARCHAR(128) NOT NULL,
        password_hash NVARCHAR(255) NOT NULL,
        disabled BIT NOT NULL CONSTRAINT DF_administrators_disabled DEFAULT 0,
        created_at DATETIME2(3) NOT NULL,
        CONSTRAINT UQ_administrators_username UNIQUE (username)
    );
END
GO

IF OBJECT_ID(N'dbo.admin_sessions', N'U') IS NULL
BEGIN
    CREATE TABLE dbo.admin_sessions (
        session_id UNIQUEIDENTIFIER NOT NULL CONSTRAINT PK_admin_sessions PRIMARY KEY,
        admin_id BIGINT NOT NULL,
        token_hash CHAR(64) NOT NULL,
        created_at DATETIME2(3) NOT NULL,
        expires_at DATETIME2(3) NOT NULL,
        last_seen_at DATETIME2(3) NOT NULL,
        revoked_at DATETIME2(3) NULL,
        CONSTRAINT UQ_admin_sessions_token UNIQUE (token_hash),
        CONSTRAINT FK_admin_sessions_admin FOREIGN KEY (admin_id) REFERENCES dbo.administrators(admin_id)
    );
END
GO
