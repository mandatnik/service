-- Integration API keys and the current CryptoPro license inventory.
-- The integration API is separate from agent/admin listeners and uses bearer
-- keys stored only as SHA-256 hashes.

IF OBJECT_ID(N'dbo.integration_api_keys', N'U') IS NULL
BEGIN
    CREATE TABLE dbo.integration_api_keys (
        key_id UNIQUEIDENTIFIER NOT NULL CONSTRAINT PK_integration_api_keys PRIMARY KEY,
        name NVARCHAR(200) NOT NULL,
        token_sha256 CHAR(64) NOT NULL,
        token_prefix NVARCHAR(16) NOT NULL,
        allowed_ips_json NVARCHAR(MAX) NOT NULL,
        created_at DATETIME2(3) NOT NULL,
        created_by NVARCHAR(128) NOT NULL,
        last_used_at DATETIME2(3) NULL,
        last_used_ip VARBINARY(16) NULL,
        revoked_at DATETIME2(3) NULL,
        revoked_by NVARCHAR(128) NULL,
        CONSTRAINT UQ_integration_api_keys_token UNIQUE (token_sha256)
    );
    CREATE INDEX IX_integration_api_keys_revoked
        ON dbo.integration_api_keys(revoked_at) INCLUDE (token_sha256);
END
GO

IF OBJECT_ID(N'dbo.reported_licenses', N'U') IS NULL
BEGIN
    CREATE TABLE dbo.reported_licenses (
        license_id CHAR(64) NOT NULL CONSTRAINT PK_reported_licenses PRIMARY KEY,
        machine_id UNIQUEIDENTIFIER NOT NULL,
        product NVARCHAR(16) NOT NULL,
        product_code INT NOT NULL,
        product_name NVARCHAR(128) NULL,
        serial_masked NVARCHAR(64) NOT NULL,
        csp_version NVARCHAR(128) NULL,
        product_version NVARCHAR(128) NULL,
        core_version NVARCHAR(128) NULL,
        license_kind NVARCHAR(16) NULL,
        license_state NVARCHAR(16) NOT NULL,
        valid_to_utc DATETIME2(3) NULL,
        valid_to_raw NVARCHAR(128) NULL,
        term_kind NVARCHAR(32) NULL,
        is_trial NVARCHAR(8) NULL,
        source NVARCHAR(128) NULL,
        complete BIT NOT NULL CONSTRAINT DF_reported_licenses_complete DEFAULT 1,
        error NVARCHAR(2048) NULL,
        last_attempt_error NVARCHAR(2048) NULL,
        collected_at DATETIME2(3) NULL,
        created_at DATETIME2(3) NOT NULL,
        updated_at DATETIME2(3) NOT NULL,
        CONSTRAINT FK_reported_licenses_machine FOREIGN KEY (machine_id)
            REFERENCES dbo.machines(machine_id),
        CONSTRAINT UQ_reported_licenses_machine_product UNIQUE (machine_id, product)
    );
    CREATE INDEX IX_reported_licenses_state ON dbo.reported_licenses(license_state);
    CREATE INDEX IX_reported_licenses_machine ON dbo.reported_licenses(machine_id, product);
END
GO
