-- Mutual DNS verification for the machine list. `last_dns_status` keeps the
-- existing forward signal (hostname -> source IP); the new columns record the
-- reverse lookup and bind the result to the exact hostname and source IP.
-- Legacy rows have no reverse value and therefore never show a green badge.

IF COL_LENGTH('dbo.registrations', 'last_dns_reverse_status') IS NULL
    ALTER TABLE dbo.registrations ADD last_dns_reverse_status NVARCHAR(16) NULL;
GO

IF COL_LENGTH('dbo.registrations', 'last_dns_hostname') IS NULL
    ALTER TABLE dbo.registrations ADD last_dns_hostname NVARCHAR(253) NULL;
GO

IF COL_LENGTH('dbo.registrations', 'last_dns_source_ip') IS NULL
    ALTER TABLE dbo.registrations ADD last_dns_source_ip VARBINARY(16) NULL;
GO
