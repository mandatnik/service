-- Keep the mutual DNS snapshot independent of legacy forward-only updates.
-- The old last_dns_status/last_dns_checked_at are also written by heartbeats;
-- they cannot establish the result or age of a mutual DNS lookup.
-- Do not backfill: legacy timestamps may already have been refreshed without
-- a lookup. A new complete verification will populate these fields together.
IF COL_LENGTH('dbo.registrations', 'last_dns_mutual_forward_status') IS NULL
    ALTER TABLE dbo.registrations ADD last_dns_mutual_forward_status NVARCHAR(16) NULL;
GO

IF COL_LENGTH('dbo.registrations', 'last_dns_mutual_checked_at') IS NULL
    ALTER TABLE dbo.registrations ADD last_dns_mutual_checked_at DATETIME2(3) NULL;
GO
