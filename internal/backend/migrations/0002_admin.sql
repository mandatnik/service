-- P08: administrative session lookup and cleanup support.
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = N'IX_admin_sessions_expires' AND object_id = OBJECT_ID(N'dbo.admin_sessions'))
BEGIN
    CREATE INDEX IX_admin_sessions_expires ON dbo.admin_sessions(expires_at) INCLUDE (admin_id, revoked_at, last_seen_at);
END
GO

IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = N'IX_events_kind_created' AND object_id = OBJECT_ID(N'dbo.events'))
BEGIN
    CREATE INDEX IX_events_kind_created ON dbo.events(kind, created_at) INCLUDE (machine_id, severity);
END
GO
