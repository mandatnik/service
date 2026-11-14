-- Administrator identity: email login, display name and role.
-- Additive only: the legacy username column is kept for one release and is
-- no longer used by the application.

IF COL_LENGTH('dbo.administrators', 'email') IS NULL
    ALTER TABLE dbo.administrators ADD email NVARCHAR(320) NULL;
GO
IF COL_LENGTH('dbo.administrators', 'display_name') IS NULL
    ALTER TABLE dbo.administrators ADD display_name NVARCHAR(255) NULL;
GO
IF COL_LENGTH('dbo.administrators', 'role') IS NULL
    ALTER TABLE dbo.administrators ADD role NVARCHAR(16) NULL;
GO

-- Backfill every existing login before the new columns become NOT NULL.
UPDATE dbo.administrators
SET email = LOWER(LTRIM(RTRIM(
    CASE WHEN CHARINDEX(N'@', username) > 0 THEN username
         ELSE username + N'@telehack.local'
    END)))
WHERE email IS NULL OR LTRIM(RTRIM(email)) = N'';
GO

UPDATE dbo.administrators
SET display_name = COALESCE(NULLIF(LTRIM(RTRIM(username)), N''), N'Администратор')
WHERE display_name IS NULL OR LTRIM(RTRIM(display_name)) = N'';
GO

UPDATE dbo.administrators
SET role = N'admin'
WHERE role IS NULL OR LTRIM(RTRIM(role)) = N'';
GO

-- The oldest administrator becomes superadmin so the system stays manageable
-- after the upgrade. Re-running this batch is a no-op once a superadmin exists.
IF NOT EXISTS (SELECT 1 FROM dbo.administrators WHERE role = N'superadmin')
BEGIN
    UPDATE dbo.administrators
    SET role = N'superadmin'
    WHERE admin_id = (SELECT MIN(admin_id) FROM dbo.administrators);
END
GO

ALTER TABLE dbo.administrators ALTER COLUMN email NVARCHAR(320) NOT NULL;
GO
ALTER TABLE dbo.administrators ALTER COLUMN display_name NVARCHAR(255) NOT NULL;
GO
ALTER TABLE dbo.administrators ALTER COLUMN role NVARCHAR(16) NOT NULL;
GO

IF NOT EXISTS (
    SELECT 1 FROM sys.check_constraints
    WHERE name = N'CK_administrators_role' AND parent_object_id = OBJECT_ID(N'dbo.administrators')
)
BEGIN
    ALTER TABLE dbo.administrators
        ADD CONSTRAINT CK_administrators_role CHECK (role IN (N'admin', N'superadmin'));
END
GO

IF NOT EXISTS (
    SELECT 1 FROM sys.indexes
    WHERE name = N'UX_administrators_email' AND object_id = OBJECT_ID(N'dbo.administrators')
)
BEGIN
    CREATE UNIQUE INDEX UX_administrators_email ON dbo.administrators(email);
END
GO
