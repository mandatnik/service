CREATE TABLE dbo.machine_groups (
 group_id UNIQUEIDENTIFIER NOT NULL PRIMARY KEY,
 name NVARCHAR(200) NOT NULL UNIQUE,
 updated_at DATETIME2(7) NOT NULL DEFAULT SYSUTCDATETIME()
);
CREATE TABLE dbo.machine_group_members (
 group_id UNIQUEIDENTIFIER NOT NULL REFERENCES dbo.machine_groups(group_id),
 machine_id UNIQUEIDENTIFIER NOT NULL REFERENCES dbo.machines(machine_id),
 PRIMARY KEY(group_id,machine_id)
);
CREATE INDEX IX_group_members_machine ON dbo.machine_group_members(machine_id,group_id);
CREATE TABLE dbo.folder_policies (
 policy_id UNIQUEIDENTIFIER NOT NULL PRIMARY KEY,
 name NVARCHAR(200) NOT NULL UNIQUE,
 rules NVARCHAR(MAX) NOT NULL,
 updated_at DATETIME2(7) NOT NULL DEFAULT SYSUTCDATETIME()
);
CREATE TABLE dbo.folder_policy_machines (
 policy_id UNIQUEIDENTIFIER NOT NULL REFERENCES dbo.folder_policies(policy_id),
 machine_id UNIQUEIDENTIFIER NOT NULL REFERENCES dbo.machines(machine_id),
 PRIMARY KEY(policy_id,machine_id)
);
CREATE INDEX IX_policy_machines_machine ON dbo.folder_policy_machines(machine_id,policy_id);
CREATE TABLE dbo.folder_policy_groups (
 policy_id UNIQUEIDENTIFIER NOT NULL REFERENCES dbo.folder_policies(policy_id),
 group_id UNIQUEIDENTIFIER NOT NULL REFERENCES dbo.machine_groups(group_id),
 PRIMARY KEY(policy_id,group_id)
);
-- Preserve previous global folders only for machines already registered.
-- Do not modify configs JSON here: its canonical hash must remain verifiable.
DECLARE @rules NVARCHAR(MAX);
SELECT @rules=STRING_AGG(CONVERT(NVARCHAR(MAX),REPLACE(value,N'\',N'/')),CHAR(10))
FROM dbo.configs CROSS APPLY OPENJSON(config_json,'$.cert_directories')
WHERE config_id=1;
IF LEN(@rules)>0 BEGIN
 DECLARE @policy UNIQUEIDENTIFIER=NEWID();
 INSERT INTO dbo.folder_policies(policy_id,name,rules) VALUES(@policy,N'Ранее настроенные папки',@rules);
 INSERT INTO dbo.folder_policy_machines(policy_id,machine_id) SELECT @policy,machine_id FROM dbo.machines;
END;
