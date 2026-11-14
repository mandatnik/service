-- Administrator-defined machine display names are independent of the agent
-- hostname. The flag prevents a later signed rename or installation
-- replacement from overwriting a name chosen by the administrator.
IF COL_LENGTH('dbo.machines', 'display_name_custom') IS NULL
    ALTER TABLE dbo.machines ADD display_name_custom BIT NOT NULL
        CONSTRAINT DF_machines_display_name_custom DEFAULT 0;
GO
