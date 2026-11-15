package db

import (
	"context"
	"database/sql"
	"fmt"
	"regexp"
	"strings"
	"time"

	"mandatnik/internal/backend/config"
)

var identifierPattern = regexp.MustCompile(`^[A-Za-z0-9_]{1,64}$`)

// Bootstrap creates the application database, runtime login and database user
// with the minimum role set needed by migrations and the runtime. It connects
// as the provided administrative SQL login (normally sa) and never creates
// tables in master. Passwords are not logged.
func Bootstrap(ctx context.Context, cfg config.Config, saPassword string) error {
	if saPassword == "" {
		return fmt.Errorf("administrative SQL password is required")
	}
	if !identifierPattern.MatchString(cfg.DB.Database) {
		return fmt.Errorf("database name may contain only letters, digits and underscore")
	}
	if !identifierPattern.MatchString(cfg.DB.User) {
		return fmt.Errorf("database user may contain only letters, digits and underscore")
	}
	appPassword, err := cfg.DB.Password()
	if err != nil {
		return err
	}
	master, err := OpenAs(ctx, cfg.DB, "sa", saPassword, "master")
	if err != nil {
		return err
	}
	defer master.Close()

	dbLiteral := strings.ReplaceAll(cfg.DB.Database, "'", "''")
	dbIdentifier := quoteIdentifier(cfg.DB.Database)
	if _, err := master.ExecContext(ctx, fmt.Sprintf(
		`IF DB_ID(N'%s') IS NULL CREATE DATABASE %s`, dbLiteral, dbIdentifier)); err != nil {
		return fmt.Errorf("create database %s: %w", cfg.DB.Database, err)
	}
	if err := waitForDatabase(ctx, master, cfg.DB.Database, 30*time.Second); err != nil {
		return err
	}

	loginLiteral := strings.ReplaceAll(cfg.DB.User, "'", "''")
	passwordLiteral := strings.ReplaceAll(appPassword, "'", "''")
	loginIdentifier := quoteIdentifier(cfg.DB.User)
	loginSQL := fmt.Sprintf(`
IF NOT EXISTS (SELECT 1 FROM sys.server_principals WHERE name = N'%s')
BEGIN
    CREATE LOGIN %s WITH PASSWORD = N'%s', CHECK_POLICY = ON, CHECK_EXPIRATION = OFF;
END
ELSE
BEGIN
    ALTER LOGIN %s WITH PASSWORD = N'%s';
END`, loginLiteral, loginIdentifier, passwordLiteral, loginIdentifier, passwordLiteral)
	if _, err := master.ExecContext(ctx, loginSQL); err != nil {
		return fmt.Errorf("create/update login %s: %w", cfg.DB.User, err)
	}

	database, err := OpenAs(ctx, cfg.DB, "sa", saPassword, cfg.DB.Database)
	if err != nil {
		return err
	}
	defer database.Close()
	userSQL := fmt.Sprintf(`
IF NOT EXISTS (SELECT 1 FROM sys.database_principals WHERE name = N'%s')
BEGIN
    CREATE USER %s FOR LOGIN %s;
END
IF IS_ROLEMEMBER(N'db_datareader', N'%s') = 0 ALTER ROLE [db_datareader] ADD MEMBER %s;
IF IS_ROLEMEMBER(N'db_datawriter', N'%s') = 0 ALTER ROLE [db_datawriter] ADD MEMBER %s;
IF IS_ROLEMEMBER(N'db_ddladmin', N'%s') = 0 ALTER ROLE [db_ddladmin] ADD MEMBER %s;`,
		loginLiteral, loginIdentifier, loginIdentifier,
		loginLiteral, loginIdentifier,
		loginLiteral, loginIdentifier,
		loginLiteral, loginIdentifier)
	if _, err := database.ExecContext(ctx, userSQL); err != nil {
		return fmt.Errorf("create database user/roles %s: %w", cfg.DB.User, err)
	}

	verify, err := OpenAs(ctx, cfg.DB, cfg.DB.User, appPassword, cfg.DB.Database)
	if err != nil {
		return fmt.Errorf("verify runtime login: %w", err)
	}
	defer verify.Close()
	var one int
	if err := verify.QueryRowContext(ctx, "SELECT 1").Scan(&one); err != nil || one != 1 {
		return fmt.Errorf("verify runtime login query: %w", err)
	}
	return nil
}

func waitForDatabase(ctx context.Context, pool *sql.DB, name string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for {
		var state string
		err := pool.QueryRowContext(ctx, `SELECT state_desc FROM sys.databases WHERE name = @p1`, name).Scan(&state)
		if err == nil && state == "ONLINE" {
			return nil
		}
		if time.Now().After(deadline) {
			if err != nil {
				return fmt.Errorf("database %s did not become online: %w", name, err)
			}
			return fmt.Errorf("database %s state is %s, not ONLINE", name, state)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(500 * time.Millisecond):
		}
	}
}

func quoteIdentifier(value string) string {
	return "[" + strings.ReplaceAll(value, "]", "]]") + "]"
}
