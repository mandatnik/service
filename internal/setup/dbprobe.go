// SQL Server probing for the wizard: connection check, database emptiness
// classification and migration status. The wizard only connects to an
// already-created database with the provided SQL account.
package setup

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	mssql "github.com/microsoft/go-mssqldb"
	"github.com/microsoft/go-mssqldb/msdsn"
)

// ProbeResult classifies the target database.
type ProbeResult struct {
	Connected     bool     `json:"connected"`
	DatabaseFound bool     `json:"database_found"`
	Kind          string   `json:"kind"` // empty|mandatnik|foreign
	Tables        []string `json:"tables,omitempty"`
	Migrations    []int    `json:"migrations,omitempty"`
}

// Probed account/password set used by the wizard before configuration exists.
type ProbeCredentials struct {
	Server                 string
	Port                   int
	Database               string
	User                   string
	Password               string
	Encrypt                bool
	TrustServerCertificate bool
	ConnectTimeoutSeconds  int
}

// mandownik tables that identify an existing installation (subset is enough).
var mandatnikCoreTables = []string{
	"machines", "registrations", "certificates", "certificate_observations",
	"administrators", "admin_sessions", "schema_migrations", "configs", "events",
}

// Connect builds a raw connection for probing with explicit credentials,
// without relying on backend.json (which may not exist yet).
func Connect(ctx context.Context, creds ProbeCredentials) (*sql.DB, error) {
	if strings.TrimSpace(creds.Database) == "" {
		return nil, errors.New("имя базы данных не указано")
	}
	if creds.ConnectTimeoutSeconds <= 0 {
		creds.ConnectTimeoutSeconds = 15
	}
	encryption := msdsn.Encryption(msdsn.EncryptionRequired)
	if !creds.Encrypt {
		encryption = msdsn.Encryption(msdsn.EncryptionOff)
	}
	connector := mssql.NewConnectorConfig(msdsn.Config{
		Host:                   creds.Server,
		Port:                   uint64(creds.Port),
		Database:               creds.Database,
		User:                   creds.User,
		Password:               creds.Password,
		Encryption:             encryption,
		TrustServerCertificate: creds.TrustServerCertificate,
		Protocols:              []string{"tcp"},
		AppName:                "MandatnikSetup",
		DialTimeout:            time.Duration(creds.ConnectTimeoutSeconds) * time.Second,
		ConnTimeout:            time.Duration(creds.ConnectTimeoutSeconds) * time.Second,
	})
	pool := sql.OpenDB(connector)
	pingCtx, cancel := context.WithTimeout(ctx, time.Duration(creds.ConnectTimeoutSeconds)*time.Second)
	defer cancel()
	if err := pool.PingContext(pingCtx); err != nil {
		pool.Close()
		return nil, err
	}
	return pool, nil
}

// ProbeDatabase connects and classifies the database contents.
func ProbeDatabase(ctx context.Context, pool *sql.DB, creds ProbeCredentials) (*ProbeResult, error) {
	out := &ProbeResult{Connected: true}
	var count int
	if err := pool.QueryRowContext(ctx, `SELECT COUNT(1) FROM sys.databases WHERE name=@p1`, creds.Database).Scan(&count); err != nil {
		return out, fmt.Errorf("проверяю базу данных: %w", err)
	}
	out.DatabaseFound = count > 0
	rows, err := pool.QueryContext(ctx, `SELECT name FROM sys.tables WHERE schema_id=SCHEMA_ID(N'dbo') ORDER BY name`)
	if err != nil {
		return out, fmt.Errorf("список таблиц: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return out, err
		}
		out.Tables = append(out.Tables, strings.ToLower(name))
	}
	if err := rows.Err(); err != nil {
		return out, err
	}
	out.Kind = classifyTables(out.Tables)
	if out.Kind == "mandatnik" {
		out.Migrations, _ = readMigrationVersions(ctx, pool)
	}
	return out, nil
}

func readMigrationVersions(ctx context.Context, pool *sql.DB) ([]int, error) {
	rows, err := pool.QueryContext(ctx, `SELECT version FROM dbo.schema_migrations ORDER BY version`)
	if err != nil {
		if strings.Contains(err.Error(), "Invalid object name") {
			return nil, nil
		}
		return nil, err
	}
	defer rows.Close()
	var versions []int
	for rows.Next() {
		var version int
		if err := rows.Scan(&version); err != nil {
			return nil, err
		}
		versions = append(versions, version)
	}
	return versions, rows.Err()
}

// classifyTables distinguishes an empty database, an existing Mandatnik
// installation and a foreign non-empty database. Own service objects
// (schema_migrations and alike) count toward "mandatnik", not toward "empty".
func classifyTables(tables []string) string {
	if len(tables) == 0 {
		return "empty"
	}
	core := map[string]bool{}
	for _, t := range mandatnikCoreTables {
		core[t] = true
	}
	for _, t := range tables {
		if core[t] {
			return "mandatnik"
		}
	}
	return "foreign"
}

// CheckMigrationRights verifies that the login can create tables and write
// rows in the target database (minimum set for migrations and runtime).
func CheckMigrationRights(ctx context.Context, pool *sql.DB) error {
	tx, err := pool.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("не могу начать транзакцию (нужны права на запись): %w", err)
	}
	defer tx.Rollback()
	table := fmt.Sprintf("dbo.mndk_setup_probe_%d", time.Now().Unix())
	if _, err := tx.ExecContext(ctx, "CREATE TABLE "+table+" (id INT NOT NULL PRIMARY KEY)"); err != nil {
		return fmt.Errorf("нет прав на создание таблиц (db_ddladmin): %w", err)
	}
	if _, err := tx.ExecContext(ctx, "INSERT INTO "+table+" (id) VALUES (1)"); err != nil {
		return fmt.Errorf("нет прав на запись данных (db_datawriter): %w", err)
	}
	if _, err := tx.ExecContext(ctx, "SELECT id FROM "+table); err != nil {
		return fmt.Errorf("нет прав на чтение данных (db_datareader): %w", err)
	}
	if err := tx.Rollback(); err != nil {
		return err
	}
	return nil
}

// RuntimeDBPassword loads the DB password for config DB plans from the sealed
// store and returns a usable config.DB value.
func RuntimeDBPassword(store SecretStore) (string, error) {
	raw, err := store.Get(SecretDBPassword)
	if err != nil {
		return "", err
	}
	defer OverwriteZero(raw)
	return string(raw), nil
}
