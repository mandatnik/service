package db

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"mandatnik/internal/backend/migrations"
)

// LogFunc receives migration progress. It must not receive credentials.
type LogFunc func(format string, args ...any)

const schemaMigrationsSQL = `
IF OBJECT_ID(N'dbo.schema_migrations', N'U') IS NULL
BEGIN
    CREATE TABLE dbo.schema_migrations (
        version INT NOT NULL CONSTRAINT PK_schema_migrations PRIMARY KEY,
        name NVARCHAR(200) NOT NULL,
        checksum CHAR(64) NOT NULL,
        applied_at DATETIME2(3) NOT NULL
    );
END`

// Migrate applies all embedded migrations in order. Applied migrations are
// checksum-verified; editing an applied file is an error. Each migration is
// transactional, so a failed batch does not leave a half-version.
func Migrate(ctx context.Context, pool *sql.DB, log LogFunc) error {
	files, err := migrations.All()
	if err != nil {
		return err
	}
	if _, err := pool.ExecContext(ctx, schemaMigrationsSQL); err != nil {
		return fmt.Errorf("create schema_migrations: %w", err)
	}
	applied, err := appliedMigrations(ctx, pool)
	if err != nil {
		return err
	}
	for _, file := range files {
		checksum := sha256.Sum256([]byte(file.Contents))
		checksumHex := hex.EncodeToString(checksum[:])
		if previous, exists := applied[file.Version]; exists {
			if previous != checksumHex {
				return fmt.Errorf("migration %s was modified after application (checksum %s, expected %s)", file.Name, checksumHex, previous)
			}
			continue
		}
		if log != nil {
			log("applying migration %s", file.Name)
		}
		if err := applyOne(ctx, pool, file, checksumHex); err != nil {
			return err
		}
		if log != nil {
			log("migration %s applied", file.Name)
		}
	}
	return nil
}

func appliedMigrations(ctx context.Context, pool *sql.DB) (map[int]string, error) {
	rows, err := pool.QueryContext(ctx, `SELECT version, checksum FROM dbo.schema_migrations`)
	if err != nil {
		return nil, fmt.Errorf("read schema_migrations: %w", err)
	}
	defer rows.Close()
	out := make(map[int]string)
	for rows.Next() {
		var version int
		var checksum string
		if err := rows.Scan(&version, &checksum); err != nil {
			return nil, err
		}
		out[version] = checksum
	}
	return out, rows.Err()
}

func applyOne(ctx context.Context, pool *sql.DB, file migrations.File, checksum string) error {
	tx, err := pool.BeginTx(ctx, &sql.TxOptions{})
	if err != nil {
		return fmt.Errorf("begin migration %s: %w", file.Name, err)
	}
	defer tx.Rollback()
	batches := splitBatches(file.Contents)
	for index, batch := range batches {
		if strings.TrimSpace(batch) == "" {
			continue
		}
		if _, err := tx.ExecContext(ctx, batch); err != nil {
			return fmt.Errorf("migration %s batch %d: %w", file.Name, index+1, err)
		}
	}
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO dbo.schema_migrations (version, name, checksum, applied_at) VALUES (@p1, @p2, @p3, @p4)`,
		file.Version, file.Name, checksum, time.Now().UTC()); err != nil {
		return fmt.Errorf("record migration %s: %w", file.Name, err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit migration %s: %w", file.Name, err)
	}
	return nil
}

// splitBatches splits on a line containing only GO (case-insensitive), which
// is the SQL Server tooling batch separator. GO is never sent to the driver.
func splitBatches(sqlText string) []string {
	lines := strings.Split(sqlText, "\n")
	var batches []string
	var current strings.Builder
	for _, line := range lines {
		if strings.EqualFold(strings.TrimSpace(line), "GO") {
			batches = append(batches, current.String())
			current.Reset()
			continue
		}
		current.WriteString(line)
		current.WriteByte('\n')
	}
	batches = append(batches, current.String())
	return batches
}

// MigrationStatus returns applied versions for diagnostics.
func MigrationStatus(ctx context.Context, pool *sql.DB) ([]int, error) {
	rows, err := pool.QueryContext(ctx, `SELECT version FROM dbo.schema_migrations ORDER BY version`)
	if err != nil {
		if strings.Contains(err.Error(), "Invalid object name") {
			return nil, errors.New("schema_migrations does not exist")
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
