// Package store contains SQL Server persistence for identities, configuration,
// jobs, reports and current observations. All mutating operations are
// transactional and replay-protected.
package store

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	mssql "github.com/microsoft/go-mssqldb"
	"mandatnik/internal/backend/licensecrypto"
	"mandatnik/internal/protocol"
)

// Store is the persistence layer.
type Store struct {
	DB             *sql.DB
	Now            func() time.Time
	LicenseKeyring *licensecrypto.Keyring
	FingerprintKey *licensecrypto.FingerprintKey
}

// New creates a Store. The clock is injectable for tests.
func New(db *sql.DB) *Store {
	return &Store{DB: db, Now: func() time.Time { return time.Now().UTC() }}
}

// SetLicenseCrypto installs the protected keyring and deduplication key. When
// they are absent, license operations fail explicitly and never fall back to
// plaintext.
func (s *Store) SetLicenseCrypto(keyring *licensecrypto.Keyring, fingerprint *licensecrypto.FingerprintKey) {
	s.LicenseKeyring = keyring
	s.FingerprintKey = fingerprint
}

func (s *Store) now() time.Time {
	if s.Now == nil {
		return time.Now().UTC()
	}
	return s.Now().UTC()
}

// isDuplicateKey reports SQL Server unique constraint/index violations.
func isDuplicateKey(err error) bool {
	var sqlErr mssql.Error
	if errors.As(err, &sqlErr) {
		if sqlErr.Number == 2627 || sqlErr.Number == 2601 {
			return true
		}
		for _, inner := range sqlErr.All {
			if inner.Number == 2627 || inner.Number == 2601 {
				return true
			}
		}
	}
	text := strings.ToLower(err.Error())
	return strings.Contains(text, "duplicate key") || strings.Contains(text, "violation of unique key")
}

// recordRequest atomically inserts a used request_id in the caller's
// transaction. A duplicate returns the stable replay error.
func recordRequest(ctx context.Context, tx *sql.Tx, identityUUID, requestID, endpoint string, now time.Time) *protocol.APIError {
	_, err := tx.ExecContext(ctx,
		`INSERT INTO dbo.request_ids (identity_uuid, request_id, endpoint, used_at) VALUES (@p1, @p2, @p3, @p4)`,
		identityUUID, requestID, endpoint, now)
	if err == nil {
		return nil
	}
	if isDuplicateKey(err) {
		return &protocol.APIError{Code: protocol.CodeReplay, Message: "request_id has already been used"}
	}
	return &protocol.APIError{Code: protocol.CodeDatabase, Message: "could not record request_id"}
}

type configRow struct {
	Config protocol.AgentConfig
	Hash   string
}

func loadConfigTx(ctx context.Context, tx *sql.Tx) (configRow, error) {
	var version int
	var raw string
	var storedHash string
	err := tx.QueryRowContext(ctx,
		`SELECT version, config_json, config_hash FROM dbo.configs WITH (NOLOCK) WHERE config_id = 1`).
		Scan(&version, &raw, &storedHash)
	if err != nil {
		return configRow{}, fmt.Errorf("load configuration: %w", err)
	}
	cfg, err := protocol.DecodeConfig([]byte(raw))
	if err != nil {
		return configRow{}, fmt.Errorf("stored configuration invalid: %w", err)
	}
	computed, err := protocol.ConfigHash(cfg)
	if err != nil {
		return configRow{}, fmt.Errorf("stored configuration hash: %w", err)
	}
	if !strings.EqualFold(computed, storedHash) {
		return configRow{}, fmt.Errorf("stored config_hash does not match config_json")
	}
	if cfg.Version != version {
		cfg.Version = version
	}
	return configRow{Config: cfg, Hash: strings.ToLower(storedHash)}, nil
}

func ipBytes(ip net.IP) []byte {
	if ip == nil {
		return nil
	}
	if v4 := ip.To4(); v4 != nil {
		return append([]byte(nil), v4...)
	}
	return append([]byte(nil), ip.To16()...)
}

func sha256Hex(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}

func sha256Bytes(value string) []byte {
	sum := sha256.Sum256([]byte(value))
	return sum[:]
}

func scopeHash(sourceType, sourceKey string) []byte {
	return sha256Bytes(strings.ToLower(sourceType) + "\x00" + strings.ToLower(sourceKey))
}

func observationHash(scope []byte, filePath string) []byte {
	if strings.TrimSpace(filePath) == "" {
		return append([]byte(nil), scope...)
	}
	h := sha256.New()
	h.Write(scope)
	h.Write([]byte("\x00"))
	h.Write([]byte(strings.ToLower(filePath)))
	return h.Sum(nil)
}

func uuidString(value mssql.UniqueIdentifier) string {
	return strings.ToLower(value.String())
}

func insertEvent(ctx context.Context, tx *sql.Tx, machineID, registrationID, reportID, requestID any, kind, severity, message string, details any, now time.Time) error {
	var detailsJSON any
	if details != nil {
		raw, err := json.Marshal(details)
		if err != nil {
			return err
		}
		detailsJSON = string(raw)
	}
	_, err := tx.ExecContext(ctx, `
INSERT INTO dbo.events (machine_id, registration_id, report_id, request_id, kind, severity, message, details_json, created_at)
VALUES (@p1, @p2, @p3, @p4, @p5, @p6, @p7, @p8, @p9)`,
		machineID, registrationID, reportID, requestID, kind, severity, truncate(message, 1024), detailsJSON, now)
	return err
}

func truncate(value string, max int) string {
	if len(value) <= max {
		return value
	}
	return value[:max]
}
