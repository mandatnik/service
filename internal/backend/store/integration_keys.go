package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	mssql "github.com/microsoft/go-mssqldb"
)

// IntegrationKey is the non-secret representation of an API key.
type IntegrationKey struct {
	KeyID       string     `json:"key_id"`
	Name        string     `json:"name"`
	TokenPrefix string     `json:"token_prefix"`
	AllowedIPs  []string   `json:"allowed_ips"`
	CreatedAt   time.Time  `json:"created_at"`
	CreatedBy   string     `json:"created_by"`
	LastUsedAt  *time.Time `json:"last_used_at,omitempty"`
	LastUsedIP  string     `json:"last_used_ip,omitempty"`
	RevokedAt   *time.Time `json:"revoked_at,omitempty"`
	RevokedBy   string     `json:"revoked_by,omitempty"`
}

// Status returns active or revoked for admin responses.
func (k IntegrationKey) Status() string {
	if k.RevokedAt != nil {
		return "revoked"
	}
	return "active"
}

// AllowsIP checks the socket address against exact addresses and CIDRs. An
// empty list denies all requests by the agreed policy.
func (k IntegrationKey) AllowsIP(address net.IP) bool {
	if address == nil || len(k.AllowedIPs) == 0 {
		return false
	}
	if v4 := address.To4(); v4 != nil {
		address = v4
	}
	for _, entry := range k.AllowedIPs {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		if strings.Contains(entry, "/") {
			_, network, err := net.ParseCIDR(entry)
			if err == nil && network.Contains(address) {
				return true
			}
			continue
		}
		parsed := net.ParseIP(entry)
		if parsed == nil {
			continue
		}
		if v4 := parsed.To4(); v4 != nil {
			parsed = v4
		}
		if parsed.Equal(address) {
			return true
		}
	}
	return false
}

// NormalizeAllowedIPs validates exact IPs and CIDRs and returns their
// canonical strings without duplicates.
func NormalizeAllowedIPs(values []string) ([]string, error) {
	seen := make(map[string]bool, len(values))
	result := make([]string, 0, len(values))
	for _, raw := range values {
		value := strings.TrimSpace(raw)
		if value == "" {
			return nil, fmt.Errorf("IP address or CIDR must not be empty")
		}
		var canonical string
		if strings.Contains(value, "/") {
			ip, network, err := net.ParseCIDR(value)
			if err != nil {
				return nil, fmt.Errorf("invalid CIDR %q", raw)
			}
			canonical = network.String()
			_ = ip
		} else {
			ip := net.ParseIP(value)
			if ip == nil {
				return nil, fmt.Errorf("invalid IP address %q", raw)
			}
			canonical = ip.String()
		}
		if !seen[canonical] {
			seen[canonical] = true
			result = append(result, canonical)
		}
	}
	return result, nil
}

func scanIntegrationKey(scanner interface {
	Scan(dest ...any) error
}) (*IntegrationKey, error) {
	var item IntegrationKey
	var keyID mssql.UniqueIdentifier
	var allowedJSON string
	var lastUsed sql.NullTime
	var lastIP []byte
	var revoked sql.NullTime
	var revokedBy sql.NullString
	if err := scanner.Scan(
		&keyID, &item.Name, &item.TokenPrefix, &allowedJSON, &item.CreatedAt,
		&item.CreatedBy, &lastUsed, &lastIP, &revoked, &revokedBy,
	); err != nil {
		return nil, err
	}
	item.KeyID = uuidString(keyID)
	if err := json.Unmarshal([]byte(allowedJSON), &item.AllowedIPs); err != nil {
		return nil, fmt.Errorf("decode allowed_ips: %w", err)
	}
	if item.AllowedIPs == nil {
		item.AllowedIPs = []string{}
	}
	item.LastUsedAt = nullTime(lastUsed)
	item.LastUsedIP = ipString(lastIP)
	item.RevokedAt = nullTime(revoked)
	item.RevokedBy = nullString(revokedBy)
	return &item, nil
}

const integrationKeySelect = `
SELECT key_id, name, token_prefix, allowed_ips_json, created_at, created_by,
       last_used_at, last_used_ip, revoked_at, revoked_by
FROM dbo.integration_api_keys`

// IntegrationKeyByHash returns a key by its stored SHA-256, including revoked
// keys so the caller can distinguish 401 from a malformed token.
func (s *Store) IntegrationKeyByHash(ctx context.Context, tokenHash string) (*IntegrationKey, error) {
	row := s.DB.QueryRowContext(ctx, integrationKeySelect+` WHERE token_sha256=@p1`, tokenHash)
	key, err := scanIntegrationKey(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, sql.ErrNoRows
	}
	return key, err
}

func (s *Store) IntegrationKeyByID(ctx context.Context, keyID string) (*IntegrationKey, error) {
	row := s.DB.QueryRowContext(ctx, integrationKeySelect+` WHERE key_id=@p1`, keyID)
	key, err := scanIntegrationKey(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, sql.ErrNoRows
	}
	return key, err
}

func (s *Store) ListIntegrationKeys(ctx context.Context) ([]IntegrationKey, error) {
	rows, err := s.DB.QueryContext(ctx, integrationKeySelect+` ORDER BY created_at DESC, name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []IntegrationKey{}
	for rows.Next() {
		item, err := scanIntegrationKey(rows)
		if err != nil {
			return nil, err
		}
		items = append(items, *item)
	}
	return items, rows.Err()
}

func (s *Store) CreateIntegrationKey(ctx context.Context, keyID, name, tokenHash, tokenPrefix string, allowedIPs []string, createdBy string) error {
	allowedJSON, err := json.Marshal(allowedIPs)
	if err != nil {
		return err
	}
	_, err = s.DB.ExecContext(ctx, `
INSERT INTO dbo.integration_api_keys
    (key_id, name, token_sha256, token_prefix, allowed_ips_json, created_at, created_by)
VALUES (@p1,@p2,@p3,@p4,@p5,@p6,@p7)`,
		keyID, truncate(name, 200), tokenHash, tokenPrefix, string(allowedJSON), s.now(), createdBy)
	return err
}

func (s *Store) UpdateIntegrationKey(ctx context.Context, keyID, name string, allowedIPs []string) error {
	allowedJSON, err := json.Marshal(allowedIPs)
	if err != nil {
		return err
	}
	result, err := s.DB.ExecContext(ctx, `
UPDATE dbo.integration_api_keys SET name=@p1, allowed_ips_json=@p2
WHERE key_id=@p3 AND revoked_at IS NULL`, truncate(name, 200), string(allowedJSON), keyID)
	if err != nil {
		return err
	}
	affected, _ := result.RowsAffected()
	if affected == 0 {
		return sql.ErrNoRows
	}
	return nil
}

func (s *Store) RevokeIntegrationKey(ctx context.Context, keyID, revokedBy string) error {
	result, err := s.DB.ExecContext(ctx, `
UPDATE dbo.integration_api_keys SET revoked_at=@p1, revoked_by=@p2
WHERE key_id=@p3 AND revoked_at IS NULL`, s.now(), revokedBy, keyID)
	if err != nil {
		return err
	}
	affected, _ := result.RowsAffected()
	if affected > 0 {
		return nil
	}
	var exists int
	if err := s.DB.QueryRowContext(ctx, `SELECT COUNT(1) FROM dbo.integration_api_keys WHERE key_id=@p1`, keyID).Scan(&exists); err != nil {
		return err
	}
	if exists == 0 {
		return sql.ErrNoRows
	}
	return nil
}

// TouchIntegrationKey updates last-used metadata at most once per minute.
func (s *Store) TouchIntegrationKey(ctx context.Context, keyID string, address net.IP) error {
	_, err := s.DB.ExecContext(ctx, `
UPDATE dbo.integration_api_keys
SET last_used_at=@p1, last_used_ip=@p2
WHERE key_id=@p3 AND (last_used_at IS NULL OR last_used_at < DATEADD(minute,-1,@p1))`,
		s.now(), ipBytes(address), keyID)
	return err
}
