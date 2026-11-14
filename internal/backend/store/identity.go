package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	mssql "github.com/microsoft/go-mssqldb"
	"telehack2026/internal/protocol"
)

// Identity is an active agent registration used for request authentication.
type Identity struct {
	RegistrationID  int64
	MachineID       string
	UUID            string
	Hostname        string
	HostnameNorm    string
	PublicKeyPEM    string
	PublicKeySHA256 string
	AgentVersion    string
	OSVersion       string
	Architecture    string
	State           string
}

// LookupActiveIdentity loads an active registration by UUID. It deliberately
// returns unknown_identity for missing and revoked rows so callers do not leak
// which UUIDs ever existed.
func (s *Store) LookupActiveIdentity(ctx context.Context, uuid string) (*Identity, *protocol.APIError) {
	normalized, err := protocol.NormalizeUUID(uuid)
	if err != nil {
		return nil, &protocol.APIError{Code: protocol.CodeInvalidIdentity, Message: err.Error()}
	}
	var identity Identity
	var machineID mssql.UniqueIdentifier
	var uuidValue mssql.UniqueIdentifier
	err = s.DB.QueryRowContext(ctx, `
SELECT registration_id, machine_id, uuid, hostname, hostname_norm, public_key_pem,
       public_key_sha256, COALESCE(agent_version,''), COALESCE(os_version,''),
       COALESCE(architecture,''), state
FROM dbo.registrations WHERE uuid = @p1`, normalized).Scan(
		&identity.RegistrationID, &machineID, &uuidValue, &identity.Hostname,
		&identity.HostnameNorm, &identity.PublicKeyPEM, &identity.PublicKeySHA256,
		&identity.AgentVersion, &identity.OSVersion, &identity.Architecture, &identity.State)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, &protocol.APIError{Code: protocol.CodeUnknownIdentity, Message: "identity is not registered"}
	}
	if err != nil {
		return nil, &protocol.APIError{Code: protocol.CodeDatabase, Message: "could not load identity"}
	}
	identity.MachineID = uuidString(machineID)
	identity.UUID = uuidString(uuidValue)
	if identity.State != "active" {
		return nil, &protocol.APIError{Code: protocol.CodeIdentityRevoked, Message: "identity is not active"}
	}
	return &identity, nil
}

// RegisterResult is the successful registration/rename response.
type RegisterResult struct {
	MachineID    string
	UUID         string
	Hostname     string
	RegisteredAt time.Time
	Config       protocol.AgentConfig
	ConfigHash   string
	Warnings     []string
}

// Register implements the registration matrix. It runs under a serializable
// transaction and locks the UUID/hostname rows to avoid silent races.
func (s *Store) Register(ctx context.Context, request *protocol.SignedRequest, sourceIP net.IP, dnsStatus string) (*RegisterResult, *protocol.APIError) {
	pub, err := protocol.ParsePublicKeyPEM(request.Data.PublicKey)
	if err != nil {
		return nil, &protocol.APIError{Code: protocol.CodeInvalidKey, Message: err.Error()}
	}
	fingerprint, err := protocol.PublicKeyFingerprint(pub)
	if err != nil {
		return nil, &protocol.APIError{Code: protocol.CodeInvalidKey, Message: err.Error()}
	}
	normalizedPublicKey, err := protocol.MarshalPublicKeyPEM(pub)
	if err != nil {
		return nil, &protocol.APIError{Code: protocol.CodeInvalidKey, Message: err.Error()}
	}
	uuid, err := protocol.NormalizeUUID(request.Data.UUID)
	if err != nil {
		return nil, &protocol.APIError{Code: protocol.CodeInvalidIdentity, Message: err.Error()}
	}
	hostname, err := protocol.NormalizeHostname(request.Data.Hostname)
	if err != nil {
		return nil, &protocol.APIError{Code: protocol.CodeInvalidIdentity, Message: err.Error()}
	}
	hostnameNorm := strings.ToLower(hostname)
	now := s.now()

	tx, err := s.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return nil, &protocol.APIError{Code: protocol.CodeDatabase, Message: "begin registration transaction"}
	}
	defer tx.Rollback()

	var existing RegistrationRow
	err = tx.QueryRowContext(ctx, `
SELECT registration_id, machine_id, hostname, hostname_norm, public_key_sha256, state, created_at,
       COALESCE(agent_version,''), COALESCE(os_version,''), COALESCE(architecture,'')
FROM dbo.registrations WITH (UPDLOCK, HOLDLOCK) WHERE uuid = @p1`, uuid).Scan(
		&existing.RegistrationID, &existing.MachineID, &existing.Hostname, &existing.HostnameNorm,
		&existing.PublicKeySHA256, &existing.State, &existing.CreatedAt,
		&existing.AgentVersion, &existing.OSVersion, &existing.Architecture)
	switch {
	case err == nil:
		if existing.State != "active" {
			return nil, &protocol.APIError{Code: protocol.CodeIdentityRevoked, Message: "identity is not active"}
		}
		if !strings.EqualFold(strings.TrimSpace(existing.PublicKeySHA256), fingerprint) {
			if apiErr := recordRequest(ctx, tx, uuid, request.Data.RequestID, protocol.PathRegister, now); apiErr != nil {
				return nil, apiErr
			}
			_ = insertEvent(ctx, tx, uuidString(existing.MachineID), existing.RegistrationID, nil, request.Data.RequestID,
				"key_conflict", "error", "registration attempted with a different public key", nil, now)
			if err := tx.Commit(); err != nil {
				return nil, &protocol.APIError{Code: protocol.CodeDatabase, Message: "commit key conflict audit"}
			}
			return nil, &protocol.APIError{Code: protocol.CodeKeyConflict, Message: "UUID is already registered with a different public key"}
		}
		if !protocol.HostnamesEqual(existing.Hostname, hostname) {
			if apiErr := recordRequest(ctx, tx, uuid, request.Data.RequestID, protocol.PathRegister, now); apiErr != nil {
				return nil, apiErr
			}
			_ = insertEvent(ctx, tx, uuidString(existing.MachineID), existing.RegistrationID, nil, request.Data.RequestID,
				"hostname_mismatch", "warning", "registration attempted with a changed hostname without rename", map[string]any{"signed_hostname": hostname, "registered_hostname": existing.Hostname}, now)
			if err := tx.Commit(); err != nil {
				return nil, &protocol.APIError{Code: protocol.CodeDatabase, Message: "commit hostname conflict audit"}
			}
			return nil, &protocol.APIError{Code: protocol.CodeHostnameMismatch, Message: "hostname changed; a signed rename is required"}
		}
		if apiErr := recordRequest(ctx, tx, uuid, request.Data.RequestID, protocol.PathRegister, now); apiErr != nil {
			return nil, apiErr
		}
		if _, err := tx.ExecContext(ctx, `
UPDATE dbo.registrations SET last_seen_at=@p1, last_source_ip=@p2, last_dns_status=@p3, last_dns_checked_at=@p4,
       agent_version=@p5, os_version=@p6, architecture=@p7
WHERE registration_id=@p8`,
			now, ipBytes(sourceIP), dnsStatus, now, boundAgentVersion(request), truncate(request.Data.OSVersion, 128), request.Data.Architecture, existing.RegistrationID); err != nil {
			return nil, &protocol.APIError{Code: protocol.CodeDatabase, Message: "update registration"}
		}
		if _, err := tx.ExecContext(ctx, `UPDATE dbo.hostnames SET last_seen_at=@p1 WHERE hostname_norm=@p2`, now, hostnameNorm); err != nil {
			return nil, &protocol.APIError{Code: protocol.CodeDatabase, Message: "update hostname reservation"}
		}
		config, configErr := effectiveConfigTx(ctx, tx, uuidString(existing.MachineID))
		if configErr != nil {
			return nil, &protocol.APIError{Code: protocol.CodeDatabase, Message: configErr.Error()}
		}
		if err := tx.Commit(); err != nil {
			return nil, &protocol.APIError{Code: protocol.CodeDatabase, Message: "commit registration"}
		}
		warnings := []string{}
		if dnsStatus == "mismatch" || dnsStatus == "error" {
			warnings = append(warnings, "dns_unverified")
		}
		return &RegisterResult{MachineID: uuidString(existing.MachineID), UUID: uuid, Hostname: hostname, RegisteredAt: existing.CreatedAt, Config: config.Config, ConfigHash: config.Hash, Warnings: warnings}, nil
	case errors.Is(err, sql.ErrNoRows):
		// Continue as a new registration.
	default:
		return nil, &protocol.APIError{Code: protocol.CodeDatabase, Message: "look up registration"}
	}

	warnings := []string{}
	// A new UUID with a previously used key is allowed, but it must not merge
	// machines or transfer history silently. Record the fact for an administrator.
	var reusedUUID string
	err = tx.QueryRowContext(ctx, `
SELECT uuid FROM dbo.registrations WITH (UPDLOCK, HOLDLOCK)
WHERE public_key_sha256=@p1 AND state='active'`, fingerprint).Scan(&reusedUUID)
	if err == nil && !strings.EqualFold(reusedUUID, uuid) {
		warnings = append(warnings, "public_key_reused")
	}

	machineID := protocol.NewUUID()
	if _, err := tx.ExecContext(ctx, `
INSERT INTO dbo.machines (machine_id, display_name, created_at, updated_at) VALUES (@p1, @p2, @p3, @p4)`,
		machineID, hostname, now, now); err != nil {
		return nil, &protocol.APIError{Code: protocol.CodeDatabase, Message: "create machine"}
	}
	var registrationID int64
	if err := tx.QueryRowContext(ctx, `
INSERT INTO dbo.registrations
 (machine_id, uuid, hostname, hostname_norm, public_key_pem, public_key_sha256, state,
  agent_version, os_version, architecture, created_at, last_seen_at, last_source_ip, last_dns_status, last_dns_checked_at)
OUTPUT INSERTED.registration_id
VALUES (@p1,@p2,@p3,@p4,@p5,@p6,N'active',@p7,@p8,@p9,@p10,@p11,@p12,@p13,@p14)`,
		machineID, uuid, hostname, hostnameNorm, normalizedPublicKey, fingerprint,
		boundAgentVersion(request), truncate(request.Data.OSVersion, 128), request.Data.Architecture,
		now, now, ipBytes(sourceIP), dnsStatus, now).Scan(&registrationID); err != nil {
		if isDuplicateKey(err) {
			return nil, &protocol.APIError{Code: protocol.CodeUUIDConflict, Message: "UUID is already registered"}
		}
		return nil, &protocol.APIError{Code: protocol.CodeDatabase, Message: "create registration"}
	}

	conflict, previousOwner, err := claimHostnameTx(ctx, tx, hostnameNorm, hostname, registrationID, machineID, now, false)
	if err != nil {
		return nil, &protocol.APIError{Code: protocol.CodeDatabase, Message: "reserve hostname"}
	}
	if conflict {
		warnings = append(warnings, "hostname_conflict")
		_ = insertEvent(ctx, tx, machineID, registrationID, nil, request.Data.RequestID,
			"hostname_conflict", "warning", "hostname is reserved by another active registration",
			map[string]any{"hostname": hostname, "previous_registration_id": previousOwner}, now)
	}
	if apiErr := recordRequest(ctx, tx, uuid, request.Data.RequestID, protocol.PathRegister, now); apiErr != nil {
		return nil, apiErr
	}
	if err := insertEvent(ctx, tx, machineID, registrationID, nil, request.Data.RequestID,
		"machine_registered", "info", "agent registered", map[string]any{"hostname": hostname, "key_fingerprint": fingerprint, "warnings": warnings}, now); err != nil {
		return nil, &protocol.APIError{Code: protocol.CodeDatabase, Message: "record registration event"}
	}
	if dnsStatus == "mismatch" || dnsStatus == "error" {
		warnings = append(warnings, "dns_unverified")
		_ = insertEvent(ctx, tx, machineID, registrationID, nil, request.Data.RequestID,
			"dns_unverified", "warning", "hostname does not resolve to the source IP", map[string]any{"dns_status": dnsStatus}, now)
	}
	config, configErr := effectiveConfigTx(ctx, tx, machineID)
	if configErr != nil {
		return nil, &protocol.APIError{Code: protocol.CodeDatabase, Message: configErr.Error()}
	}
	if err := tx.Commit(); err != nil {
		return nil, &protocol.APIError{Code: protocol.CodeDatabase, Message: "commit registration"}
	}
	return &RegisterResult{MachineID: machineID, UUID: uuid, Hostname: hostname, RegisteredAt: now, Config: config.Config, ConfigHash: config.Hash, Warnings: warnings}, nil
}

type RegistrationRow struct {
	RegistrationID  int64
	MachineID       mssql.UniqueIdentifier
	Hostname        string
	HostnameNorm    string
	PublicKeySHA256 string
	State           string
	CreatedAt       time.Time
	AgentVersion    string
	OSVersion       string
	Architecture    string
}

func boundAgentVersion(request *protocol.SignedRequest) string {
	if request == nil {
		return ""
	}
	return truncate(request.Data.AgentVersion, 128)
}

// claimHostnameTx reserves a hostname for a registration. It returns a
// conflict flag and the previous owner registration ID (0 if none). A stale
// reservation is reclaimed; an active owner is never overwritten silently.
func claimHostnameTx(ctx context.Context, tx *sql.Tx, hostnameNorm, displayName string, registrationID int64, machineID string, now time.Time, releaseOnly bool) (bool, int64, error) {
	var owner sql.NullInt64
	err := tx.QueryRowContext(ctx, `
SELECT owner_registration_id FROM dbo.hostnames WITH (UPDLOCK, HOLDLOCK) WHERE hostname_norm=@p1`, hostnameNorm).Scan(&owner)
	if errors.Is(err, sql.ErrNoRows) {
		if releaseOnly {
			return false, 0, nil
		}
		_, err = tx.ExecContext(ctx, `
INSERT INTO dbo.hostnames (hostname_norm, display_name, owner_registration_id, owner_machine_id, reserved_at, last_seen_at)
VALUES (@p1,@p2,@p3,@p4,@p5,@p6)`, hostnameNorm, displayName, registrationID, machineID, now, now)
		return false, 0, err
	}
	if err != nil {
		return false, 0, err
	}
	if !owner.Valid {
		if releaseOnly {
			return false, 0, nil
		}
		_, err = tx.ExecContext(ctx, `
UPDATE dbo.hostnames SET display_name=@p1, owner_registration_id=@p2, owner_machine_id=@p3, reserved_at=@p4, last_seen_at=@p5
WHERE hostname_norm=@p6`, displayName, registrationID, machineID, now, now, hostnameNorm)
		return false, 0, err
	}
	if owner.Int64 == registrationID {
		if !releaseOnly {
			_, err = tx.ExecContext(ctx, `UPDATE dbo.hostnames SET display_name=@p1, last_seen_at=@p2 WHERE hostname_norm=@p3`, displayName, now, hostnameNorm)
		}
		return false, owner.Int64, err
	}
	var ownerState string
	if err := tx.QueryRowContext(ctx, `SELECT state FROM dbo.registrations WITH (UPDLOCK, HOLDLOCK) WHERE registration_id=@p1`, owner.Int64).Scan(&ownerState); err != nil && !errors.Is(err, sql.ErrNoRows) {
		return false, owner.Int64, err
	}
	if ownerState == "active" {
		return true, owner.Int64, nil
	}
	if releaseOnly {
		return false, owner.Int64, nil
	}
	_, err = tx.ExecContext(ctx, `
UPDATE dbo.hostnames SET display_name=@p1, owner_registration_id=@p2, owner_machine_id=@p3, reserved_at=@p4, last_seen_at=@p5
WHERE hostname_norm=@p6`, displayName, registrationID, machineID, now, now, hostnameNorm)
	return false, owner.Int64, err
}

func releaseHostnameTx(ctx context.Context, tx *sql.Tx, hostnameNorm string, registrationID int64) error {
	_, err := tx.ExecContext(ctx, `
UPDATE dbo.hostnames SET owner_registration_id=NULL, owner_machine_id=NULL
WHERE hostname_norm=@p1 AND owner_registration_id=@p2`, hostnameNorm, registrationID)
	return err
}

// Rename performs a signed identity transition. The old registration remains
// in history as 'renamed'; the machine_id and all observations are preserved.
func (s *Store) Rename(ctx context.Context, request *protocol.SignedRequest, sourceIP net.IP, dnsStatus string) (*RegisterResult, *protocol.APIError) {
	oldUUID, err := protocol.NormalizeUUID(request.Data.UUID)
	if err != nil {
		return nil, &protocol.APIError{Code: protocol.CodeInvalidIdentity, Message: err.Error()}
	}
	newUUID, err := protocol.NormalizeUUID(request.Data.NewUUID)
	if err != nil {
		return nil, &protocol.APIError{Code: protocol.CodeInvalidIdentity, Message: "new_uuid: " + err.Error()}
	}
	if newUUID == oldUUID {
		return nil, &protocol.APIError{Code: protocol.CodeInvalidIdentity, Message: "new_uuid must differ from the old UUID"}
	}
	newHostname, err := protocol.NormalizeHostname(request.Data.NewHostname)
	if err != nil {
		return nil, &protocol.APIError{Code: protocol.CodeInvalidIdentity, Message: "new_hostname: " + err.Error()}
	}
	newPub, err := protocol.ParsePublicKeyPEM(request.Data.NewPublicKey)
	if err != nil {
		return nil, &protocol.APIError{Code: protocol.CodeInvalidKey, Message: "new_public_key: " + err.Error()}
	}
	newFingerprint, err := protocol.PublicKeyFingerprint(newPub)
	if err != nil {
		return nil, &protocol.APIError{Code: protocol.CodeInvalidKey, Message: err.Error()}
	}
	normalizedNewKey, err := protocol.MarshalPublicKeyPEM(newPub)
	if err != nil {
		return nil, &protocol.APIError{Code: protocol.CodeInvalidKey, Message: err.Error()}
	}
	now := s.now()

	tx, err := s.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return nil, &protocol.APIError{Code: protocol.CodeDatabase, Message: "begin rename transaction"}
	}
	defer tx.Rollback()

	var old RegistrationRow
	err = tx.QueryRowContext(ctx, `
SELECT registration_id, machine_id, hostname, hostname_norm, public_key_sha256, state, created_at,
       COALESCE(agent_version,''), COALESCE(os_version,''), COALESCE(architecture,'')
FROM dbo.registrations WITH (UPDLOCK, HOLDLOCK) WHERE uuid=@p1`, oldUUID).Scan(
		&old.RegistrationID, &old.MachineID, &old.Hostname, &old.HostnameNorm, &old.PublicKeySHA256,
		&old.State, &old.CreatedAt, &old.AgentVersion, &old.OSVersion, &old.Architecture)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, &protocol.APIError{Code: protocol.CodeUnknownIdentity, Message: "identity is not registered"}
	}
	if err != nil {
		return nil, &protocol.APIError{Code: protocol.CodeDatabase, Message: "load old registration"}
	}
	if old.State != "active" {
		return nil, &protocol.APIError{Code: protocol.CodeIdentityRevoked, Message: "identity is not active"}
	}
	if protocol.HostnamesEqual(old.Hostname, newHostname) {
		return nil, &protocol.APIError{Code: protocol.CodeInvalidIdentity, Message: "new hostname must differ from the old hostname"}
	}
	var exists int
	err = tx.QueryRowContext(ctx, `SELECT COUNT(1) FROM dbo.registrations WITH (UPDLOCK, HOLDLOCK) WHERE uuid=@p1`, newUUID).Scan(&exists)
	if err != nil {
		return nil, &protocol.APIError{Code: protocol.CodeDatabase, Message: "check new UUID"}
	}
	if exists != 0 {
		return nil, &protocol.APIError{Code: protocol.CodeUUIDConflict, Message: "new UUID is already registered"}
	}

	machineID := uuidString(old.MachineID)
	var newRegistrationID int64
	if err := tx.QueryRowContext(ctx, `
INSERT INTO dbo.registrations
 (machine_id, uuid, hostname, hostname_norm, public_key_pem, public_key_sha256, state,
  agent_version, os_version, architecture, previous_registration_id, created_at, last_seen_at, last_source_ip, last_dns_status, last_dns_checked_at)
OUTPUT INSERTED.registration_id
VALUES (@p1,@p2,@p3,@p4,@p5,@p6,N'active',@p7,@p8,@p9,@p10,@p11,@p12,@p13,@p14,@p15)`,
		machineID, newUUID, newHostname, strings.ToLower(newHostname), normalizedNewKey, newFingerprint,
		boundAgentVersion(request), truncate(request.Data.OSVersion, 128), request.Data.Architecture,
		old.RegistrationID, now, now, ipBytes(sourceIP), dnsStatus, now).Scan(&newRegistrationID); err != nil {
		return nil, &protocol.APIError{Code: protocol.CodeDatabase, Message: "create new registration"}
	}
	if _, err := tx.ExecContext(ctx, `
UPDATE dbo.registrations SET state=N'renamed', revoked_at=@p1, replaced_by_registration_id=@p2 WHERE registration_id=@p3`,
		now, newRegistrationID, old.RegistrationID); err != nil {
		return nil, &protocol.APIError{Code: protocol.CodeDatabase, Message: "retire old registration"}
	}
	// A rename is a confirmed transition of the same machine. Preserve
	// capabilities and the active encryption key while deactivating the old
	// registration's key row, so unfinished item envelopes remain decryptable.
	if _, err := tx.ExecContext(ctx, `
INSERT INTO dbo.agent_capabilities(registration_id,capabilities_json,schedule_v2,tasks_v1,install_v1,updated_at)
SELECT @p1,capabilities_json,schedule_v2,tasks_v1,install_v1,@p2
FROM dbo.agent_capabilities WHERE registration_id=@p3`, newRegistrationID, now, old.RegistrationID); err != nil {
		return nil, &protocol.APIError{Code: protocol.CodeDatabase, Message: "copy agent capabilities on rename"}
	}
	if _, err := tx.ExecContext(ctx, `
UPDATE dbo.agent_encryption_keys SET active=0 WHERE registration_id=@p1 AND revoked_at IS NULL`, old.RegistrationID); err != nil {
		return nil, &protocol.APIError{Code: protocol.CodeDatabase, Message: "deactivate old encryption key"}
	}
	if _, err := tx.ExecContext(ctx, `
INSERT INTO dbo.agent_encryption_keys(key_id,machine_id,registration_id,public_key_pem,algorithm,bits,active,created_at)
SELECT key_id,machine_id,@p1,public_key_pem,algorithm,bits,1,@p2
FROM dbo.agent_encryption_keys WHERE registration_id=@p3 AND active=0 AND revoked_at IS NULL
  AND NOT EXISTS(SELECT 1 FROM dbo.agent_encryption_keys k2 WHERE k2.registration_id=@p1 AND k2.key_id=dbo.agent_encryption_keys.key_id)`,
		newRegistrationID, now, old.RegistrationID); err != nil {
		return nil, &protocol.APIError{Code: protocol.CodeDatabase, Message: "copy encryption key on rename"}
	}
	if _, err := tx.ExecContext(ctx, `UPDATE dbo.machines SET display_name=@p1, updated_at=@p2 WHERE machine_id=@p3`, newHostname, now, machineID); err != nil {
		return nil, &protocol.APIError{Code: protocol.CodeDatabase, Message: "update machine name"}
	}
	if err := releaseHostnameTx(ctx, tx, old.HostnameNorm, old.RegistrationID); err != nil {
		return nil, &protocol.APIError{Code: protocol.CodeDatabase, Message: "release old hostname"}
	}
	warnings := []string{}
	conflict, previousOwner, err := claimHostnameTx(ctx, tx, strings.ToLower(newHostname), newHostname, newRegistrationID, machineID, now, false)
	if err != nil {
		return nil, &protocol.APIError{Code: protocol.CodeDatabase, Message: "claim new hostname"}
	}
	if conflict {
		warnings = append(warnings, "hostname_conflict")
		_ = insertEvent(ctx, tx, machineID, newRegistrationID, nil, request.Data.RequestID,
			"hostname_conflict", "warning", "renamed hostname is reserved by another active registration",
			map[string]any{"hostname": newHostname, "previous_registration_id": previousOwner}, now)
	}
	// The old registration is no longer authorized, so its delayed reports
	// cannot apply. Reset per-source ordering for the new identity while
	// preserving the current observations.
	if _, err := tx.ExecContext(ctx, `UPDATE dbo.source_states SET last_scan_seq=0, updated_at=@p1 WHERE machine_id=@p2`, now, machineID); err != nil {
		return nil, &protocol.APIError{Code: protocol.CodeDatabase, Message: "reset source ordering"}
	}
	if _, err := tx.ExecContext(ctx, `UPDATE dbo.csp_states SET last_scan_seq=0, updated_at=@p1 WHERE machine_id=@p2`, now, machineID); err != nil {
		return nil, &protocol.APIError{Code: protocol.CodeDatabase, Message: "reset CSP ordering"}
	}
	if apiErr := recordRequest(ctx, tx, oldUUID, request.Data.RequestID, protocol.PathRename, now); apiErr != nil {
		return nil, apiErr
	}
	if err := insertEvent(ctx, tx, machineID, newRegistrationID, nil, request.Data.RequestID,
		"machine_renamed", "info", "identity transition completed",
		map[string]any{"old_uuid": oldUUID, "old_hostname": old.Hostname, "new_uuid": newUUID, "new_hostname": newHostname}, now); err != nil {
		return nil, &protocol.APIError{Code: protocol.CodeDatabase, Message: "record rename event"}
	}
	config, configErr := effectiveConfigTx(ctx, tx, machineID)
	if configErr != nil {
		return nil, &protocol.APIError{Code: protocol.CodeDatabase, Message: configErr.Error()}
	}
	if err := tx.Commit(); err != nil {
		return nil, &protocol.APIError{Code: protocol.CodeDatabase, Message: "commit rename"}
	}
	return &RegisterResult{MachineID: machineID, UUID: newUUID, Hostname: newHostname, RegisteredAt: now, Config: config.Config, ConfigHash: config.Hash, Warnings: warnings}, nil
}

// UpdateNetworkTrust records the source IP and DNS signal on an active
// registration. It is used by sync/report before the business transaction.
func (s *Store) UpdateNetworkTrust(ctx context.Context, identity *Identity, sourceIP net.IP, dnsStatus string) {
	if identity == nil {
		return
	}
	_, _ = s.DB.ExecContext(ctx, `
UPDATE dbo.registrations SET last_seen_at=@p1, last_source_ip=@p2, last_dns_status=@p3, last_dns_checked_at=@p1
WHERE registration_id=@p4`, s.now(), ipBytes(sourceIP), dnsStatus, identity.RegistrationID)
}

// Config returns the current configuration and hash.
func (s *Store) Config(ctx context.Context) (protocol.AgentConfig, string, error) {
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return protocol.AgentConfig{}, "", err
	}
	defer tx.Rollback()
	row, err := loadConfigTx(ctx, tx)
	if err != nil {
		return protocol.AgentConfig{}, "", err
	}
	_ = tx.Commit()
	return row.Config, row.Hash, nil
}

// MachineByUUID returns the internal machine_id and active registration for a
// UUID; used by acceptance checks.
func (s *Store) MachineByUUID(ctx context.Context, uuid string) (string, int64, error) {
	var machine mssql.UniqueIdentifier
	var registration int64
	err := s.DB.QueryRowContext(ctx, `SELECT machine_id, registration_id FROM dbo.registrations WHERE uuid=@p1`, uuid).Scan(&machine, &registration)
	if err != nil {
		return "", 0, err
	}
	return uuidString(machine), registration, nil
}

// RecordDNSWarning records a throttled administrator event when hostname
// resolution does not confirm the source IP. A correctly signed request is
// still accepted; DNS is a signal, not an authorization gate.
func (s *Store) RecordDNSWarning(ctx context.Context, machineID, status string) {
	if machineID == "" || (status != "mismatch" && status != "error") {
		return
	}
	now := s.now()
	var count int
	err := s.DB.QueryRowContext(ctx, `
SELECT COUNT(1) FROM dbo.events
WHERE machine_id=@p1 AND kind=N'dns_unverified' AND created_at > DATEADD(hour, -1, @p2)`, machineID, now).Scan(&count)
	if err != nil || count != 0 {
		return
	}
	_, _ = s.DB.ExecContext(ctx, `
INSERT INTO dbo.events (machine_id, registration_id, report_id, request_id, kind, severity, message, details_json, created_at)
VALUES (@p1, NULL, NULL, NULL, N'dns_unverified', N'warning', N'hostname does not resolve to the source IP', @p2, @p3)`,
		machineID, fmt.Sprintf(`{"dns_status":%q}`, status), now)
}
