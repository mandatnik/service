package store

import (
	"context"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	mssql "github.com/microsoft/go-mssqldb"
	"telehack2026/internal/protocol"
)

// InstallationRegistrationInfo is the registration view shown to an
// administrator before an installation decision. It never contains a private
// key or any agent secret.
type InstallationRegistrationInfo struct {
	RegistrationID int64      `json:"registration_id"`
	UUID           string     `json:"uuid"`
	Hostname       string     `json:"hostname"`
	State          string     `json:"state"`
	KeyFingerprint string     `json:"key_fingerprint"`
	CreatedAt      time.Time  `json:"created_at"`
	LastSeenAt     *time.Time `json:"last_seen_at,omitempty"`
	SourceIP       string     `json:"source_ip,omitempty"`
	DNSStatus      string     `json:"dns_status,omitempty"`
}

// InstallationCandidate is an existing machine card whose name or historical
// registration matches a pending installation. Matching is informational: a
// candidate is never merged automatically.
type InstallationCandidate struct {
	MachineID          string                        `json:"machine_id"`
	DisplayName        string                        `json:"display_name"`
	Archived           bool                          `json:"archived"`
	ArchiveReason      string                        `json:"archive_reason,omitempty"`
	NameMatch          bool                          `json:"name_match"`
	ActiveRegistration *InstallationRegistrationInfo `json:"active_registration,omitempty"`
	LastRegistration   *InstallationRegistrationInfo `json:"last_registration,omitempty"`
	LastSeenAt         *time.Time                    `json:"last_seen_at,omitempty"`
	Online             bool                          `json:"online"`
	RecentActivity     bool                          `json:"recent_activity"`
}

// PendingInstallation is one signed agent installation waiting for an
// administrator decision. RequestVersion and KeyFingerprint are the
// confirmation nonce: a decision is rejected if either changed after the
// administrator opened the review.
type PendingInstallation struct {
	RequestID      string     `json:"request_id"`
	RequestVersion int        `json:"request_version"`
	UUID           string     `json:"uuid"`
	Hostname       string     `json:"hostname"`
	KeyFingerprint string     `json:"key_fingerprint"`
	FirstSeenAt    time.Time  `json:"first_seen_at"`
	LastSeenAt     time.Time  `json:"last_seen_at"`
	SourceIP       string     `json:"source_ip,omitempty"`
	DNSStatus      string     `json:"dns_status,omitempty"`
	AgentVersion   string     `json:"agent_version,omitempty"`
	OSVersion      string     `json:"os_version,omitempty"`
	Architecture   string     `json:"architecture,omitempty"`
	State          string     `json:"state"`
	CreatedAt      time.Time  `json:"created_at"`
	DecidedAt      *time.Time `json:"decided_at,omitempty"`
	DecidedBy      string     `json:"decided_by,omitempty"`
	DecisionNote   string     `json:"decision_note,omitempty"`

	// Candidates are machines that share the signed name (current display
	// name, active or historical registration hostname, or hostname owner).
	Candidates []InstallationCandidate `json:"candidates"`

	// RegisteredMachineID is set when this UUID is already active in another
	// machine card. Replacement and separate registration are then refused;
	// the administrator must archive/review the existing card instead of
	// performing a partial merge.
	RegisteredMachineID   string `json:"registered_machine_id,omitempty"`
	RegisteredMachineName string `json:"registered_machine_name,omitempty"`
	ResolvedMachineID     string `json:"resolved_machine_id,omitempty"`
	ResolvedRegistration  int64  `json:"resolved_registration_id,omitempty"`
}

type InstallationDecisionInput struct {
	RequestID           string
	RequestVersion      int
	KeyFingerprint      string
	MachineID           string
	OldRegistrationID   int64
	Reason              string
	ConfirmNameConflict bool
}

type InstallationDecisionResult struct {
	RequestID        string `json:"request_id"`
	MachineID        string `json:"machine_id"`
	RegistrationID   int64  `json:"registration_id"`
	UUID             string `json:"uuid"`
	Hostname         string `json:"hostname"`
	State            string `json:"state"`
	KeyFingerprint   string `json:"key_fingerprint"`
	Duplicate        bool   `json:"duplicate"`
	OldSeenRecently  bool   `json:"old_seen_recently"`
	HostnameConflict bool   `json:"hostname_conflict"`
}

type installationRequestRow struct {
	RequestID              string
	UUID                   string
	Hostname               string
	HostnameNorm           string
	PublicKeyPEM           string
	PublicKeySHA256        string
	State                  string
	RequestVersion         int
	FirstSeenAt            time.Time
	LastSeenAt             time.Time
	LastSourceIP           []byte
	DNSStatus              string
	AgentVersion           string
	OSVersion              string
	Architecture           string
	ResolvedMachineID      string
	ResolvedRegistrationID int64
	DecidedBy              string
	DecidedAt              *time.Time
	DecisionNote           string
	CreatedAt              time.Time
}

func normalizeFingerprint(value string) (string, error) {
	value = strings.ToLower(strings.TrimSpace(value))
	if len(value) != 64 {
		return "", fmt.Errorf("key fingerprint must be 64 hexadecimal characters")
	}
	if _, err := hex.DecodeString(value); err != nil {
		return "", fmt.Errorf("key fingerprint must be hexadecimal")
	}
	return value, nil
}

// CreateOrUpdateInstallationRequest stores a signed unknown installation when
// its hostname is already associated with an existing machine card. Only the
// public key is retained; the registration request signature already proved
// possession of the corresponding private key.
func (s *Store) createOrUpdateInstallationRequest(ctx context.Context, tx *sql.Tx, uuid, hostname, hostnameNorm, publicKeyPEM, fingerprint string, request *protocol.SignedRequest, sourceIP []byte, dnsStatus string, now time.Time) (*protocol.APIError, error) {
	var existing installationRequestRow
	var lastIP []byte
	var dns sql.NullString
	var agentVersion, osVersion, architecture, decidedBy, decisionNote sql.NullString
	var resolvedMachine mssql.NullUniqueIdentifier
	var resolvedRegistration sql.NullInt64
	var decidedAt sql.NullTime
	var requestIDValue, uuidValue mssql.UniqueIdentifier
	err := tx.QueryRowContext(ctx, `
SELECT request_id,uuid,hostname,hostname_norm,public_key_pem,public_key_sha256,state,request_version,
       first_seen_at,last_seen_at,last_source_ip,last_dns_status,agent_version,os_version,architecture,
       resolved_machine_id,resolved_registration_id,decided_by,decided_at,decision_note,created_at
FROM dbo.agent_install_requests WITH (UPDLOCK,HOLDLOCK) WHERE uuid=@p1`, uuid).Scan(
		&requestIDValue, &uuidValue, &existing.Hostname, &existing.HostnameNorm,
		&existing.PublicKeyPEM, &existing.PublicKeySHA256, &existing.State, &existing.RequestVersion,
		&existing.FirstSeenAt, &existing.LastSeenAt, &lastIP, &dns, &agentVersion, &osVersion, &architecture,
		&resolvedMachine, &resolvedRegistration, &decidedBy, &decidedAt, &decisionNote, &existing.CreatedAt)
	if err == nil {
		existing.RequestID = uuidString(requestIDValue)
		existing.UUID = uuidString(uuidValue)
		existing.LastSourceIP = lastIP
		existing.DNSStatus = nullString(dns)
		existing.AgentVersion = nullString(agentVersion)
		existing.OSVersion = nullString(osVersion)
		existing.Architecture = nullString(architecture)
		existing.DecidedBy = nullString(decidedBy)
		existing.DecisionNote = nullString(decisionNote)
		existing.DecidedAt = nullTime(decidedAt)
		if resolvedMachine.Valid {
			existing.ResolvedMachineID = uuidString(resolvedMachine.UUID)
		}
		if resolvedRegistration.Valid {
			existing.ResolvedRegistrationID = resolvedRegistration.Int64
		}
		if existing.State != "pending" {
			return &protocol.APIError{
				Code:    protocol.CodeInstallationRejected,
				Message: "this installation request was already decided; reset the agent identity to start a new request",
				Details: map[string]any{"request_id": existing.RequestID, "state": existing.State},
			}, nil
		}
		if !strings.EqualFold(strings.TrimSpace(existing.PublicKeySHA256), fingerprint) {
			_ = insertEvent(ctx, tx, nil, nil, nil, request.Data.RequestID,
				"installation_key_conflict", "error",
				"pending installation was contacted with a different public key",
				map[string]any{"uuid": uuid, "hostname": hostname, "request_id": existing.RequestID}, now)
			return &protocol.APIError{
				Code:    protocol.CodeKeyConflict,
				Message: "this UUID already has a pending installation with a different public key",
				Details: map[string]any{"request_id": existing.RequestID, "retry_after_seconds": 300},
			}, nil
		}
		changed := existing.HostnameNorm != hostnameNorm ||
			existing.AgentVersion != boundAgentVersion(request) ||
			existing.OSVersion != truncate(request.Data.OSVersion, 128) ||
			existing.Architecture != truncate(request.Data.Architecture, 32) ||
			ipString(existing.LastSourceIP) != ipString(sourceIP) ||
			existing.DNSStatus != dnsStatus
		newVersion := existing.RequestVersion
		if changed {
			newVersion++
		}
		if _, err := tx.ExecContext(ctx, `
UPDATE dbo.agent_install_requests
SET hostname=@p1,hostname_norm=@p2,request_version=@p3,last_seen_at=@p4,last_source_ip=@p5,
    last_dns_status=@p6,agent_version=@p7,os_version=@p8,architecture=@p9,updated_at=@p4
WHERE request_id=@p10`,
			hostname, hostnameNorm, newVersion, now, sourceIP, nilIfEmpty(dnsStatus),
			truncate(boundAgentVersion(request), 128), truncate(request.Data.OSVersion, 128),
			truncate(request.Data.Architecture, 32), existing.RequestID); err != nil {
			return nil, fmt.Errorf("update request: %w", err)
		}
		if changed {
			_ = insertEvent(ctx, tx, nil, nil, nil, request.Data.RequestID,
				"installation_request_updated", "info",
				"pending installation details changed before an administrator decision",
				map[string]any{"request_id": existing.RequestID, "uuid": uuid, "hostname": hostname, "request_version": newVersion}, now)
		}
		return &protocol.APIError{
			Code:    protocol.CodeInstallationPending,
			Message: "installation is waiting for administrator confirmation",
			Details: map[string]any{
				"request_id": existing.RequestID, "request_version": newVersion,
				"hostname": hostname, "retry_after_seconds": 300,
			},
		}, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("select request: %w", err)
	}

	requestID := protocol.NewUUID()
	if _, err := tx.ExecContext(ctx, `
INSERT INTO dbo.agent_install_requests
 (request_id,uuid,hostname,hostname_norm,public_key_pem,public_key_sha256,state,request_version,
  first_seen_at,last_seen_at,last_source_ip,last_dns_status,agent_version,os_version,architecture,created_at,updated_at)
VALUES (@p1,@p2,@p3,@p4,@p5,@p6,N'pending',1,@p7,@p7,@p8,@p9,@p10,@p11,@p12,@p7,@p7)`,
		requestID, uuid, hostname, hostnameNorm, publicKeyPEM, fingerprint, now, sourceIP, nilIfEmpty(dnsStatus),
		truncate(boundAgentVersion(request), 128), truncate(request.Data.OSVersion, 128), truncate(request.Data.Architecture, 32)); err != nil {
		return nil, fmt.Errorf("insert request: %w", err)
	}
	_ = insertEvent(ctx, tx, nil, nil, nil, request.Data.RequestID,
		"installation_pending", "warning",
		"new installation uses a hostname associated with an existing machine and requires confirmation",
		map[string]any{"request_id": requestID, "uuid": uuid, "hostname": hostname, "key_fingerprint": fingerprint}, now)
	return &protocol.APIError{
		Code:    protocol.CodeInstallationPending,
		Message: "installation is waiting for administrator confirmation",
		Details: map[string]any{
			"request_id": requestID, "request_version": 1,
			"hostname": hostname, "retry_after_seconds": 300,
		},
	}, nil
}

// hostnameAssociatedMachineIDsTx returns machine cards whose current name or
// registration history matches hostnameNorm. Archived cards are included: an
// archive must not become an automatic-registration bypass.
func hostnameAssociatedMachineIDsTx(ctx context.Context, tx *sql.Tx, hostnameNorm string) ([]string, error) {
	rows, err := tx.QueryContext(ctx, `
SELECT DISTINCT m.machine_id
FROM dbo.machines m
WHERE LOWER(LTRIM(RTRIM(m.display_name)))=@p1
   OR EXISTS (SELECT 1 FROM dbo.registrations r WHERE r.machine_id=m.machine_id AND r.hostname_norm=@p1)
   OR EXISTS (SELECT 1 FROM dbo.hostnames h WHERE h.owner_machine_id=m.machine_id AND h.hostname_norm=@p1)`,
		hostnameNorm)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var ids []string
	for rows.Next() {
		var id mssql.UniqueIdentifier
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, uuidString(id))
	}
	return ids, rows.Err()
}

func (s *Store) loadInstallationRequestTx(ctx context.Context, tx *sql.Tx, requestID string) (*installationRequestRow, *protocol.APIError) {
	var row installationRequestRow
	var resolvedMachine mssql.NullUniqueIdentifier
	var resolvedRegistration sql.NullInt64
	var decidedAt sql.NullTime
	var lastIP []byte
	var requestIDValue, uuidValue mssql.UniqueIdentifier
	var dns, agentVersion, osVersion, architecture, decidedBy, decisionNote sql.NullString
	err := tx.QueryRowContext(ctx, `
SELECT request_id,uuid,hostname,hostname_norm,public_key_pem,public_key_sha256,state,request_version,
       first_seen_at,last_seen_at,last_source_ip,last_dns_status,agent_version,os_version,architecture,
       resolved_machine_id,resolved_registration_id,decided_by,decided_at,decision_note,created_at
FROM dbo.agent_install_requests WITH (UPDLOCK,HOLDLOCK) WHERE request_id=@p1`, requestID).Scan(
		&requestIDValue, &uuidValue, &row.Hostname, &row.HostnameNorm, &row.PublicKeyPEM, &row.PublicKeySHA256,
		&row.State, &row.RequestVersion, &row.FirstSeenAt, &row.LastSeenAt, &lastIP, &dns,
		&agentVersion, &osVersion, &architecture, &resolvedMachine, &resolvedRegistration,
		&decidedBy, &decidedAt, &decisionNote, &row.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, &protocol.APIError{Code: protocol.CodeNotFound, Message: "installation request not found"}
	}
	if err != nil {
		return nil, &protocol.APIError{Code: protocol.CodeDatabase, Message: "load installation request"}
	}
	row.RequestID = uuidString(requestIDValue)
	row.UUID = uuidString(uuidValue)
	row.LastSourceIP = lastIP
	row.DNSStatus = nullString(dns)
	row.AgentVersion = nullString(agentVersion)
	row.OSVersion = nullString(osVersion)
	row.Architecture = nullString(architecture)
	row.DecidedBy = nullString(decidedBy)
	row.DecisionNote = nullString(decisionNote)
	row.DecidedAt = nullTime(decidedAt)
	if resolvedMachine.Valid {
		row.ResolvedMachineID = uuidString(resolvedMachine.UUID)
	}
	if resolvedRegistration.Valid {
		row.ResolvedRegistrationID = resolvedRegistration.Int64
	}
	return &row, nil
}

func checkDecisionFreshness(row *installationRequestRow, input InstallationDecisionInput) *protocol.APIError {
	fingerprint, err := normalizeFingerprint(input.KeyFingerprint)
	if err != nil {
		return &protocol.APIError{Code: protocol.CodeInstallationStale, Message: err.Error()}
	}
	if row.RequestVersion != input.RequestVersion || !strings.EqualFold(row.PublicKeySHA256, fingerprint) {
		return &protocol.APIError{
			Code:    protocol.CodeInstallationStale,
			Message: "the installation request changed after review; reload and confirm the current data",
		}
	}
	return nil
}

func (s *Store) ListInstallations(ctx context.Context, status string) ([]PendingInstallation, error) {
	where := "state=N'pending'"
	switch strings.ToLower(strings.TrimSpace(status)) {
	case "", "pending":
	case "decided":
		where = "state IN (N'replaced',N'separated',N'rejected')"
	case "all":
		where = "1=1"
	default:
		return nil, fmt.Errorf("installation status must be pending, decided or all")
	}
	rows, err := s.DB.QueryContext(ctx, `
SELECT request_id,uuid,hostname,state,request_version,public_key_sha256,first_seen_at,last_seen_at,last_source_ip,
       COALESCE(last_dns_status,''),COALESCE(agent_version,''),COALESCE(os_version,''),COALESCE(architecture,''),
       created_at,decided_at,COALESCE(decided_by,''),COALESCE(decision_note,''),
       resolved_machine_id,resolved_registration_id
FROM dbo.agent_install_requests WHERE `+where+` ORDER BY last_seen_at DESC, request_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var items []PendingInstallation
	for rows.Next() {
		var item PendingInstallation
		var id, uuid mssql.UniqueIdentifier
		var ip []byte
		var decidedAt sql.NullTime
		var resolvedMachine mssql.NullUniqueIdentifier
		var resolvedRegistration sql.NullInt64
		if err := rows.Scan(&id, &uuid, &item.Hostname, &item.State, &item.RequestVersion, &item.KeyFingerprint,
			&item.FirstSeenAt, &item.LastSeenAt, &ip, &item.DNSStatus, &item.AgentVersion,
			&item.OSVersion, &item.Architecture, &item.CreatedAt, &decidedAt, &item.DecidedBy,
			&item.DecisionNote, &resolvedMachine, &resolvedRegistration); err != nil {
			return nil, err
		}
		item.RequestID = uuidString(id)
		item.UUID = uuidString(uuid)
		item.SourceIP = ipString(ip)
		item.DecidedAt = nullTime(decidedAt)
		if resolvedMachine.Valid {
			item.ResolvedMachineID = uuidString(resolvedMachine.UUID)
		}
		if resolvedRegistration.Valid {
			item.ResolvedRegistration = resolvedRegistration.Int64
		}
		item.Candidates = []InstallationCandidate{}
		if item.State == "pending" {
			candidates, err := s.installationCandidates(ctx, item.Hostname)
			if err != nil {
				return nil, err
			}
			item.Candidates = candidates
			registeredMachine, registeredName, err := s.registrationOwnerForUUID(ctx, item.UUID)
			if err != nil {
				return nil, err
			}
			item.RegisteredMachineID = registeredMachine
			item.RegisteredMachineName = registeredName
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func (s *Store) registrationOwnerForUUID(ctx context.Context, uuid string) (string, string, error) {
	var machineID mssql.UniqueIdentifier
	var displayName string
	err := s.DB.QueryRowContext(ctx, `
SELECT r.machine_id,m.display_name FROM dbo.registrations r
JOIN dbo.machines m ON m.machine_id=r.machine_id
WHERE r.uuid=@p1 AND r.state=N'active'`, uuid).Scan(&machineID, &displayName)
	if errors.Is(err, sql.ErrNoRows) {
		return "", "", nil
	}
	if err != nil {
		return "", "", err
	}
	return uuidString(machineID), displayName, nil
}

func (s *Store) installationCandidates(ctx context.Context, hostname string) ([]InstallationCandidate, error) {
	hostnameNorm := strings.ToLower(hostname)
	rows, err := s.DB.QueryContext(ctx, `
SELECT m.machine_id,m.display_name,m.archived_at,COALESCE(m.archive_reason,'')
FROM dbo.machines m
WHERE LOWER(LTRIM(RTRIM(m.display_name)))=@p1
   OR EXISTS (SELECT 1 FROM dbo.registrations r WHERE r.machine_id=m.machine_id AND r.hostname_norm=@p1)
   OR EXISTS (SELECT 1 FROM dbo.hostnames h WHERE h.owner_machine_id=m.machine_id AND h.hostname_norm=@p1)
ORDER BY CASE WHEN m.archived_at IS NULL THEN 0 ELSE 1 END, m.display_name, m.machine_id`, hostnameNorm)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []InstallationCandidate
	for rows.Next() {
		var candidate InstallationCandidate
		var machineID mssql.UniqueIdentifier
		var archived sql.NullTime
		if err := rows.Scan(&machineID, &candidate.DisplayName, &archived, &candidate.ArchiveReason); err != nil {
			return nil, err
		}
		candidate.MachineID = uuidString(machineID)
		candidate.Archived = archived.Valid
		candidate.NameMatch = true
		active, err := s.installationRegistration(ctx, candidate.MachineID, true)
		if err != nil {
			return nil, err
		}
		last, err := s.installationRegistration(ctx, candidate.MachineID, false)
		if err != nil {
			return nil, err
		}
		candidate.ActiveRegistration = active
		candidate.LastRegistration = last
		if active != nil {
			candidate.LastSeenAt = active.LastSeenAt
		} else if last != nil {
			candidate.LastSeenAt = last.LastSeenAt
		}
		if candidate.LastSeenAt != nil {
			now := s.now()
			candidate.Online = !machineOffline(candidate.LastSeenAt, now)
			candidate.RecentActivity = now.Sub(*candidate.LastSeenAt) <= 20*time.Minute
		}
		out = append(out, candidate)
	}
	if out == nil {
		out = []InstallationCandidate{}
	}
	return out, rows.Err()
}

func (s *Store) installationRegistration(ctx context.Context, machineID string, activeOnly bool) (*InstallationRegistrationInfo, error) {
	query := `
SELECT TOP 1 registration_id,uuid,hostname,state,public_key_sha256,created_at,last_seen_at,last_source_ip,last_dns_status
FROM dbo.registrations WHERE machine_id=@p1`
	if activeOnly {
		query += ` AND state=N'active'`
	} else {
		query += ` ORDER BY created_at DESC, registration_id DESC`
	}
	var item InstallationRegistrationInfo
	var uuid mssql.UniqueIdentifier
	var key string
	var created time.Time
	var lastSeen sql.NullTime
	var ip []byte
	var dns sql.NullString
	err := s.DB.QueryRowContext(ctx, query, machineID).Scan(&item.RegistrationID, &uuid, &item.Hostname,
		&item.State, &key, &created, &lastSeen, &ip, &dns)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	item.UUID = uuidString(uuid)
	item.KeyFingerprint = strings.TrimSpace(key)
	item.CreatedAt = created.UTC()
	item.LastSeenAt = nullTime(lastSeen)
	item.SourceIP = ipString(ip)
	item.DNSStatus = nullString(dns)
	return &item, nil
}

// PendingInstallationsForMachine returns pending requests that could replace
// the given card. The UI uses this to place the replacement action in the
// machine card without hiding the global queue.
func (s *Store) PendingInstallationsForMachine(ctx context.Context, machineID string) ([]PendingInstallation, error) {
	normalized, err := protocol.NormalizeUUID(machineID)
	if err != nil {
		return nil, err
	}
	items, err := s.ListInstallations(ctx, "pending")
	if err != nil {
		return nil, err
	}
	// A card action can link a pending installation manually even when the
	// signed hostname differs (for example, Windows reinstalled with a new
	// name). Append the target card to every pending request with NameMatch
	// false so the review screen still shows the exact machine_id, old
	// registration and connection state before confirmation.
	target, err := s.installationCandidateByMachine(ctx, normalized, false)
	if err != nil {
		return nil, err
	}
	if target != nil {
		for i := range items {
			found := false
			for j := range items[i].Candidates {
				if strings.EqualFold(items[i].Candidates[j].MachineID, normalized) {
					items[i].Candidates[j].NameMatch = true
					found = true
					break
				}
			}
			if !found {
				items[i].Candidates = append(items[i].Candidates, *target)
			}
		}
	}
	return items, nil
}

func (s *Store) installationCandidateByMachine(ctx context.Context, machineID string, nameMatch bool) (*InstallationCandidate, error) {
	var candidate InstallationCandidate
	var id mssql.UniqueIdentifier
	var archived sql.NullTime
	if err := s.DB.QueryRowContext(ctx, `
SELECT machine_id,display_name,archived_at,COALESCE(archive_reason,'') FROM dbo.machines WHERE machine_id=@p1`, machineID).
		Scan(&id, &candidate.DisplayName, &archived, &candidate.ArchiveReason); errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	} else if err != nil {
		return nil, err
	}
	candidate.MachineID = uuidString(id)
	candidate.Archived = archived.Valid
	candidate.NameMatch = nameMatch
	active, err := s.installationRegistration(ctx, candidate.MachineID, true)
	if err != nil {
		return nil, err
	}
	last, err := s.installationRegistration(ctx, candidate.MachineID, false)
	if err != nil {
		return nil, err
	}
	candidate.ActiveRegistration = active
	candidate.LastRegistration = last
	if active != nil {
		candidate.LastSeenAt = active.LastSeenAt
	} else if last != nil {
		candidate.LastSeenAt = last.LastSeenAt
	}
	if candidate.LastSeenAt != nil {
		now := s.now()
		candidate.Online = !machineOffline(candidate.LastSeenAt, now)
		candidate.RecentActivity = now.Sub(*candidate.LastSeenAt) <= 20*time.Minute
	}
	return &candidate, nil
}

func activeRegistrationForMachineTx(ctx context.Context, tx *sql.Tx, machineID string) (*installOldRegistration, error) {
	var row installOldRegistration
	var hostnameNorm string
	var lastSeen sql.NullTime
	err := tx.QueryRowContext(ctx, `
SELECT registration_id,machine_id,uuid,hostname,hostname_norm,public_key_pem,public_key_sha256,created_at,
       last_seen_at,scan_epoch
FROM dbo.registrations WITH (UPDLOCK,HOLDLOCK)
WHERE machine_id=@p1 AND state=N'active'`, machineID).Scan(&row.RegistrationID, &row.MachineID, &row.UUID,
		&row.Hostname, &hostnameNorm, &row.PublicKeyPEM, &row.PublicKeySHA256, &row.CreatedAt, &lastSeen, &row.ScanEpoch)
	row.HostnameNorm = hostnameNorm
	row.LastSeenAt = nullTime(lastSeen)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &row, nil
}

type installOldRegistration struct {
	RegistrationID  int64
	MachineID       mssql.UniqueIdentifier
	UUID            mssql.UniqueIdentifier
	Hostname        string
	HostnameNorm    string
	PublicKeyPEM    string
	PublicKeySHA256 string
	CreatedAt       time.Time
	LastSeenAt      *time.Time
	ScanEpoch       int
}

func (s *Store) duplicateReplacement(ctx context.Context, request *installationRequestRow, machineID string, now time.Time) (*InstallationDecisionResult, bool, error) {
	var registrationID int64
	var state string
	var previous sql.NullInt64
	err := s.DB.QueryRowContext(ctx, `
SELECT registration_id,state,previous_registration_id FROM dbo.registrations WHERE uuid=@p1 AND machine_id=@p2`, request.UUID, machineID).
		Scan(&registrationID, &state, &previous)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	if state != "active" || registrationID != request.ResolvedRegistrationID {
		return nil, false, nil
	}
	oldSeen := false
	if previous.Valid {
		var lastSeen sql.NullTime
		_ = s.DB.QueryRowContext(ctx, `SELECT last_seen_at FROM dbo.registrations WHERE registration_id=@p1`, previous.Int64).Scan(&lastSeen)
		if lastSeen.Valid && now.Sub(lastSeen.Time.UTC()) <= 20*time.Minute {
			oldSeen = true
		}
	}
	return &InstallationDecisionResult{
		RequestID: request.RequestID, MachineID: machineID, RegistrationID: registrationID,
		UUID: request.UUID, Hostname: request.Hostname, State: "replaced",
		KeyFingerprint: request.PublicKeySHA256, Duplicate: true, OldSeenRecently: oldSeen,
	}, true, nil
}

// ReplaceInstallation atomically retires the current installation of one
// machine card and activates the pending installation under the same
// machine_id. History, users, reports, groups and policies stay on the card;
// unfinished tasks and encryption keys of the old installation do not move.
func (s *Store) ReplaceInstallation(ctx context.Context, input InstallationDecisionInput, admin string) (*InstallationDecisionResult, *protocol.APIError) {
	requestID, err := protocol.NormalizeUUID(input.RequestID)
	if err != nil {
		return nil, &protocol.APIError{Code: protocol.CodeNotFound, Message: "invalid installation request id"}
	}
	machineID, err := protocol.NormalizeUUID(input.MachineID)
	if err != nil {
		return nil, &protocol.APIError{Code: protocol.CodeInstallationConflict, Message: "invalid target machine"}
	}
	if input.OldRegistrationID < 0 {
		return nil, &protocol.APIError{Code: protocol.CodeInstallationStale, Message: "invalid expected registration"}
	}
	fingerprint, err := normalizeFingerprint(input.KeyFingerprint)
	if err != nil {
		return nil, &protocol.APIError{Code: protocol.CodeInstallationStale, Message: err.Error()}
	}
	note := truncate(strings.TrimSpace(input.Reason), 1024)
	now := s.now()

	tx, err := s.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return nil, &protocol.APIError{Code: protocol.CodeDatabase, Message: "begin installation replacement"}
	}
	defer tx.Rollback()

	request, apiErr := s.loadInstallationRequestTx(ctx, tx, requestID)
	if apiErr != nil {
		return nil, apiErr
	}
	if request.State == "replaced" && strings.EqualFold(request.ResolvedMachineID, machineID) && request.ResolvedRegistrationID > 0 && strings.EqualFold(request.PublicKeySHA256, fingerprint) {
		if duplicate, ok, err := s.duplicateReplacement(ctx, request, machineID, now); err != nil {
			return nil, &protocol.APIError{Code: protocol.CodeDatabase, Message: "verify previous replacement"}
		} else if ok {
			return duplicate, nil
		}
	}
	if request.State != "pending" {
		return nil, &protocol.APIError{Code: protocol.CodeInstallationConflict, Message: "installation request is already decided"}
	}
	if apiErr := checkDecisionFreshness(request, input); apiErr != nil {
		return nil, apiErr
	}

	var displayName string
	var archived sql.NullTime
	if err := tx.QueryRowContext(ctx, `SELECT display_name,archived_at FROM dbo.machines WITH (UPDLOCK,HOLDLOCK) WHERE machine_id=@p1`, machineID).Scan(&displayName, &archived); errors.Is(err, sql.ErrNoRows) {
		return nil, &protocol.APIError{Code: protocol.CodeNotFound, Message: "target machine not found"}
	} else if err != nil {
		return nil, &protocol.APIError{Code: protocol.CodeDatabase, Message: "load target machine"}
	}
	if archived.Valid {
		return nil, &protocol.APIError{Code: protocol.CodeInstallationConflict, Message: "archived machine cards cannot be replacement targets; restore the card or create a separate machine"}
	}

	old, err := activeRegistrationForMachineTx(ctx, tx, machineID)
	if err != nil {
		return nil, &protocol.APIError{Code: protocol.CodeDatabase, Message: "load old registration"}
	}
	if old != nil {
		if input.OldRegistrationID != old.RegistrationID {
			return nil, &protocol.APIError{Code: protocol.CodeInstallationStale, Message: "the active registration changed after review"}
		}
	} else if input.OldRegistrationID != 0 {
		return nil, &protocol.APIError{Code: protocol.CodeInstallationStale, Message: "the machine has no active registration"}
	}

	var existingMachine mssql.UniqueIdentifier
	var existingRegistration int64
	var existingState string
	err = tx.QueryRowContext(ctx, `SELECT machine_id,registration_id,state FROM dbo.registrations WITH (UPDLOCK,HOLDLOCK) WHERE uuid=@p1`, request.UUID).
		Scan(&existingMachine, &existingRegistration, &existingState)
	if err == nil {
		return nil, &protocol.APIError{
			Code:    protocol.CodeInstallationConflict,
			Message: "this UUID is already registered; partial history merge is not supported",
			Details: map[string]any{"machine_id": uuidString(existingMachine), "registration_id": existingRegistration, "state": existingState},
		}
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return nil, &protocol.APIError{Code: protocol.CodeDatabase, Message: "check installation UUID"}
	}

	previousID := int64(0)
	if old != nil {
		previousID = old.RegistrationID
	} else {
		var lastID sql.NullInt64
		_ = tx.QueryRowContext(ctx, `SELECT TOP 1 registration_id FROM dbo.registrations WHERE machine_id=@p1 ORDER BY created_at DESC,registration_id DESC`, machineID).Scan(&lastID)
		if lastID.Valid {
			previousID = lastID.Int64
		}
	}
	var maxEpoch int
	if err := tx.QueryRowContext(ctx, `SELECT COALESCE(MAX(scan_epoch),0) FROM dbo.registrations WHERE machine_id=@p1`, machineID).Scan(&maxEpoch); err != nil {
		return nil, &protocol.APIError{Code: protocol.CodeDatabase, Message: "load scan epoch"}
	}
	newEpoch := maxEpoch + 1

	if old != nil {
		result, err := tx.ExecContext(ctx, `
UPDATE dbo.registrations SET state=N'replaced',revoked_at=@p1
WHERE registration_id=@p2 AND state=N'active'`, now, old.RegistrationID)
		if err != nil {
			return nil, &protocol.APIError{Code: protocol.CodeDatabase, Message: "retire old registration"}
		}
		if affected, _ := result.RowsAffected(); affected != 1 {
			return nil, &protocol.APIError{Code: protocol.CodeInstallationStale, Message: "old registration is no longer active"}
		}
	}

	var newRegistrationID int64
	if err := tx.QueryRowContext(ctx, `
INSERT INTO dbo.registrations
 (machine_id,uuid,hostname,hostname_norm,public_key_pem,public_key_sha256,state,agent_version,os_version,architecture,
  previous_registration_id,scan_epoch,created_at,last_seen_at,last_source_ip,last_dns_status,last_dns_checked_at)
OUTPUT INSERTED.registration_id
VALUES (@p1,@p2,@p3,@p4,@p5,@p6,N'active',@p7,@p8,@p9,@p10,@p11,@p12,@p12,@p13,@p14,@p12)`,
		machineID, request.UUID, request.Hostname, request.HostnameNorm, request.PublicKeyPEM, request.PublicKeySHA256,
		truncate(request.AgentVersion, 128), truncate(request.OSVersion, 128), truncate(request.Architecture, 32),
		nilIfZero(previousID), newEpoch, now, request.LastSourceIP, nilIfEmpty(request.DNSStatus)).Scan(&newRegistrationID); err != nil {
		if isDuplicateKey(err) {
			return nil, &protocol.APIError{Code: protocol.CodeInstallationConflict, Message: "UUID or active registration was created concurrently"}
		}
		return nil, &protocol.APIError{Code: protocol.CodeDatabase, Message: "create replacement registration"}
	}
	if old != nil {
		if _, err := tx.ExecContext(ctx, `UPDATE dbo.registrations SET replaced_by_registration_id=@p1 WHERE registration_id=@p2`, newRegistrationID, old.RegistrationID); err != nil {
			return nil, &protocol.APIError{Code: protocol.CodeDatabase, Message: "link replacement registration"}
		}
	}

	// Replacement is a new installation, not a signed rename. Old task keys,
	// capabilities and unfinished jobs must not follow it.
	if _, err := tx.ExecContext(ctx, `
UPDATE dbo.agent_encryption_keys SET active=0,revoked_at=@p1
WHERE machine_id=@p2 AND active=1 AND revoked_at IS NULL`, now, machineID); err != nil {
		return nil, &protocol.APIError{Code: protocol.CodeDatabase, Message: "retire old encryption keys"}
	}
	if apiErr := s.retireTasksForInstallationTx(ctx, tx, machineID, newRegistrationID, now); apiErr != nil {
		return nil, apiErr
	}

	if old != nil {
		if err := releaseHostnameTx(ctx, tx, old.HostnameNorm, old.RegistrationID); err != nil {
			return nil, &protocol.APIError{Code: protocol.CodeDatabase, Message: "release old hostname"}
		}
	}
	hostnameConflict, _, err := claimHostnameTx(ctx, tx, request.HostnameNorm, request.Hostname, newRegistrationID, machineID, now, false)
	if err != nil {
		return nil, &protocol.APIError{Code: protocol.CodeDatabase, Message: "reserve replacement hostname"}
	}
	if _, err := tx.ExecContext(ctx, `
UPDATE dbo.machines SET display_name=CASE WHEN display_name_custom=0 THEN @p1 ELSE display_name END,updated_at=@p2
WHERE machine_id=@p3`, request.Hostname, now, machineID); err != nil {
		return nil, &protocol.APIError{Code: protocol.CodeDatabase, Message: "update machine name"}
	}
	if _, err := tx.ExecContext(ctx, `
UPDATE dbo.source_states SET last_scan_epoch=@p1,last_scan_seq=0,updated_at=@p2 WHERE machine_id=@p3`, newEpoch, now, machineID); err != nil {
		return nil, &protocol.APIError{Code: protocol.CodeDatabase, Message: "reset source ordering"}
	}
	if _, err := tx.ExecContext(ctx, `
UPDATE dbo.csp_states SET last_scan_epoch=@p1,last_scan_seq=0,updated_at=@p2 WHERE machine_id=@p3`, newEpoch, now, machineID); err != nil {
		return nil, &protocol.APIError{Code: protocol.CodeDatabase, Message: "reset CSP ordering"}
	}

	result, err := tx.ExecContext(ctx, `
UPDATE dbo.agent_install_requests
SET state=N'replaced',resolved_machine_id=@p1,resolved_registration_id=@p2,decided_by=@p3,decided_at=@p4,
    decision_note=@p5,request_version=request_version+1,updated_at=@p4
WHERE request_id=@p6 AND state=N'pending' AND request_version=@p7`,
		machineID, newRegistrationID, admin, now, nilIfEmpty(note), request.RequestID, input.RequestVersion)
	if err != nil {
		return nil, &protocol.APIError{Code: protocol.CodeDatabase, Message: "record installation decision"}
	}
	if affected, _ := result.RowsAffected(); affected != 1 {
		return nil, &protocol.APIError{Code: protocol.CodeInstallationStale, Message: "installation request changed during confirmation"}
	}

	oldSeenRecently := false
	var oldRegistrationID any
	if old != nil {
		oldRegistrationID = old.RegistrationID
		if old.LastSeenAt != nil && now.Sub(*old.LastSeenAt) <= 20*time.Minute {
			oldSeenRecently = true
		}
	}
	oldUUID := ""
	if old != nil {
		oldUUID = uuidString(old.UUID)
	}
	details := map[string]any{
		"admin": admin, "installation_request_id": request.RequestID, "old_uuid": oldUUID,
		"new_uuid": request.UUID, "old_registration_id": oldRegistrationID, "new_registration_id": newRegistrationID,
		"hostname": request.Hostname, "key_fingerprint": request.PublicKeySHA256,
		"old_seen_recently": oldSeenRecently, "hostname_conflict": hostnameConflict,
	}
	if err := insertEvent(ctx, tx, machineID, &newRegistrationID, nil, nil,
		"installation_replaced", "warning", "administrator replaced the agent installation", details, now); err != nil {
		return nil, &protocol.APIError{Code: protocol.CodeDatabase, Message: "record installation replacement event"}
	}
	if err := tx.Commit(); err != nil {
		return nil, &protocol.APIError{Code: protocol.CodeDatabase, Message: "commit installation replacement"}
	}
	return &InstallationDecisionResult{
		RequestID: request.RequestID, MachineID: machineID, RegistrationID: newRegistrationID,
		UUID: request.UUID, Hostname: request.Hostname, State: "replaced",
		KeyFingerprint: request.PublicKeySHA256, OldSeenRecently: oldSeenRecently, HostnameConflict: hostnameConflict,
	}, nil
}

func nilIfZero(value int64) any {
	if value == 0 {
		return nil
	}
	return value
}

// RegisterSeparateInstallation creates a distinct machine card after an
// explicit administrator decision. It never moves reports or history from a
// machine with the same hostname.
func (s *Store) RegisterSeparateInstallation(ctx context.Context, input InstallationDecisionInput, admin string) (*InstallationDecisionResult, *protocol.APIError) {
	requestID, err := protocol.NormalizeUUID(input.RequestID)
	if err != nil {
		return nil, &protocol.APIError{Code: protocol.CodeNotFound, Message: "invalid installation request id"}
	}
	if _, err := normalizeFingerprint(input.KeyFingerprint); err != nil {
		return nil, &protocol.APIError{Code: protocol.CodeInstallationStale, Message: err.Error()}
	}
	now := s.now()
	tx, err := s.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return nil, &protocol.APIError{Code: protocol.CodeDatabase, Message: "begin separate registration"}
	}
	defer tx.Rollback()
	request, apiErr := s.loadInstallationRequestTx(ctx, tx, requestID)
	if apiErr != nil {
		return nil, apiErr
	}
	if request.State == "separated" && request.ResolvedRegistrationID > 0 {
		var state string
		err := tx.QueryRowContext(ctx, `SELECT state FROM dbo.registrations WHERE registration_id=@p1`, request.ResolvedRegistrationID).Scan(&state)
		if err == nil && state == "active" {
			return &InstallationDecisionResult{
				RequestID: request.RequestID, MachineID: request.ResolvedMachineID, RegistrationID: request.ResolvedRegistrationID,
				UUID: request.UUID, Hostname: request.Hostname, State: "separated",
				KeyFingerprint: request.PublicKeySHA256, Duplicate: true,
			}, nil
		}
	}
	if request.State != "pending" {
		return nil, &protocol.APIError{Code: protocol.CodeInstallationConflict, Message: "installation request is already decided"}
	}
	if !input.ConfirmNameConflict {
		return nil, &protocol.APIError{Code: protocol.CodeInstallationConflict, Message: "explicit confirmation of the hostname collision is required"}
	}
	if apiErr := checkDecisionFreshness(request, input); apiErr != nil {
		return nil, apiErr
	}
	var existingMachine mssql.UniqueIdentifier
	var existingRegistration int64
	var existingState string
	err = tx.QueryRowContext(ctx, `SELECT machine_id,registration_id,state FROM dbo.registrations WITH (UPDLOCK,HOLDLOCK) WHERE uuid=@p1`, request.UUID).
		Scan(&existingMachine, &existingRegistration, &existingState)
	if err == nil {
		return nil, &protocol.APIError{
			Code:    protocol.CodeInstallationConflict,
			Message: "this UUID is already registered; partial history merge is not supported",
			Details: map[string]any{"machine_id": uuidString(existingMachine), "registration_id": existingRegistration, "state": existingState},
		}
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return nil, &protocol.APIError{Code: protocol.CodeDatabase, Message: "check installation UUID"}
	}
	machineID := protocol.NewUUID()
	if _, err := tx.ExecContext(ctx, `
INSERT INTO dbo.machines(machine_id,display_name,created_at,updated_at) VALUES(@p1,@p2,@p3,@p3)`, machineID, request.Hostname, now); err != nil {
		return nil, &protocol.APIError{Code: protocol.CodeDatabase, Message: "create separate machine"}
	}
	var registrationID int64
	if err := tx.QueryRowContext(ctx, `
INSERT INTO dbo.registrations
 (machine_id,uuid,hostname,hostname_norm,public_key_pem,public_key_sha256,state,agent_version,os_version,architecture,
  scan_epoch,created_at,last_seen_at,last_source_ip,last_dns_status,last_dns_checked_at)
OUTPUT INSERTED.registration_id
VALUES (@p1,@p2,@p3,@p4,@p5,@p6,N'active',@p7,@p8,@p9,0,@p10,@p10,@p11,@p12,@p10)`,
		machineID, request.UUID, request.Hostname, request.HostnameNorm, request.PublicKeyPEM,
		request.PublicKeySHA256, truncate(request.AgentVersion, 128), truncate(request.OSVersion, 128),
		truncate(request.Architecture, 32), now, request.LastSourceIP, nilIfEmpty(request.DNSStatus)).Scan(&registrationID); err != nil {
		if isDuplicateKey(err) {
			return nil, &protocol.APIError{Code: protocol.CodeInstallationConflict, Message: "UUID or active registration was created concurrently"}
		}
		return nil, &protocol.APIError{Code: protocol.CodeDatabase, Message: "create separate registration"}
	}
	hostnameConflict, _, err := claimHostnameTx(ctx, tx, request.HostnameNorm, request.Hostname, registrationID, machineID, now, false)
	if err != nil {
		return nil, &protocol.APIError{Code: protocol.CodeDatabase, Message: "reserve separate hostname"}
	}
	result, err := tx.ExecContext(ctx, `
UPDATE dbo.agent_install_requests
SET state=N'separated',resolved_machine_id=@p1,resolved_registration_id=@p2,decided_by=@p3,decided_at=@p4,
    decision_note=@p5,request_version=request_version+1,updated_at=@p4
WHERE request_id=@p6 AND state=N'pending' AND request_version=@p7`,
		machineID, registrationID, admin, now, nilIfEmpty(truncate(strings.TrimSpace(input.Reason), 1024)), request.RequestID, input.RequestVersion)
	if err != nil {
		return nil, &protocol.APIError{Code: protocol.CodeDatabase, Message: "record separate registration decision"}
	}
	if affected, _ := result.RowsAffected(); affected != 1 {
		return nil, &protocol.APIError{Code: protocol.CodeInstallationStale, Message: "installation request changed during confirmation"}
	}
	_ = insertEvent(ctx, tx, machineID, &registrationID, nil, nil,
		"installation_registered_separately", "warning",
		"administrator allowed a new machine with an existing hostname",
		map[string]any{"admin": admin, "installation_request_id": request.RequestID, "uuid": request.UUID,
			"hostname": request.Hostname, "key_fingerprint": request.PublicKeySHA256, "hostname_conflict": hostnameConflict}, now)
	if err := tx.Commit(); err != nil {
		return nil, &protocol.APIError{Code: protocol.CodeDatabase, Message: "commit separate registration"}
	}
	return &InstallationDecisionResult{
		RequestID: request.RequestID, MachineID: machineID, RegistrationID: registrationID,
		UUID: request.UUID, Hostname: request.Hostname, State: "separated",
		KeyFingerprint: request.PublicKeySHA256, HostnameConflict: hostnameConflict,
	}, nil
}

func (s *Store) RejectInstallation(ctx context.Context, input InstallationDecisionInput, admin string) (*InstallationDecisionResult, *protocol.APIError) {
	requestID, err := protocol.NormalizeUUID(input.RequestID)
	if err != nil {
		return nil, &protocol.APIError{Code: protocol.CodeNotFound, Message: "invalid installation request id"}
	}
	fingerprint, err := normalizeFingerprint(input.KeyFingerprint)
	if err != nil {
		return nil, &protocol.APIError{Code: protocol.CodeInstallationStale, Message: err.Error()}
	}
	now := s.now()
	tx, err := s.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return nil, &protocol.APIError{Code: protocol.CodeDatabase, Message: "begin installation rejection"}
	}
	defer tx.Rollback()
	request, apiErr := s.loadInstallationRequestTx(ctx, tx, requestID)
	if apiErr != nil {
		return nil, apiErr
	}
	if request.State == "rejected" && strings.EqualFold(request.PublicKeySHA256, fingerprint) {
		return &InstallationDecisionResult{
			RequestID: request.RequestID, UUID: request.UUID, Hostname: request.Hostname,
			State: "rejected", KeyFingerprint: request.PublicKeySHA256, Duplicate: true,
		}, nil
	}
	if request.State != "pending" {
		return nil, &protocol.APIError{Code: protocol.CodeInstallationConflict, Message: "installation request is already decided"}
	}
	if apiErr := checkDecisionFreshness(request, input); apiErr != nil {
		return nil, apiErr
	}
	result, err := tx.ExecContext(ctx, `
UPDATE dbo.agent_install_requests
SET state=N'rejected',decided_by=@p1,decided_at=@p2,decision_note=@p3,request_version=request_version+1,updated_at=@p2
WHERE request_id=@p4 AND state=N'pending' AND request_version=@p5`,
		admin, now, nilIfEmpty(truncate(strings.TrimSpace(input.Reason), 1024)), request.RequestID, input.RequestVersion)
	if err != nil {
		return nil, &protocol.APIError{Code: protocol.CodeDatabase, Message: "record installation rejection"}
	}
	if affected, _ := result.RowsAffected(); affected != 1 {
		return nil, &protocol.APIError{Code: protocol.CodeInstallationStale, Message: "installation request changed during confirmation"}
	}
	_ = insertEvent(ctx, tx, nil, nil, nil, nil,
		"installation_rejected", "warning", "administrator rejected an installation request",
		map[string]any{"admin": admin, "installation_request_id": request.RequestID, "uuid": request.UUID,
			"hostname": request.Hostname, "key_fingerprint": request.PublicKeySHA256, "reason": truncate(strings.TrimSpace(input.Reason), 1024)}, now)
	if err := tx.Commit(); err != nil {
		return nil, &protocol.APIError{Code: protocol.CodeDatabase, Message: "commit installation rejection"}
	}
	return &InstallationDecisionResult{
		RequestID: request.RequestID, UUID: request.UUID, Hostname: request.Hostname,
		State: "rejected", KeyFingerprint: request.PublicKeySHA256,
	}, nil
}

// ArchiveMachine hides a historical card from the active list without
// deleting any history. Only a card with no active registration may be
// archived.
func (s *Store) ArchiveMachine(ctx context.Context, machineID, reason, admin string) error {
	id, err := protocol.NormalizeUUID(machineID)
	if err != nil {
		return fmt.Errorf("invalid machine identifier")
	}
	reason = truncate(strings.TrimSpace(reason), 1024)
	if reason == "" {
		return fmt.Errorf("archive reason is required")
	}
	now := s.now()
	tx, err := s.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var displayName string
	var archived sql.NullTime
	if err := tx.QueryRowContext(ctx, `SELECT display_name,archived_at FROM dbo.machines WITH (UPDLOCK,HOLDLOCK) WHERE machine_id=@p1`, id).Scan(&displayName, &archived); errors.Is(err, sql.ErrNoRows) {
		return sql.ErrNoRows
	} else if err != nil {
		return err
	}
	if archived.Valid {
		return nil
	}
	var active int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(1) FROM dbo.registrations WITH (UPDLOCK,HOLDLOCK) WHERE machine_id=@p1 AND state=N'active'`, id).Scan(&active); err != nil {
		return err
	}
	if active != 0 {
		return fmt.Errorf("machine still has an active registration; revoke or replace it first")
	}
	if _, err := tx.ExecContext(ctx, `
UPDATE dbo.machines SET archived_at=@p1,archived_by=@p2,archive_reason=@p3,updated_at=@p1 WHERE machine_id=@p4`,
		now, admin, reason, id); err != nil {
		return err
	}
	if err := insertEvent(ctx, tx, id, nil, nil, nil, "machine_archived", "warning",
		"administrator archived a historical machine card",
		map[string]any{"admin": admin, "reason": reason, "display_name": displayName}, now); err != nil {
		return err
	}
	return tx.Commit()
}

// retireTasksForInstallationTx applies the replacement task policy:
//   - not-started tasks are expired and their licenses released;
//   - started install_license tasks become outcome_unknown and keep the
//     license reserved for read-only reconciliation;
//   - started scan tasks become failed, never succeeded or silently retried.
func (s *Store) retireTasksForInstallationTx(ctx context.Context, tx *sql.Tx, machineID string, newRegistrationID int64, now time.Time) *protocol.APIError {
	rows, err := tx.QueryContext(ctx, `
SELECT item_id FROM dbo.task_items WITH (UPDLOCK,HOLDLOCK)
WHERE machine_id=@p1 AND registration_id<>@p2 AND completed_at IS NULL`, machineID, newRegistrationID)
	if err != nil {
		return &protocol.APIError{Code: protocol.CodeDatabase, Message: "list old installation tasks"}
	}
	var ids []string
	for rows.Next() {
		var id mssql.UniqueIdentifier
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return &protocol.APIError{Code: protocol.CodeDatabase, Message: "decode old installation task"}
		}
		ids = append(ids, uuidString(id))
	}
	rows.Close()
	for _, id := range ids {
		row, apiErr := s.loadAgentTaskRowTx(ctx, tx, id, true)
		if apiErr != nil {
			return apiErr
		}
		if protocol.IsTerminalTaskState(row.State) {
			continue
		}
		started := row.StartedAt != nil || row.State == protocol.TaskStateRunning
		nextState := protocol.TaskStateExpired
		reason := "registration_replaced"
		if row.Kind == protocol.TaskKindInstallLicense && (started || row.State == protocol.TaskStateOutcomeUnknown) {
			nextState = protocol.TaskStateOutcomeUnknown
			if apiErr := s.markLicenseUnknownTx(ctx, tx, row, reason, now); apiErr != nil {
				return apiErr
			}
		} else if row.Kind == protocol.TaskKindInstallLicense {
			if apiErr := s.releaseLicenseTx(ctx, tx, row, "replaced_before_start", now); apiErr != nil {
				return apiErr
			}
		} else if started {
			nextState = protocol.TaskStateFailed
		}
		if _, err := tx.ExecContext(ctx, `
UPDATE dbo.task_items
SET state=@p1,reason_code=@p2,completed_at=@p3,updated_at=@p3,
    encrypted_parameters=NULL,encryption_key_id=NULL,delivery_version=delivery_version+1
WHERE item_id=@p4 AND completed_at IS NULL`, nextState, reason, now, row.ItemID); err != nil {
			return &protocol.APIError{Code: protocol.CodeDatabase, Message: "retire old installation task"}
		}
		jobState := "canceled"
		if nextState == protocol.TaskStateOutcomeUnknown || nextState == protocol.TaskStateFailed {
			jobState = "failed"
		}
		_, _ = s.updateLegacyJobTxWithState(ctx, tx, row, jobState, now)
		if sequence, err := s.nextSequenceTx(ctx, tx, row.ItemID); err == nil {
			_ = insertTaskEventTx(ctx, tx, row.ItemID, sequence, row.AttemptCount, "registration_replaced",
				map[string]any{"previous_state": row.State, "state": nextState, "reason_code": reason}, now)
		}
	}
	// Close any legacy job that is not linked to a task item; otherwise it
	// would remain deliverable by machine forever. Linked terminal items are
	// reconciled to their actual terminal outcome, never blindly canceled.
	if _, err := tx.ExecContext(ctx, `
UPDATE dbo.jobs SET state=N'canceled',completed_at=@p1,acknowledged_at=@p1,message=N'registration_replaced'
WHERE machine_id=@p2 AND state IN (N'pending',N'delivered') AND task_item_id IS NULL`, now, machineID); err != nil {
		return &protocol.APIError{Code: protocol.CodeDatabase, Message: "close unlinked legacy jobs"}
	}
	if _, err := tx.ExecContext(ctx, `
UPDATE j SET state=CASE
		WHEN ti.state IN (N'succeeded',N'skipped') THEN N'completed'
		WHEN ti.state IN (N'failed',N'outcome_unknown') THEN N'failed'
		ELSE N'canceled' END,
	completed_at=@p1,acknowledged_at=@p1,message=N'registration_replaced'
FROM dbo.jobs j JOIN dbo.task_items ti ON ti.item_id=j.task_item_id
WHERE j.machine_id=@p2 AND j.state IN (N'pending',N'delivered')
  AND ti.state IN (N'succeeded',N'skipped',N'failed',N'outcome_unknown',N'cancelled',N'expired')`, now, machineID); err != nil {
		return &protocol.APIError{Code: protocol.CodeDatabase, Message: "reconcile legacy jobs"}
	}
	return nil
}
