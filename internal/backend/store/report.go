package store

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	mssql "github.com/microsoft/go-mssqldb"
	"telehack2026/internal/certparse"
	"telehack2026/internal/protocol"
)

// SubmitReport applies one idempotent report. The request_id and all business
// changes are committed together. A delayed report is accepted but applies
// only sources whose scan_seq is newer than the last applied sequence for that
// source.
func (s *Store) SubmitReport(ctx context.Context, identity *Identity, request *protocol.SignedRequest, sourceIP net.IP, dnsStatus string) (*protocol.ReportResponse, *protocol.APIError) {
	report, apiErr := protocol.DecodeReport(request.Data.Report)
	if apiErr != nil {
		return nil, apiErr
	}
	if !strings.EqualFold(report.ReportID, request.Data.ReportID) ||
		report.ScanSeq != *request.Data.ScanSeq ||
		report.CollectedAt != request.Data.CollectedAt {
		return nil, &protocol.APIError{Code: protocol.CodeReportInvalid, Message: "report fields do not match signed data"}
	}
	if !protocol.HostnamesEqual(report.Hostname, identity.Hostname) {
		return nil, &protocol.APIError{Code: protocol.CodeHostnameMismatch, Message: "report hostname does not match the registered identity"}
	}
	canonical, err := protocol.Canonicalize(request.Data.Report)
	if err != nil {
		return nil, &protocol.APIError{Code: protocol.CodeReportInvalid, Message: err.Error()}
	}
	payloadHash := sha256Hex(string(canonical))
	collectedAt, _ := protocol.ValidateTimestamp(report.CollectedAt)
	now := s.now()

	tx, err := s.DB.BeginTx(ctx, &sql.TxOptions{})
	if err != nil {
		return nil, &protocol.APIError{Code: protocol.CodeDatabase, Message: "begin report transaction"}
	}
	defer tx.Rollback()
	if apiErr := recordRequest(ctx, tx, identity.UUID, request.Data.RequestID, protocol.PathReport, now); apiErr != nil {
		return nil, apiErr
	}

	var state string
	if err := tx.QueryRowContext(ctx, `SELECT state FROM dbo.registrations WITH (UPDLOCK, HOLDLOCK) WHERE registration_id=@p1`, identity.RegistrationID).Scan(&state); err != nil {
		return nil, &protocol.APIError{Code: protocol.CodeDatabase, Message: "reload identity"}
	}
	if state != "active" {
		return nil, &protocol.APIError{Code: protocol.CodeIdentityRevoked, Message: "identity is not active"}
	}

	var existingMachine mssql.UniqueIdentifier
	var existingHash string
	var existingReceived time.Time
	err = tx.QueryRowContext(ctx, `SELECT machine_id, payload_sha256, received_at FROM dbo.reports WHERE report_id=@p1`, report.ReportID).
		Scan(&existingMachine, &existingHash, &existingReceived)
	if err == nil {
		if uuidString(existingMachine) != identity.MachineID || !strings.EqualFold(strings.TrimSpace(existingHash), payloadHash) {
			return nil, &protocol.APIError{Code: protocol.CodeReportConflict, Message: "report_id already exists with different content or machine"}
		}
		if err := tx.Commit(); err != nil {
			return nil, &protocol.APIError{Code: protocol.CodeDatabase, Message: "commit duplicate report"}
		}
		return &protocol.ReportResponse{Accepted: true, Duplicate: true, Applied: false, ReportID: report.ReportID, ReceivedAt: existingReceived.UTC().Format(time.RFC3339Nano)}, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return nil, &protocol.APIError{Code: protocol.CodeDatabase, Message: "check existing report"}
	}

	personalComplete := true
	for _, source := range report.Sources {
		if source.SourceType == "user_store" && !source.Complete {
			personalComplete = false
		}
	}
	if !report.ProfilesComplete {
		personalComplete = false
	}
	if _, err := tx.ExecContext(ctx, `
INSERT INTO dbo.reports (report_id, machine_id, registration_id, scan_seq, collected_at, received_at, status, applied, applied_sources, payload_sha256, payload_json, source_ip, dns_status, profiles_complete, personal_complete)
VALUES (@p1,@p2,@p3,@p4,@p5,@p6,@p7,0,0,@p8,@p9,@p10,@p11,@p12,@p13)`,
		report.ReportID, identity.MachineID, identity.RegistrationID, report.ScanSeq, collectedAt, now,
		report.Status, payloadHash, string(canonical), ipBytes(sourceIP), dnsStatus, report.ProfilesComplete, personalComplete); err != nil {
		if isDuplicateKey(err) {
			return nil, &protocol.APIError{Code: protocol.CodeReportConflict, Message: "report_id was inserted concurrently"}
		}
		return nil, &protocol.APIError{Code: protocol.CodeDatabase, Message: "store report"}
	}

	users, apiErr := s.upsertProfilesTx(ctx, tx, identity, report, now)
	if apiErr != nil {
		return nil, apiErr
	}
	appliedSources := 0
	for index := range report.Sources {
		applied, apiErr := s.applySourceTx(ctx, tx, identity, report, &report.Sources[index], users, now)
		if apiErr != nil {
			return nil, apiErr
		}
		if applied {
			appliedSources++
		}
	}
	if apiErr := s.applyCSPTx(ctx, tx, identity, report, now); apiErr != nil {
		return nil, apiErr
	}
	if _, err := tx.ExecContext(ctx, `UPDATE dbo.reports SET applied=@p1, applied_sources=@p2 WHERE report_id=@p3`,
		appliedSources > 0, appliedSources, report.ReportID); err != nil {
		return nil, &protocol.APIError{Code: protocol.CodeDatabase, Message: "update report application state"}
	}
	warnings := []string{}
	if dnsStatus == "mismatch" || dnsStatus == "error" {
		warnings = append(warnings, "dns_unverified")
	}
	if appliedSources == 0 {
		warnings = append(warnings, "no_newer_sources")
	}
	_ = insertEvent(ctx, tx, identity.MachineID, identity.RegistrationID, report.ReportID, request.Data.RequestID,
		"report_received", "info", "report processed",
		map[string]any{"status": report.Status, "applied_sources": appliedSources, "warnings": warnings}, now)
	if err := tx.Commit(); err != nil {
		return nil, &protocol.APIError{Code: protocol.CodeDatabase, Message: "commit report"}
	}
	return &protocol.ReportResponse{
		Accepted: true, Duplicate: false, Applied: appliedSources > 0,
		ReportID: report.ReportID, ReceivedAt: now.Format(time.RFC3339Nano), Warnings: warnings,
	}, nil
}

func (s *Store) upsertProfilesTx(ctx context.Context, tx *sql.Tx, identity *Identity, report *protocol.Report, now time.Time) (map[string]int64, *protocol.APIError) {
	users := make(map[string]int64, len(report.Profiles))
	for _, profile := range report.Profiles {
		sid, err := protocol.ValidateUserSID(profile.SID)
		if err != nil {
			return nil, &protocol.APIError{Code: protocol.CodeReportInvalid, Message: "profile SID: " + err.Error()}
		}
		id, apiErr := upsertMachineUserTx(ctx, tx, identity.MachineID, sid, profile.Name, profile.ProfilePath, profile.Loaded, report.ReportID, now)
		if apiErr != nil {
			return nil, apiErr
		}
		users[sid] = id
	}
	if report.ProfilesComplete {
		query := `UPDATE dbo.machine_users SET present=0 WHERE machine_id=@p1 AND present=1`
		args := []any{identity.MachineID}
		if len(users) > 0 {
			placeholders := make([]string, 0, len(users))
			for index, sid := range sortedKeys(users) {
				placeholders = append(placeholders, fmt.Sprintf("@p%d", index+2))
				args = append(args, sid)
			}
			query += ` AND sid NOT IN (` + strings.Join(placeholders, ",") + `)`
		}
		if _, err := tx.ExecContext(ctx, query, args...); err != nil {
			return nil, &protocol.APIError{Code: protocol.CodeDatabase, Message: "mark absent users"}
		}
	}
	return users, nil
}

func sortedKeys(values map[string]int64) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	for i := 1; i < len(keys); i++ {
		for j := i; j > 0 && keys[j] < keys[j-1]; j-- {
			keys[j], keys[j-1] = keys[j-1], keys[j]
		}
	}
	return keys
}

func upsertMachineUserTx(ctx context.Context, tx *sql.Tx, machineID, sid, name, profilePath string, loaded bool, reportID string, now time.Time) (int64, *protocol.APIError) {
	var path any
	if strings.TrimSpace(profilePath) != "" {
		path = profilePath
	}
	var id int64
	err := tx.QueryRowContext(ctx, `
MERGE dbo.machine_users WITH (HOLDLOCK) AS target
USING (SELECT @p1 AS machine_id, @p2 AS sid) AS source
ON target.machine_id=source.machine_id AND target.sid=source.sid
WHEN MATCHED THEN UPDATE SET name=@p3, profile_path=@p4, present=1, loaded=@p5, last_seen_at=@p6, last_report_id=@p7
WHEN NOT MATCHED THEN INSERT (machine_id, sid, name, profile_path, present, loaded, first_seen_at, last_seen_at, last_report_id)
VALUES (@p1, @p2, @p3, @p4, 1, @p5, @p6, @p6, @p7)
OUTPUT INSERTED.machine_user_id;`,
		machineID, sid, truncate(name, 256), path, loaded, now, reportID).Scan(&id)
	if err != nil {
		return 0, &protocol.APIError{Code: protocol.CodeDatabase, Message: "upsert machine user"}
	}
	return id, nil
}

func (s *Store) applySourceTx(ctx context.Context, tx *sql.Tx, identity *Identity, report *protocol.Report, source *protocol.SourceResult, users map[string]int64, now time.Time) (bool, *protocol.APIError) {
	scope := scopeHash(source.SourceType, source.SourceKey)
	// A queued legacy-folder report must not resurrect files after a newer
	// policy scan has revoked them. Compare ordering across the scope transition.
	if source.SourceType == "folder" && source.SourceKey != "folder-policies" {
		var seq int64
		err := tx.QueryRowContext(ctx, `SELECT last_scan_seq FROM dbo.source_states WITH(UPDLOCK,HOLDLOCK) WHERE machine_id=@p1 AND source_key_hash=@p2`, identity.MachineID, scopeHash("folder", "folder-policies")).Scan(&seq)
		if err == nil && report.ScanSeq <= seq {
			return false, nil
		}
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return false, &protocol.APIError{Code: protocol.CodeDatabase, Message: "load policy source ordering"}
		}
	}
	var lastSeq int64
	err := tx.QueryRowContext(ctx, `
SELECT last_scan_seq FROM dbo.source_states WITH (UPDLOCK, HOLDLOCK)
WHERE machine_id=@p1 AND source_key_hash=@p2`, identity.MachineID, scope).Scan(&lastSeq)
	if err == nil && report.ScanSeq <= lastSeq {
		return false, nil
	}
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return false, &protocol.APIError{Code: protocol.CodeDatabase, Message: "load source state"}
	}

	var userID any
	if source.SourceType == "user_store" {
		id, ok := users[source.UserSID]
		if !ok {
			sid, sidErr := protocol.ValidateUserSID(source.UserSID)
			if sidErr != nil {
				return false, &protocol.APIError{Code: protocol.CodeReportInvalid, Message: "source user SID: " + sidErr.Error()}
			}
			var createErr *protocol.APIError
			id, createErr = upsertMachineUserTx(ctx, tx, identity.MachineID, sid, source.DisplayName, "", false, report.ReportID, now)
			if createErr != nil {
				return false, createErr
			}
			users[sid] = id
		}
		userID = id
	}

	certHashes := make(map[string]bool, len(source.Certificates))
	for index := range source.Certificates {
		cert := &source.Certificates[index]
		if apiErr := upsertCertificateTx(ctx, tx, cert, now); apiErr != nil {
			return false, apiErr
		}
		certHashes[cert.SHA256] = true
	}

	if source.SourceType == "user_store" {
		for _, cert := range source.Certificates {
			observationID, apiErr := upsertObservationTx(ctx, tx, identity.MachineID, scope, scope, source, cert.SHA256, "", userID, report, now)
			if apiErr != nil {
				return false, apiErr
			}
			if apiErr := replaceObservationBindingsTx(ctx, tx, observationID, cert.ProviderBindings, now); apiErr != nil {
				return false, apiErr
			}
			if apiErr := upsertUserCertificateTx(ctx, tx, userID.(int64), cert.SHA256, report.ReportID, now); apiErr != nil {
				return false, apiErr
			}
		}
	} else {
		seenFileCert := make(map[string]bool)
		for _, file := range source.Files {
			if file.SHA256 == "" {
				continue
			}
			hash := strings.ToLower(file.SHA256)
			if !certHashes[hash] {
				continue
			}
			seenFileCert[hash] = true
			obsKey := observationHash(scope, file.Path)
			observationID, apiErr := upsertObservationTx(ctx, tx, identity.MachineID, scope, obsKey, source, hash, file.Path, nil, report, now)
			if apiErr != nil {
				return false, apiErr
			}
			if apiErr := replaceObservationBindingsTx(ctx, tx, observationID, nil, now); apiErr != nil {
				return false, apiErr
			}
		}
		for _, cert := range source.Certificates {
			if !seenFileCert[cert.SHA256] {
				observationID, apiErr := upsertObservationTx(ctx, tx, identity.MachineID, scope, scope, source, cert.SHA256, "", nil, report, now)
				if apiErr != nil {
					return false, apiErr
				}
				if apiErr := replaceObservationBindingsTx(ctx, tx, observationID, nil, now); apiErr != nil {
					return false, apiErr
				}
			}
		}
	}

	if source.Complete {
		if apiErr := removeMissingObservationsTx(ctx, tx, identity, source, scope, certHashes, userID, report, now); apiErr != nil {
			return false, apiErr
		}
	}
	if err := upsertSourceStateTx(ctx, tx, identity.MachineID, scope, source, report, now); err != nil {
		return false, &protocol.APIError{Code: protocol.CodeDatabase, Message: "update source state"}
	}
	if !source.Complete {
		_ = insertEvent(ctx, tx, identity.MachineID, identity.RegistrationID, report.ReportID, nil,
			"source_partial", "warning", "source was collected partially", map[string]any{"source_type": source.SourceType, "source_key": source.SourceKey, "error": source.Error}, now)
	}
	return true, nil
}

func upsertCertificateTx(ctx context.Context, tx *sql.Tx, observed *protocol.ObservedCertificate, now time.Time) *protocol.APIError {
	der, err := base64.StdEncoding.Strict().DecodeString(observed.DERBase64)
	if err != nil {
		return &protocol.APIError{Code: protocol.CodeReportInvalid, Message: "certificate DER base64"}
	}
	sum := sha256.Sum256(der)
	if hex.EncodeToString(sum[:]) != observed.SHA256 {
		return &protocol.APIError{Code: protocol.CodeReportInvalid, Message: "certificate SHA-256 mismatch"}
	}
	parsed, parseErr := certparse.Parse(der)
	var serialHex, serialNumber, subject, issuer, ownerCN, inn, snils, sigAlg any
	var notBefore, notAfter any
	var publicBits any
	var issuerHash any
	embedded := "unknown"
	parseError := observed.ParseError
	if parseErr == nil {
		serialHex = parsed.SerialHex
		serialNumber = parsed.SerialNumber
		subject = parsed.SubjectString
		issuer = parsed.IssuerString
		ownerCN = parsed.Subject.CommonName()
		inn = parsed.AttributeString(certparse.OIDINN)
		snils = parsed.AttributeString(certparse.OIDSNILS)
		sigAlg = certparse.SignatureAlgorithmName(parsed.SignatureAlgorithm)
		notBefore = parsed.NotBefore.UTC()
		notAfter = parsed.NotAfter.UTC()
		publicBits = parsed.PublicKeyBits
		issuerHash = sha256Bytes(strings.ToLower(parsed.IssuerString))
		if parsed.EmbeddedLicense {
			embedded = "present"
		} else {
			embedded = "absent"
		}
		parseError = ""
	} else if observed.ParseError == "" {
		return &protocol.APIError{Code: protocol.CodeReportInvalid, Message: "certificate cannot be parsed but parse_error is empty"}
	}
	if serialHex != nil && observed.SerialHex != "" && !strings.EqualFold(observed.SerialHex, fmt.Sprint(serialHex)) {
		return &protocol.APIError{Code: protocol.CodeReportInvalid, Message: "certificate serial number does not match DER"}
	}
	if parseErr == nil && observed.NotBefore != "" {
		agentBefore, err := protocol.ValidateTimestamp(observed.NotBefore)
		if err == nil && !agentBefore.Equal(parsed.NotBefore.UTC()) {
			return &protocol.APIError{Code: protocol.CodeReportInvalid, Message: "certificate not_before does not match DER"}
		}
	}
	if parseErr == nil && observed.NotAfter != "" {
		agentAfter, err := protocol.ValidateTimestamp(observed.NotAfter)
		if err == nil && !agentAfter.Equal(parsed.NotAfter.UTC()) {
			return &protocol.APIError{Code: protocol.CodeReportInvalid, Message: "certificate not_after does not match DER"}
		}
	}
	_, err = tx.ExecContext(ctx, `
MERGE dbo.certificates WITH (HOLDLOCK) AS target
USING (SELECT @p1 AS sha256) AS source
ON target.sha256=source.sha256
WHEN MATCHED THEN UPDATE SET
    der=@p2, serial_hex=@p3, serial_number=@p4, subject=@p5, issuer=@p6, issuer_hash=@p7,
    owner_cn=@p8, inn=@p9, snils=@p10, public_key_bits=@p11, signature_algorithm=@p12,
    embedded_license=@p13, not_before=@p14, not_after=@p15, parse_error=@p16, updated_at=@p17
WHEN NOT MATCHED THEN INSERT
    (sha256, der, serial_hex, serial_number, subject, issuer, issuer_hash, owner_cn, inn, snils,
     public_key_bits, signature_algorithm, embedded_license, not_before, not_after, parse_error, created_at, updated_at)
VALUES (@p1,@p2,@p3,@p4,@p5,@p6,@p7,@p8,@p9,@p10,@p11,@p12,@p13,@p14,@p15,@p16,@p17,@p17);`,
		observed.SHA256, der, serialHex, serialNumber, subject, issuer, issuerHash, ownerCN, inn, snils,
		publicBits, sigAlg, embedded, notBefore, notAfter, truncate(parseError, 2048), now)
	if err != nil {
		return &protocol.APIError{Code: protocol.CodeDatabase, Message: "upsert certificate"}
	}
	return nil
}

func upsertObservationTx(ctx context.Context, tx *sql.Tx, machineID string, scope, obsKey []byte, source *protocol.SourceResult, certSHA, filePath string, userID any, report *protocol.Report, now time.Time) (int64, *protocol.APIError) {
	var path any
	if strings.TrimSpace(filePath) != "" {
		path = filePath
	}
	var observationID int64
	err := tx.QueryRowContext(ctx, `
MERGE dbo.certificate_observations WITH (HOLDLOCK) AS target
USING (SELECT @p1 AS machine_id, @p2 AS observation_key_hash, @p3 AS certificate_sha256) AS source
ON target.machine_id=source.machine_id AND target.observation_key_hash=source.observation_key_hash AND target.certificate_sha256=source.certificate_sha256
WHEN MATCHED THEN UPDATE SET
    machine_user_id=@p4, source_type=@p5, source_key=@p6, source_scope_hash=@p7, file_path=@p8,
    active=1, last_seen_at=@p9, removed_at=NULL, last_report_id=@p10, last_scan_seq=@p11
WHEN NOT MATCHED THEN INSERT
    (machine_id, machine_user_id, source_type, source_key, source_scope_hash, observation_key_hash, file_path,
     certificate_sha256, active, first_seen_at, last_seen_at, removed_at, last_report_id, last_scan_seq)
VALUES (@p1,@p4,@p5,@p6,@p7,@p2,@p8,@p3,1,@p9,@p9,NULL,@p10,@p11)
OUTPUT INSERTED.observation_id;`,
		machineID, obsKey, certSHA, userID, source.SourceType, source.SourceKey, scope, path,
		now, report.ReportID, report.ScanSeq).Scan(&observationID)
	if err != nil {
		return 0, &protocol.APIError{Code: protocol.CodeDatabase, Message: "upsert certificate observation: " + err.Error()}
	}
	return observationID, nil
}

func replaceObservationBindingsTx(ctx context.Context, tx *sql.Tx, observationID int64, bindings []protocol.ProviderBinding, now time.Time) *protocol.APIError {
	if _, err := tx.ExecContext(ctx, `DELETE FROM dbo.certificate_observation_bindings WHERE observation_id=@p1`, observationID); err != nil {
		return &protocol.APIError{Code: protocol.CodeDatabase, Message: "replace provider bindings"}
	}
	for index, binding := range bindings {
		state := binding.BindingState
		if state == "" {
			state = "absent"
		}
		owner := binding.ProviderOwner
		if owner == "" {
			owner = "unknown"
		}
		privateKeyState := binding.PrivateKeyState
		if privateKeyState == "" {
			privateKeyState = "not_checked"
		}
		var observed any
		if binding.ObservedAt != "" {
			if value, err := protocol.ValidateTimestamp(binding.ObservedAt); err == nil {
				observed = value.UTC()
			}
		} else {
			observed = now
		}
		_, err := tx.ExecContext(ctx, `
INSERT INTO dbo.certificate_observation_bindings(observation_id,binding_index,provider_name,provider_api,provider_type,key_spec,
 binding_state,provider_owner,attribution_source,attribution_version,private_key_state,metadata_error_code,observed_at)
VALUES(@p1,@p2,@p3,@p4,@p5,@p6,@p7,@p8,@p9,@p10,@p11,@p12,@p13)`,
			observationID, index, truncate(binding.ProviderName, 512), truncate(binding.ProviderAPI, 16), int(binding.ProviderType), int(binding.KeySpec),
			state, owner, truncate(binding.AttributionSource, 128), truncate(binding.AttributionVersion, 64), privateKeyState,
			truncate(binding.MetadataErrorCode, 128), observed)
		if err != nil {
			return &protocol.APIError{Code: protocol.CodeDatabase, Message: "insert provider binding"}
		}
	}
	return nil
}

func upsertUserCertificateTx(ctx context.Context, tx *sql.Tx, userID int64, certSHA, reportID string, now time.Time) *protocol.APIError {
	_, err := tx.ExecContext(ctx, `
MERGE dbo.machine_user_certificates WITH (HOLDLOCK) AS target
USING (SELECT @p1 AS machine_user_id, @p2 AS certificate_sha256) AS source
ON target.machine_user_id=source.machine_user_id AND target.certificate_sha256=source.certificate_sha256
WHEN MATCHED THEN UPDATE SET active=1, last_seen_at=@p3, last_report_id=@p4
WHEN NOT MATCHED THEN INSERT (machine_user_id, certificate_sha256, active, first_seen_at, last_seen_at, last_report_id)
VALUES (@p1, @p2, 1, @p3, @p3, @p4);`,
		userID, certSHA, now, reportID)
	if err != nil {
		return &protocol.APIError{Code: protocol.CodeDatabase, Message: "upsert machine user certificate"}
	}
	return nil
}

func removeMissingObservationsTx(ctx context.Context, tx *sql.Tx, identity *Identity, source *protocol.SourceResult, scope []byte, certHashes map[string]bool, userID any, report *protocol.Report, now time.Time) *protocol.APIError {
	// User stores are keyed by SID; folders are keyed by SID+file path, so a
	// certificate moving between files must retire the old path observation.
	expectedObservations := make(map[string]bool)
	if source.SourceType == "folder" {
		for _, file := range source.Files {
			if file.SHA256 == "" {
				continue
			}
			expectedObservations[hex.EncodeToString(observationHash(scope, file.Path))+"\x00"+strings.ToLower(file.SHA256)] = true
		}
	} else {
		expectedObservations[hex.EncodeToString(scope)] = true
	}
	rows, err := tx.QueryContext(ctx, `
SELECT observation_id, observation_key_hash, certificate_sha256 FROM dbo.certificate_observations WITH (UPDLOCK, HOLDLOCK)
WHERE machine_id=@p1 AND (source_scope_hash=@p2 OR (@p3=1 AND source_type=N'folder')) AND active=1 AND last_scan_seq<=@p4`, identity.MachineID, scope, source.SourceType == "folder" && source.SourceKey == "folder-policies", report.ScanSeq)
	if err != nil {
		return &protocol.APIError{Code: protocol.CodeDatabase, Message: "load current observations"}
	}
	type staleObservation struct {
		id   int64
		hash string
	}
	var removed []staleObservation
	for rows.Next() {
		var id int64
		var key []byte
		var hash string
		if err := rows.Scan(&id, &key, &hash); err != nil {
			rows.Close()
			return &protocol.APIError{Code: protocol.CodeDatabase, Message: "decode observation"}
		}
		remove := false
		if source.SourceType == "folder" {
			remove = !expectedObservations[hex.EncodeToString(key)+"\x00"+strings.ToLower(hash)]
		} else {
			remove = !certHashes[strings.ToLower(hash)]
		}
		if remove {
			removed = append(removed, staleObservation{id: id, hash: strings.ToLower(hash)})
		}
	}
	rows.Close()
	for _, stale := range removed {
		if _, err := tx.ExecContext(ctx, `
UPDATE dbo.certificate_observations SET active=0, removed_at=@p1, last_report_id=@p2, last_scan_seq=@p3
WHERE observation_id=@p4 AND active=1`,
			now, report.ReportID, report.ScanSeq, stale.id); err != nil {
			return &protocol.APIError{Code: protocol.CodeDatabase, Message: "remove certificate observation"}
		}
		_ = insertEvent(ctx, tx, identity.MachineID, identity.RegistrationID, report.ReportID, nil,
			"certificate_disappeared", "warning", "certificate no longer observed in a fully scanned source",
			map[string]any{"source_type": source.SourceType, "source_key": source.SourceKey, "sha256": stale.hash}, now)
	}
	if source.SourceType == "user_store" && userID != nil {
		rows, err := tx.QueryContext(ctx, `
SELECT certificate_sha256 FROM dbo.machine_user_certificates WITH (UPDLOCK, HOLDLOCK)
WHERE machine_user_id=@p1 AND active=1`, userID)
		if err != nil {
			return &protocol.APIError{Code: protocol.CodeDatabase, Message: "load user certificate links"}
		}
		var links []string
		for rows.Next() {
			var hash string
			if err := rows.Scan(&hash); err != nil {
				rows.Close()
				return &protocol.APIError{Code: protocol.CodeDatabase, Message: "decode user certificate link"}
			}
			if !certHashes[strings.ToLower(hash)] {
				links = append(links, strings.ToLower(hash))
			}
		}
		rows.Close()
		for _, hash := range links {
			if _, err := tx.ExecContext(ctx, `
UPDATE dbo.machine_user_certificates SET active=0, last_report_id=@p1
WHERE machine_user_id=@p2 AND certificate_sha256=@p3 AND active=1`, report.ReportID, userID, hash); err != nil {
				return &protocol.APIError{Code: protocol.CodeDatabase, Message: "deactivate user certificate link"}
			}
		}
	}
	return nil
}

func upsertSourceStateTx(ctx context.Context, tx *sql.Tx, machineID string, scope []byte, source *protocol.SourceResult, report *protocol.Report, now time.Time) error {
	_, err := tx.ExecContext(ctx, `
MERGE dbo.source_states WITH (HOLDLOCK) AS target
USING (SELECT @p1 AS machine_id, @p2 AS source_key_hash) AS source
ON target.machine_id=source.machine_id AND target.source_key_hash=source.source_key_hash
WHEN MATCHED THEN UPDATE SET source_type=@p3, source_key=@p4, last_scan_seq=@p5, last_report_id=@p6,
    last_complete=@p7, last_collected_at=@p8, updated_at=@p9
WHEN NOT MATCHED THEN INSERT (machine_id, source_type, source_key, source_key_hash, last_scan_seq, last_report_id, last_complete, last_collected_at, updated_at)
VALUES (@p1,@p3,@p4,@p2,@p5,@p6,@p7,@p8,@p9);`,
		machineID, scope, source.SourceType, source.SourceKey, report.ScanSeq, report.ReportID,
		source.Complete, parseTimeOrZero(report.CollectedAt), now)
	return err
}

// licensesCollectionApplicable distinguishes a new agent's intentional empty
// list from a failed license collection. A nil list means an old agent and
// must not touch existing rows. COM/GetType/GetExpireDate failures must keep
// the last known state; a serial read error is a completed collection with no
// serial, so the stale row is removed and the machine becomes unknown.
func licensesCollectionApplicable(csp *protocol.CSPResult) bool {
	if csp.Licenses == nil {
		return false
	}
	if csp.License.State == "error" {
		return false
	}
	if csp.License.Error != "" && !strings.HasPrefix(csp.License.Error, "serial:") {
		return false
	}
	return true
}

func (s *Store) applyCSPTx(ctx context.Context, tx *sql.Tx, identity *Identity, report *protocol.Report, now time.Time) *protocol.APIError {
	if !report.CSP.Scanned {
		return nil
	}
	var lastSeq int64
	var oldKind, oldState, oldProduct string
	err := tx.QueryRowContext(ctx, `
SELECT last_scan_seq, COALESCE(license_kind,''), COALESCE(license_state,''), COALESCE(product_version,'')
FROM dbo.csp_states WITH (UPDLOCK, HOLDLOCK) WHERE machine_id=@p1`, identity.MachineID).
		Scan(&lastSeq, &oldKind, &oldState, &oldProduct)
	exists := err == nil
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return &protocol.APIError{Code: protocol.CodeDatabase, Message: "load CSP state"}
	}
	if exists && report.ScanSeq <= lastSeq {
		return nil
	}
	productsJSON := "[]"
	if len(report.CSP.Products) > 0 {
		raw, err := json.Marshal(report.CSP.Products)
		if err != nil {
			return &protocol.APIError{Code: protocol.CodeReportInvalid, Message: "CSP products JSON"}
		}
		productsJSON = string(raw)
	}
	if !report.CSP.Complete {
		if !exists {
			if _, err := tx.ExecContext(ctx, `
INSERT INTO dbo.csp_states (machine_id, scanned, complete, present, license_kind, license_kind_raw, license_kind_source,
 license_state, time_basis, term_kind, is_trial, source, error, products_json, last_scan_seq, collected_at, updated_at, last_attempt_at, last_attempt_error)
VALUES (@p1,1,0,@p2,'unknown','','','unknown','','unknown','unknown','',@p3,@p4,0,@p5,@p6,@p6,@p3)`,
				identity.MachineID, report.CSP.Present, truncate(report.CSP.Error, 2048), productsJSON,
				parseTimeOrZero(report.CollectedAt), now); err != nil {
				return &protocol.APIError{Code: protocol.CodeDatabase, Message: "store partial CSP state"}
			}
		} else if _, err := tx.ExecContext(ctx, `
UPDATE dbo.csp_states SET last_attempt_at=@p1, last_attempt_error=@p2, updated_at=@p1 WHERE machine_id=@p3`,
			now, truncate(report.CSP.Error, 2048), identity.MachineID); err != nil {
			return &protocol.APIError{Code: protocol.CodeDatabase, Message: "update partial CSP attempt"}
		}
		_ = insertEvent(ctx, tx, identity.MachineID, identity.RegistrationID, report.ReportID, nil,
			"csp_partial", "warning", "CryptoPro state was not fully collected", map[string]any{"error": report.CSP.Error}, now)
		return nil
	}
	validToUTC := any(nil)
	if report.CSP.License.ValidToUTC != "" {
		if parsed, err := time.Parse(time.RFC3339, report.CSP.License.ValidToUTC); err == nil {
			validToUTC = parsed.UTC()
		}
	}
	_, err = tx.ExecContext(ctx, `
MERGE dbo.csp_states WITH (HOLDLOCK) AS target
USING (SELECT @p1 AS machine_id) AS source
ON target.machine_id=source.machine_id
WHEN MATCHED THEN UPDATE SET scanned=1, complete=1, present=@p2, product_version=@p3, core_version=@p4,
 license_kind=@p5, license_kind_raw=@p6, license_kind_source=@p7, license_state=@p8,
 valid_to_raw=@p9, valid_to_utc=@p10, time_basis=@p11, term_kind=@p12, is_trial=@p13,
 source=@p14, error=@p15, products_json=@p16, last_report_id=@p17, last_scan_seq=@p18,
 collected_at=@p19, updated_at=@p20, last_attempt_at=@p20, last_attempt_error=NULL, environment=@p21
WHEN NOT MATCHED THEN INSERT (machine_id, scanned, complete, present, product_version, core_version,
 license_kind, license_kind_raw, license_kind_source, license_state, valid_to_raw, valid_to_utc,
 time_basis, term_kind, is_trial, source, error, products_json, last_report_id, last_scan_seq,
 collected_at, updated_at, last_attempt_at, last_attempt_error, environment)
VALUES (@p1,1,1,@p2,@p3,@p4,@p5,@p6,@p7,@p8,@p9,@p10,@p11,@p12,@p13,@p14,@p15,@p16,@p17,@p18,@p19,@p20,@p20,NULL,@p21);`,
		identity.MachineID, report.CSP.Present, nilIfEmpty(report.CSP.ProductVersion), nilIfEmpty(report.CSP.CoreVersion),
		nilIfEmpty(report.CSP.License.Kind), nilIfEmpty(report.CSP.License.KindRaw), nilIfEmpty(report.CSP.License.KindSource),
		nilIfEmpty(report.CSP.License.State), nilIfEmpty(report.CSP.License.ValidToRaw), validToUTC,
		nilIfEmpty(report.CSP.License.TimeBasis), nilIfEmpty(report.CSP.License.TermKind), nilIfEmpty(report.CSP.License.IsTrial),
		nilIfEmpty(report.CSP.License.Source), nilIfEmpty(report.CSP.Error), productsJSON, report.ReportID,
		report.ScanSeq, parseTimeOrZero(report.CollectedAt), now, nilIfEmpty(report.CSP.Environment))
	if err != nil {
		return &protocol.APIError{Code: protocol.CodeDatabase, Message: "store CSP state"}
	}
	if licensesCollectionApplicable(&report.CSP) {
		if apiErr := s.applyLicensesTx(ctx, tx, identity, report, now); apiErr != nil {
			return apiErr
		}
	}
	if exists && (oldKind != report.CSP.License.Kind || oldState != report.CSP.License.State || oldProduct != report.CSP.ProductVersion) {
		_ = insertEvent(ctx, tx, identity.MachineID, identity.RegistrationID, report.ReportID, nil,
			"license_changed", "info", "CryptoPro version or license state changed",
			map[string]any{"old_kind": oldKind, "new_kind": report.CSP.License.Kind, "old_state": oldState, "new_state": report.CSP.License.State, "old_product": oldProduct, "new_product": report.CSP.ProductVersion}, now)
	}
	return nil
}

func parseTimeOrZero(value string) time.Time {
	parsed, err := time.Parse(time.RFC3339Nano, value)
	if err != nil {
		return time.Time{}
	}
	return parsed.UTC()
}

func nilIfEmpty(value string) any {
	if value == "" {
		return nil
	}
	return value
}
