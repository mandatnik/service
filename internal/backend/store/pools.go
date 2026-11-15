package store

import (
	"context"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	mssql "github.com/microsoft/go-mssqldb"
	"telehack2026/internal/backend/licensecrypto"
	"telehack2026/internal/protocol"
)

// LicensePool is the administrator-visible pool metadata with counters.
type LicensePool struct {
	ID              string        `json:"id"`
	Name            string        `json:"name"`
	CSPMajorVersion int           `json:"csp_major_version"`
	LicenseKind     string        `json:"license_kind"`
	Term            string        `json:"term"`
	ArchivedAt      *time.Time    `json:"archived_at,omitempty"`
	CreatedAt       time.Time     `json:"created_at"`
	CreatedBy       string        `json:"created_by,omitempty"`
	UpdatedAt       time.Time     `json:"updated_at"`
	UpdatedBy       string        `json:"updated_by,omitempty"`
	Counts          LicenseCounts `json:"counts"`
}

type LicenseCounts struct {
	Total          int `json:"total"`
	Available      int `json:"available"`
	Reserved       int `json:"reserved"`
	Used           int `json:"used"`
	OutcomeUnknown int `json:"outcome_unknown"`
	Blocked        int `json:"blocked"`
}

type LicenseItem struct {
	ID                 string     `json:"id"`
	PoolID             string     `json:"pool_id"`
	Mask               string     `json:"mask"`
	State              string     `json:"state"`
	AssignedMachineID  string     `json:"assigned_machine_id,omitempty"`
	MachineName        string     `json:"machine_name,omitempty"`
	AssignedTaskID     string     `json:"assigned_task_id,omitempty"`
	AssignedTaskItemID string     `json:"assigned_task_item_id,omitempty"`
	ReservedAt         *time.Time `json:"reserved_at,omitempty"`
	UsedAt             *time.Time `json:"used_at,omitempty"`
	LastErrorCode      string     `json:"last_error_code,omitempty"`
	CreatedAt          time.Time  `json:"created_at"`
	CreatedBy          string     `json:"created_by,omitempty"`
}

type PoolInput struct {
	Name            string `json:"name"`
	CSPMajorVersion int    `json:"csp_major_version"`
	LicenseKind     string `json:"license_kind"`
	Term            string `json:"term"`
}

func validatePoolInput(input PoolInput) (PoolInput, error) {
	input.Name = strings.TrimSpace(input.Name)
	if input.Name == "" || len(input.Name) > 200 {
		return input, fmt.Errorf("name must contain 1..200 characters")
	}
	if input.CSPMajorVersion != 4 && input.CSPMajorVersion != 5 {
		return input, fmt.Errorf("csp_major_version must be 4 or 5")
	}
	if input.LicenseKind != protocol.PoolKindClient && input.LicenseKind != protocol.PoolKindServer {
		return input, fmt.Errorf("license_kind must be client or server")
	}
	switch input.Term {
	case protocol.PoolTermOneYear, protocol.PoolTermTwoYears, protocol.PoolTermPerpetual:
	default:
		return input, fmt.Errorf("term must be one_year, two_years or perpetual")
	}
	return input, nil
}

func (s *Store) CreatePool(ctx context.Context, input PoolInput, admin string) (*LicensePool, *protocol.APIError) {
	input, err := validatePoolInput(input)
	if err != nil {
		return nil, &protocol.APIError{Code: protocol.CodeConfigInvalid, Message: err.Error()}
	}
	now := s.now()
	poolID := protocol.NewUUID()
	_, err = s.DB.ExecContext(ctx, `
INSERT INTO dbo.license_pools(pool_id,name,csp_major_version,license_kind,term,created_at,created_by,updated_at,updated_by)
VALUES(@p1,@p2,@p3,@p4,@p5,@p6,@p7,@p6,@p7)`,
		poolID, input.Name, input.CSPMajorVersion, input.LicenseKind, input.Term, now, admin)
	if err != nil {
		if isDuplicateKey(err) {
			return nil, &protocol.APIError{Code: protocol.CodeConflict, Message: "a license pool with this name already exists"}
		}
		return nil, &protocol.APIError{Code: protocol.CodeDatabase, Message: "create license pool"}
	}
	s.insertLicenseEvent(ctx, nil, poolID, "pool_created", admin, map[string]any{
		"csp_major_version": input.CSPMajorVersion, "license_kind": input.LicenseKind, "term": input.Term,
	})
	return s.GetPool(ctx, poolID)
}

func (s *Store) UpdatePool(ctx context.Context, poolID string, input PoolInput, admin string) (*LicensePool, *protocol.APIError) {
	id, err := protocol.NormalizeUUID(poolID)
	if err != nil {
		return nil, &protocol.APIError{Code: protocol.CodeNotFound, Message: "invalid pool id"}
	}
	input, err = validatePoolInput(input)
	if err != nil {
		return nil, &protocol.APIError{Code: protocol.CodeConfigInvalid, Message: err.Error()}
	}
	var currentCSP int
	var currentKind, currentTerm string
	err = s.DB.QueryRowContext(ctx, `
SELECT csp_major_version,license_kind,term FROM dbo.license_pools WHERE pool_id=@p1`, id).
		Scan(&currentCSP, &currentKind, &currentTerm)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, &protocol.APIError{Code: protocol.CodeNotFound, Message: "license pool not found"}
	}
	if err != nil {
		return nil, &protocol.APIError{Code: protocol.CodeDatabase, Message: "load license pool"}
	}
	if currentCSP != input.CSPMajorVersion || currentKind != input.LicenseKind || currentTerm != input.Term {
		return nil, &protocol.APIError{Code: protocol.CodeConfigInvalid, Message: "CSP version, license kind and term are immutable once a pool exists"}
	}
	_, err = s.DB.ExecContext(ctx, `
UPDATE dbo.license_pools SET name=@p1,updated_at=@p2,updated_by=@p3 WHERE pool_id=@p4`, input.Name, s.now(), admin, id)
	if err != nil {
		if isDuplicateKey(err) {
			return nil, &protocol.APIError{Code: protocol.CodeConflict, Message: "a license pool with this name already exists"}
		}
		return nil, &protocol.APIError{Code: protocol.CodeDatabase, Message: "update license pool"}
	}
	s.insertLicenseEvent(ctx, nil, id, "pool_renamed", admin, nil)
	return s.GetPool(ctx, id)
}

func (s *Store) SetPoolArchived(ctx context.Context, poolID string, archived bool, admin string) (*LicensePool, *protocol.APIError) {
	id, err := protocol.NormalizeUUID(poolID)
	if err != nil {
		return nil, &protocol.APIError{Code: protocol.CodeNotFound, Message: "invalid pool id"}
	}
	var archivedAt any
	if archived {
		archivedAt = s.now()
	}
	result, err := s.DB.ExecContext(ctx, `
UPDATE dbo.license_pools SET archived_at=@p1,updated_at=@p2,updated_by=@p3 WHERE pool_id=@p4`,
		archivedAt, s.now(), admin, id)
	if err != nil {
		return nil, &protocol.APIError{Code: protocol.CodeDatabase, Message: "update pool archive state"}
	}
	if affected, _ := result.RowsAffected(); affected == 0 {
		return nil, &protocol.APIError{Code: protocol.CodeNotFound, Message: "license pool not found"}
	}
	kind := "pool_archived"
	if !archived {
		kind = "pool_unarchived"
	}
	s.insertLicenseEvent(ctx, nil, id, kind, admin, nil)
	return s.GetPool(ctx, id)
}

func (s *Store) GetPool(ctx context.Context, poolID string) (*LicensePool, *protocol.APIError) {
	id, err := protocol.NormalizeUUID(poolID)
	if err != nil {
		return nil, &protocol.APIError{Code: protocol.CodeNotFound, Message: "invalid pool id"}
	}
	var pool LicensePool
	var poolIDValue mssql.UniqueIdentifier
	var archived sql.NullTime
	var createdBy, updatedBy sql.NullString
	err = s.DB.QueryRowContext(ctx, `
SELECT pool_id,name,csp_major_version,license_kind,term,archived_at,created_at,created_by,updated_at,updated_by
FROM dbo.license_pools WHERE pool_id=@p1`, id).Scan(
		&poolIDValue, &pool.Name, &pool.CSPMajorVersion, &pool.LicenseKind, &pool.Term, &archived,
		&pool.CreatedAt, &createdBy, &pool.UpdatedAt, &updatedBy)
	pool.ID = uuidString(poolIDValue)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, &protocol.APIError{Code: protocol.CodeNotFound, Message: "license pool not found"}
	}
	if err != nil {
		return nil, &protocol.APIError{Code: protocol.CodeDatabase, Message: "load license pool"}
	}
	if archived.Valid {
		value := archived.Time.UTC()
		pool.ArchivedAt = &value
	}
	pool.CreatedBy = nullString(createdBy)
	pool.UpdatedBy = nullString(updatedBy)
	counts, err := s.poolCounts(ctx, id)
	if err != nil {
		return nil, &protocol.APIError{Code: protocol.CodeDatabase, Message: "load pool counters"}
	}
	pool.Counts = counts
	return &pool, nil
}

func (s *Store) poolCounts(ctx context.Context, poolID string) (LicenseCounts, error) {
	var counts LicenseCounts
	rows, err := s.DB.QueryContext(ctx, `
SELECT state,COUNT(1) FROM dbo.licenses WHERE pool_id=@p1 GROUP BY state`, poolID)
	if err != nil {
		return counts, err
	}
	defer rows.Close()
	for rows.Next() {
		var state string
		var count int
		if err := rows.Scan(&state, &count); err != nil {
			return counts, err
		}
		counts.Total += count
		switch state {
		case protocol.LicenseStateAvailable:
			counts.Available = count
		case protocol.LicenseStateReserved:
			counts.Reserved = count
		case protocol.LicenseStateUsed:
			counts.Used = count
		case protocol.LicenseStateOutcomeUnknown:
			counts.OutcomeUnknown = count
		case protocol.LicenseStateBlocked:
			counts.Blocked = count
		}
	}
	return counts, rows.Err()
}

func (s *Store) ListPools(ctx context.Context) ([]LicensePool, error) {
	rows, err := s.DB.QueryContext(ctx, `
SELECT pool_id,name,csp_major_version,license_kind,term,archived_at,created_at,created_by,updated_at,updated_by
FROM dbo.license_pools ORDER BY archived_at, name, pool_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var pools []LicensePool
	for rows.Next() {
		var pool LicensePool
		var poolIDValue mssql.UniqueIdentifier
		var archived sql.NullTime
		var createdBy, updatedBy sql.NullString
		if err := rows.Scan(&poolIDValue, &pool.Name, &pool.CSPMajorVersion, &pool.LicenseKind, &pool.Term,
			&archived, &pool.CreatedAt, &createdBy, &pool.UpdatedAt, &updatedBy); err != nil {
			return nil, err
		}
		pool.ID = uuidString(poolIDValue)
		if archived.Valid {
			value := archived.Time.UTC()
			pool.ArchivedAt = &value
		}
		pool.CreatedBy = nullString(createdBy)
		pool.UpdatedBy = nullString(updatedBy)
		counts, err := s.poolCounts(ctx, pool.ID)
		if err != nil {
			return nil, err
		}
		pool.Counts = counts
		pools = append(pools, pool)
	}
	return pools, rows.Err()
}

var serialLikePattern = regexp.MustCompile(`(?i)[0-9a-z]{4,5}([ -]?[0-9a-z]{4,5}){4}`)

func redactSerialLike(value string) string {
	return serialLikePattern.ReplaceAllString(value, "[redacted]")
}

type LicenseImportLine struct {
	Line       int    `json:"line"`
	Status     string `json:"status"`
	ReasonCode string `json:"reason_code,omitempty"`
	LicenseID  string `json:"license_id,omitempty"`
	Mask       string `json:"mask,omitempty"`
}

type LicenseImportResult struct {
	Accepted bool                `json:"accepted"`
	PoolID   string              `json:"pool_id"`
	Lines    []LicenseImportLine `json:"lines"`
	Imported int                 `json:"imported"`
	Counts   LicenseCounts       `json:"counts"`
}

// ImportLicenses validates every line first. Any invalid or globally duplicate
// line rejects the whole batch; no hidden partial import is performed.
func (s *Store) ImportLicenses(ctx context.Context, poolID string, serials []string, admin string) (*LicenseImportResult, *protocol.APIError) {
	id, err := protocol.NormalizeUUID(poolID)
	if err != nil {
		return nil, &protocol.APIError{Code: protocol.CodeNotFound, Message: "invalid pool id"}
	}
	if s.LicenseKeyring == nil || s.FingerprintKey == nil {
		return nil, &protocol.APIError{Code: protocol.CodeLicenseUnavailable, Message: "license key material is not available on this server"}
	}
	if len(serials) == 0 || len(serials) > 2000 {
		return nil, &protocol.APIError{Code: protocol.CodeConfigInvalid, Message: "import must contain 1..2000 lines"}
	}
	var pool LicensePool
	var poolIDValue mssql.UniqueIdentifier
	var archived sql.NullTime
	err = s.DB.QueryRowContext(ctx, `
SELECT pool_id,name,csp_major_version,license_kind,term,archived_at FROM dbo.license_pools WHERE pool_id=@p1`, id).
		Scan(&poolIDValue, &pool.Name, &pool.CSPMajorVersion, &pool.LicenseKind, &pool.Term, &archived)
	pool.ID = uuidString(poolIDValue)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, &protocol.APIError{Code: protocol.CodeNotFound, Message: "license pool not found"}
	}
	if err != nil {
		return nil, &protocol.APIError{Code: protocol.CodeDatabase, Message: "load license pool"}
	}
	if archived.Valid {
		return nil, &protocol.APIError{Code: protocol.CodeConfigInvalid, Message: "archived pools cannot receive licenses"}
	}

	result := &LicenseImportResult{PoolID: id, Lines: make([]LicenseImportLine, 0, len(serials))}
	var candidates []licenseCandidate
	seen := map[string]int{}
	valid := true
	for index, raw := range serials {
		line := index + 1
		normalized := protocol.NormalizeSerial(raw)
		if err := protocol.ValidateSerialFormat(normalized); err != nil {
			result.Lines = append(result.Lines, LicenseImportLine{Line: line, Status: "invalid", ReasonCode: "invalid_format"})
			valid = false
			continue
		}
		if previous, duplicate := seen[normalized]; duplicate {
			result.Lines = append(result.Lines, LicenseImportLine{Line: line, Status: "duplicate", ReasonCode: "duplicate_in_import"})
			_ = previous
			valid = false
			continue
		}
		seen[normalized] = line
		fingerprint := s.FingerprintKey.Fingerprint(normalized)
		candidates = append(candidates, licenseCandidate{line: line, serial: normalized, mask: protocol.MaskSerial(normalized), fingerprint: fingerprint})
	}
	if len(candidates) > 0 {
		existing, err := s.existingFingerprints(ctx, candidates)
		if err != nil {
			return nil, &protocol.APIError{Code: protocol.CodeDatabase, Message: "check serial duplicates"}
		}
		for i := range candidates {
			if _, duplicate := existing[hex.EncodeToString(candidates[i].fingerprint)]; duplicate {
				result.Lines = append(result.Lines, LicenseImportLine{Line: candidates[i].line, Status: "duplicate", ReasonCode: "duplicate_in_system"})
				valid = false
			}
		}
	}
	if !valid {
		result.Accepted = false
		return result, nil
	}

	tx, err := s.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return nil, &protocol.APIError{Code: protocol.CodeDatabase, Message: "begin license import"}
	}
	defer tx.Rollback()
	now := s.now()
	for i := range candidates {
		licenseID := protocol.NewUUID()
		aad, err := licensecrypto.LicenseAAD(licensecrypto.LicenseBinding{
			LicenseID: licenseID, PoolID: id, CSPMajorVersion: pool.CSPMajorVersion,
			LicenseKind: pool.LicenseKind, Term: pool.Term,
		})
		if err != nil {
			return nil, &protocol.APIError{Code: protocol.CodeInternal, Message: "bind license encryption"}
		}
		sealed, err := s.LicenseKeyring.Encrypt(candidates[i].serial, aad)
		if err != nil {
			return nil, &protocol.APIError{Code: protocol.CodeLicenseUnavailable, Message: "encrypt license serial"}
		}
		_, err = tx.ExecContext(ctx, `
INSERT INTO dbo.licenses(license_id,pool_id,encrypted_serial,encryption_key_id,serial_fingerprint,serial_mask,state,created_at,created_by,updated_at)
VALUES(@p1,@p2,@p3,@p4,@p5,@p6,N'available',@p7,@p8,@p7)`,
			licenseID, id, sealed, s.LicenseKeyring.ActiveKeyID(), candidates[i].fingerprint, candidates[i].mask, now, admin)
		if err != nil {
			if isDuplicateKey(err) {
				return nil, &protocol.APIError{Code: protocol.CodeConflict, Message: "a license in this import was added concurrently; nothing was imported"}
			}
			return nil, &protocol.APIError{Code: protocol.CodeDatabase, Message: "insert license"}
		}
		candidates[i].licenseID = licenseID
		result.Lines = append(result.Lines, LicenseImportLine{Line: candidates[i].line, Status: "accepted", LicenseID: licenseID, Mask: candidates[i].mask})
	}
	if _, err := tx.ExecContext(ctx, `
INSERT INTO dbo.license_events(license_id,pool_id,kind,actor,details_json,created_at)
VALUES(NULL,@p1,N'licenses_imported',@p2,@p3,@p4)`,
		id, admin, fmt.Sprintf(`{"count":%d}`, len(candidates)), now); err != nil {
		return nil, &protocol.APIError{Code: protocol.CodeDatabase, Message: "record license import"}
	}
	if err := tx.Commit(); err != nil {
		return nil, &protocol.APIError{Code: protocol.CodeDatabase, Message: "commit license import"}
	}
	result.Accepted = true
	result.Imported = len(candidates)
	counts, err := s.poolCounts(ctx, id)
	if err == nil {
		result.Counts = counts
	}
	return result, nil
}

type licenseCandidate struct {
	line        int
	serial      string
	mask        string
	fingerprint []byte
	licenseID   string
}

func (s *Store) existingFingerprints(ctx context.Context, candidates []licenseCandidate) (map[string]string, error) {
	hexes := make([]map[string]string, 0, len(candidates))
	for _, candidate := range candidates {
		hexes = append(hexes, map[string]string{"h": hex.EncodeToString(candidate.fingerprint)})
	}
	raw, _ := json.Marshal(hexes)
	rows, err := s.DB.QueryContext(ctx, `
SELECT CONVERT(VARCHAR(64), serial_fingerprint, 2) FROM dbo.licenses WHERE serial_fingerprint IN (
  SELECT CONVERT(VARBINARY(32), value, 2) FROM OPENJSON(@p1) WITH (value NVARCHAR(64) '$.h')
)`, string(raw))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	found := map[string]string{}
	for rows.Next() {
		var value string
		if err := rows.Scan(&value); err != nil {
			return nil, err
		}
		found[strings.ToLower(value)] = value
	}
	return found, rows.Err()
}

func (s *Store) ListLicenses(ctx context.Context, poolID, state string, page, pageSize int) (Page[LicenseItem], error) {
	page, pageSize = normalizePage(page, pageSize)
	id, err := protocol.NormalizeUUID(poolID)
	if err != nil {
		return Page[LicenseItem]{}, err
	}
	where := []string{"l.pool_id=@p1"}
	args := []any{id}
	if state != "" {
		where = append(where, "l.state=@p2")
		args = append(args, state)
	}
	base := ` FROM dbo.licenses l
LEFT JOIN dbo.machines m ON m.machine_id=l.assigned_machine_id
LEFT JOIN dbo.task_items ti ON ti.item_id=l.assigned_task_item_id
WHERE ` + strings.Join(where, " AND ")
	var total int
	if err := s.DB.QueryRowContext(ctx, "SELECT COUNT(1)"+base, args...).Scan(&total); err != nil {
		return Page[LicenseItem]{}, err
	}
	queryArgs := append([]any(nil), args...)
	queryArgs = append(queryArgs, (page-1)*pageSize, pageSize)
	rows, err := s.DB.QueryContext(ctx, `
SELECT l.license_id,l.pool_id,l.serial_mask,l.state,l.assigned_machine_id,m.display_name,l.assigned_task_item_id,
       ti.task_id,l.reserved_at,l.used_at,l.last_error_code,l.created_at,l.created_by
`+base+fmt.Sprintf(` ORDER BY l.created_at,l.license_id OFFSET @p%d ROWS FETCH NEXT @p%d ROWS ONLY`, len(args)+1, len(args)+2), queryArgs...)
	if err != nil {
		return Page[LicenseItem]{}, err
	}
	defer rows.Close()
	items := []LicenseItem{}
	for rows.Next() {
		var item LicenseItem
		var licenseID, poolIDValue mssql.UniqueIdentifier
		var machine, taskItem, taskID mssql.NullUniqueIdentifier
		var machineName sql.NullString
		var reserved, used sql.NullTime
		var lastError, createdBy sql.NullString
		if err := rows.Scan(&licenseID, &poolIDValue, &item.Mask, &item.State, &machine, &machineName,
			&taskItem, &taskID, &reserved, &used, &lastError, &item.CreatedAt, &createdBy); err != nil {
			return Page[LicenseItem]{}, err
		}
		item.ID = uuidString(licenseID)
		item.PoolID = uuidString(poolIDValue)
		item.AssignedMachineID = nullUUIDString(machine)
		item.MachineName = nullString(machineName)
		item.AssignedTaskItemID = nullUUIDString(taskItem)
		item.AssignedTaskID = nullUUIDString(taskID)
		if reserved.Valid {
			value := reserved.Time.UTC()
			item.ReservedAt = &value
		}
		if used.Valid {
			value := used.Time.UTC()
			item.UsedAt = &value
		}
		item.LastErrorCode = nullString(lastError)
		item.CreatedBy = nullString(createdBy)
		items = append(items, item)
	}
	return Page[LicenseItem]{Items: items, Page: page, PageSize: pageSize, Total: total}, rows.Err()
}

func (s *Store) BlockLicense(ctx context.Context, licenseID, reason, admin string) *protocol.APIError {
	id, err := protocol.NormalizeUUID(licenseID)
	if err != nil {
		return &protocol.APIError{Code: protocol.CodeNotFound, Message: "invalid license id"}
	}
	reason = strings.TrimSpace(reason)
	if reason == "" || len(reason) > 512 {
		return &protocol.APIError{Code: protocol.CodeConfigInvalid, Message: "block reason is required"}
	}
	reason = redactSerialLike(reason)
	result, err := s.DB.ExecContext(ctx, `
UPDATE dbo.licenses SET state=N'blocked',last_error_code=@p1,updated_at=@p2
WHERE license_id=@p3 AND state=N'available'`, reason, s.now(), id)
	if err != nil {
		return &protocol.APIError{Code: protocol.CodeDatabase, Message: "block license"}
	}
	if affected, _ := result.RowsAffected(); affected == 0 {
		return &protocol.APIError{Code: protocol.CodeConflict, Message: "only an available license can be blocked"}
	}
	s.insertLicenseEvent(ctx, &id, nil, "license_blocked", admin, map[string]any{"reason": reason})
	return nil
}

// ResolveLicenseSerial decrypts a serial only for the assignment transaction.
func (s *Store) ResolveLicenseSerial(ctx context.Context, licenseID string) (string, *protocol.APIError) {
	if s.LicenseKeyring == nil {
		return "", &protocol.APIError{Code: protocol.CodeLicenseUnavailable, Message: "license key material is not available on this server"}
	}
	id, err := protocol.NormalizeUUID(licenseID)
	if err != nil {
		return "", &protocol.APIError{Code: protocol.CodeNotFound, Message: "invalid license id"}
	}
	var sealed []byte
	var poolIDValue mssql.UniqueIdentifier
	var csp int
	var kind, term string
	err = s.DB.QueryRowContext(ctx, `
SELECT l.encrypted_serial,l.pool_id,p.csp_major_version,p.license_kind,p.term
FROM dbo.licenses l JOIN dbo.license_pools p ON p.pool_id=l.pool_id WHERE l.license_id=@p1`, id).
		Scan(&sealed, &poolIDValue, &csp, &kind, &term)
	if errors.Is(err, sql.ErrNoRows) {
		return "", &protocol.APIError{Code: protocol.CodeNotFound, Message: "license not found"}
	}
	if err != nil {
		return "", &protocol.APIError{Code: protocol.CodeDatabase, Message: "load license"}
	}
	poolID := uuidString(poolIDValue)
	aad, err := licensecrypto.LicenseAAD(licensecrypto.LicenseBinding{LicenseID: id, PoolID: poolID, CSPMajorVersion: csp, LicenseKind: kind, Term: term})
	if err != nil {
		return "", &protocol.APIError{Code: protocol.CodeInternal, Message: "bind license encryption"}
	}
	serial, err := s.LicenseKeyring.Decrypt(sealed, aad)
	if err != nil {
		return "", &protocol.APIError{Code: protocol.CodeLicenseUnavailable, Message: "license serial cannot be decrypted with the configured keyring"}
	}
	return serial, nil
}

type LicenseHistoryItem struct {
	CreatedAt  time.Time       `json:"created_at"`
	Kind       string          `json:"kind"`
	LicenseID  string          `json:"license_id,omitempty"`
	Mask       string          `json:"mask,omitempty"`
	MachineID  string          `json:"machine_id,omitempty"`
	Machine    string          `json:"machine_name,omitempty"`
	TaskItemID string          `json:"task_item_id,omitempty"`
	Reason     string          `json:"reason,omitempty"`
	Details    json.RawMessage `json:"details,omitempty"`
}

// LicenseHistory returns the append-only reservation/assignment trail without
// serial numbers. It is intentionally separate from the license table so a
// release never erases why a key was held.
func (s *Store) LicenseHistory(ctx context.Context, poolID string, limit int) ([]LicenseHistoryItem, error) {
	id, err := protocol.NormalizeUUID(poolID)
	if err != nil {
		return nil, err
	}
	if limit <= 0 || limit > 500 {
		limit = 200
	}
	rows, err := s.DB.QueryContext(ctx, `
SELECT e.created_at,e.kind,COALESCE(l.license_id,'00000000-0000-0000-0000-000000000000'),COALESCE(l.serial_mask,''),
       m.machine_id,m.display_name,COALESCE(l.assigned_task_item_id,'00000000-0000-0000-0000-000000000000'),
       COALESCE(l.last_error_code,''),e.details_json
FROM dbo.license_events e
LEFT JOIN dbo.licenses l ON l.license_id=e.license_id
LEFT JOIN dbo.machines m ON m.machine_id=l.assigned_machine_id
WHERE e.pool_id=@p1 OR e.license_id IN (SELECT license_id FROM dbo.licenses WHERE pool_id=@p1)
UNION ALL
SELECT a.created_at,N'assignment_'+a.state,a.license_id,l.serial_mask,a.machine_id,m.display_name,a.task_item_id,
       COALESCE(a.released_reason,''),NULL
FROM dbo.license_assignments a
JOIN dbo.licenses l ON l.license_id=a.license_id
JOIN dbo.machines m ON m.machine_id=a.machine_id
WHERE l.pool_id=@p1
ORDER BY created_at DESC
OFFSET 0 ROWS FETCH NEXT @p2 ROWS ONLY`, id, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var items []LicenseHistoryItem
	for rows.Next() {
		var item LicenseHistoryItem
		var licenseID, machineID, taskItemID mssql.NullUniqueIdentifier
		var mask, machine, reason, details sql.NullString
		if err := rows.Scan(&item.CreatedAt, &item.Kind, &licenseID, &mask, &machineID, &machine, &taskItemID, &reason, &details); err != nil {
			return nil, err
		}
		item.LicenseID = nullUUIDString(licenseID)
		item.Mask = nullString(mask)
		item.MachineID = nullUUIDString(machineID)
		item.Machine = nullString(machine)
		item.TaskItemID = nullUUIDString(taskItemID)
		item.Reason = nullString(reason)
		if details.Valid {
			item.Details = json.RawMessage(details.String)
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func (s *Store) insertLicenseEvent(ctx context.Context, licenseID any, poolID any, kind, actor string, details any) {
	var detailsJSON any
	if details != nil {
		raw, err := json.Marshal(details)
		if err == nil {
			detailsJSON = string(raw)
		}
	}
	_, _ = s.DB.ExecContext(ctx, `
INSERT INTO dbo.license_events(license_id,pool_id,kind,actor,details_json,created_at)
VALUES(@p1,@p2,@p3,@p4,@p5,@p6)`, licenseID, poolID, kind, actor, detailsJSON, s.now())
}

func nullUUID(value mssql.NullUniqueIdentifier) string {
	return nullUUIDString(value)
}
