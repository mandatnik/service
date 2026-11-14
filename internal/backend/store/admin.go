package store

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/asn1"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strings"
	"telehack2026/internal/certparse"
	"time"

	mssql "github.com/microsoft/go-mssqldb"
	"telehack2026/internal/protocol"
)

// AdminAccount is the credential record used by the local admin login.
type AdminAccount struct {
	ID           int64
	Username     string
	PasswordHash string
	Disabled     bool
}

// AdminSession is an authenticated browser session.
type AdminSession struct {
	SessionID string
	AdminID   int64
	Username  string
	ExpiresAt time.Time
}

func (s *Store) AdminByUsername(ctx context.Context, username string) (*AdminAccount, error) {
	var account AdminAccount
	err := s.DB.QueryRowContext(ctx, `
SELECT admin_id, username, password_hash, disabled FROM dbo.administrators WHERE username=@p1`, username).
		Scan(&account.ID, &account.Username, &account.PasswordHash, &account.Disabled)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, sql.ErrNoRows
	}
	if err != nil {
		return nil, err
	}
	return &account, nil
}

// UpsertAdmin creates or replaces a local administrator. The password hash
// must already be a bcrypt hash; the plaintext password never reaches SQL.
func (s *Store) UpsertAdmin(ctx context.Context, username, passwordHash string) (int64, error) {
	username = strings.TrimSpace(username)
	if len(username) < 3 || len(username) > 128 {
		return 0, fmt.Errorf("username must be between 3 and 128 characters")
	}
	var id int64
	err := s.DB.QueryRowContext(ctx, `
MERGE dbo.administrators WITH (HOLDLOCK) AS target
USING (SELECT @p1 AS username) AS source ON target.username=source.username
WHEN MATCHED THEN UPDATE SET password_hash=@p2, disabled=0
WHEN NOT MATCHED THEN INSERT (username, password_hash, disabled, created_at)
VALUES (@p1, @p2, 0, @p3)
OUTPUT INSERTED.admin_id;`, username, passwordHash, s.now()).Scan(&id)
	if err != nil {
		return 0, fmt.Errorf("upsert administrator: %w", err)
	}
	return id, nil
}

func (s *Store) CreateAdminSession(ctx context.Context, adminID int64, tokenHash string, ttl time.Duration) (time.Time, error) {
	now := s.now()
	expires := now.Add(ttl)
	_, _ = s.DB.ExecContext(ctx, `DELETE FROM dbo.admin_sessions WHERE expires_at < @p1 OR revoked_at IS NOT NULL`, now)
	_, err := s.DB.ExecContext(ctx, `
INSERT INTO dbo.admin_sessions (session_id, admin_id, token_hash, created_at, expires_at, last_seen_at)
VALUES (@p1, @p2, @p3, @p4, @p5, @p4)`, protocol.NewUUID(), adminID, tokenHash, now, expires)
	if err != nil {
		return time.Time{}, fmt.Errorf("create admin session: %w", err)
	}
	return expires, nil
}

func (s *Store) ValidateAdminSession(ctx context.Context, tokenHash string) (*AdminSession, error) {
	var session AdminSession
	var id mssql.UniqueIdentifier
	var expires time.Time
	err := s.DB.QueryRowContext(ctx, `
SELECT s.session_id, s.admin_id, a.username, s.expires_at
FROM dbo.admin_sessions s JOIN dbo.administrators a ON a.admin_id=s.admin_id
WHERE s.token_hash=@p1 AND s.revoked_at IS NULL AND s.expires_at > @p2 AND a.disabled=0`,
		tokenHash, s.now()).Scan(&id, &session.AdminID, &session.Username, &expires)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, sql.ErrNoRows
	}
	if err != nil {
		return nil, err
	}
	session.SessionID = uuidString(id)
	session.ExpiresAt = expires.UTC()
	_, _ = s.DB.ExecContext(ctx, `UPDATE dbo.admin_sessions SET last_seen_at=@p1 WHERE token_hash=@p2`, s.now(), tokenHash)
	return &session, nil
}

func (s *Store) RevokeAdminSession(ctx context.Context, tokenHash string) error {
	_, err := s.DB.ExecContext(ctx, `UPDATE dbo.admin_sessions SET revoked_at=@p1 WHERE token_hash=@p2 AND revoked_at IS NULL`, s.now(), tokenHash)
	return err
}

// TokenHash returns the stable SHA-256 hex used for session storage.
func TokenHash(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// Admin job/config/event helpers -------------------------------------------------

func (s *Store) AddAdminJob(ctx context.Context, machineID, admin string) (string, error) {
	jobID, err := s.AddJob(ctx, machineID, admin)
	if err != nil {
		return "", err
	}
	s.InsertAdminEvent(ctx, machineID, "job_created", "info", "manual scan job created by administrator", map[string]any{"job_id": jobID, "admin": admin})
	return jobID, nil
}

func (s *Store) InsertAdminEvent(ctx context.Context, machineID any, kind, severity, message string, details any) {
	var detailsJSON any
	if details != nil {
		if raw, err := json.Marshal(details); err == nil {
			detailsJSON = string(raw)
		}
	}
	_, _ = s.DB.ExecContext(ctx, `
INSERT INTO dbo.events (machine_id, registration_id, report_id, request_id, kind, severity, message, details_json, created_at)
VALUES (@p1, NULL, NULL, NULL, @p2, @p3, @p4, @p5, @p6)`,
		machineID, kind, severity, truncate(message, 1024), detailsJSON, s.now())
}

// Admin DTOs -------------------------------------------------------------------

type MachineSummary struct {
	MachineID         string     `json:"machine_id"`
	DisplayName       string     `json:"display_name"`
	UUID              string     `json:"uuid,omitempty"`
	Hostname          string     `json:"hostname,omitempty"`
	RegistrationState string     `json:"registration_state"`
	LastSeenAt        *time.Time `json:"last_seen_at,omitempty"`
	SourceIP          string     `json:"source_ip,omitempty"`
	DNSStatus         string     `json:"dns_status,omitempty"`
	HostnameConflict  bool       `json:"hostname_conflict"`
	ProductVersion    string     `json:"product_version,omitempty"`
	CoreVersion       string     `json:"core_version,omitempty"`
	LicenseKind       string     `json:"license_kind,omitempty"`
	LicenseKindRaw    string     `json:"license_kind_raw,omitempty"`
	LicenseState      string     `json:"license_state,omitempty"`
	TermKind          string     `json:"term_kind,omitempty"`
	IsTrial           string     `json:"is_trial,omitempty"`
	LastReportID      string     `json:"last_report_id,omitempty"`
	LastReportStatus  string     `json:"last_report_status,omitempty"`
	LastReportAt      *time.Time `json:"last_report_at,omitempty"`
	AppliedSources    int        `json:"applied_sources"`
	Users             int        `json:"users"`
	ActiveCerts       int        `json:"active_certificates"`
	Offline           bool       `json:"offline"`
}

type Page[T any] struct {
	Items    []T `json:"items"`
	Page     int `json:"page"`
	PageSize int `json:"page_size"`
	Total    int `json:"total"`
}

func normalizePage(page, pageSize int) (int, int) {
	if page < 1 {
		page = 1
	}
	if pageSize < 1 {
		pageSize = 25
	}
	if pageSize > 100 {
		pageSize = 100
	}
	return page, pageSize
}

func nullString(value sql.NullString) string {
	if value.Valid {
		return value.String
	}
	return ""
}

func nullTime(value sql.NullTime) *time.Time {
	if value.Valid {
		v := value.Time.UTC()
		return &v
	}
	return nil
}

func nullUUIDString(value mssql.NullUniqueIdentifier) string {
	if value.Valid {
		return uuidString(value.UUID)
	}
	return ""
}

func ipString(value []byte) string {
	if len(value) == 0 {
		return ""
	}
	return net.IP(value).String()
}

type AdminMachineFilter struct {
	Query     string
	Status    string
	Page      int
	PageSize  int
	MachineID string
}

func (s *Store) ListMachines(ctx context.Context, filter AdminMachineFilter) (Page[MachineSummary], error) {
	page, pageSize := normalizePage(filter.Page, filter.PageSize)
	where := []string{"1=1"}
	args := []any{}
	add := func(format string, values ...any) {
		placeholders := make([]any, len(values))
		for i := range values {
			placeholders[i] = len(args) + i + 1
		}
		where = append(where, fmt.Sprintf(format, placeholders...))
		args = append(args, values...)
	}
	if filter.MachineID != "" {
		add("m.machine_id=@p%d", filter.MachineID)
	}
	if q := strings.TrimSpace(filter.Query); q != "" {
		like := "%" + q + "%"
		add("(m.display_name LIKE @p%d OR r.hostname LIKE @p%d OR CONVERT(nvarchar(36), r.uuid) LIKE @p%d)", like, like, like)
	}
	switch filter.Status {
	case "active":
		where = append(where, "r.state='active'")
	case "offline":
		where = append(where, "r.state='active' AND (r.last_seen_at IS NULL OR r.last_seen_at < DATEADD(minute, -20, SYSUTCDATETIME()))")
	case "conflict":
		where = append(where, "EXISTS (SELECT 1 FROM dbo.registrations r2 WHERE r2.hostname_norm=r.hostname_norm AND r2.state='active' AND r2.registration_id<>r.registration_id)")
	}
	baseJoin := `
FROM dbo.machines m
LEFT JOIN dbo.registrations r ON r.machine_id=m.machine_id AND r.state='active'
LEFT JOIN dbo.csp_states c ON c.machine_id=m.machine_id
OUTER APPLY (SELECT TOP 1 report_id,status,collected_at,applied_sources FROM dbo.reports rep WHERE rep.machine_id=m.machine_id ORDER BY rep.scan_seq DESC) rp
WHERE ` + strings.Join(where, " AND ")
	countArgs := append([]any(nil), args...)
	var total int
	if err := s.DB.QueryRowContext(ctx, "SELECT COUNT(1) "+baseJoin, countArgs...).Scan(&total); err != nil {
		return Page[MachineSummary]{}, err
	}
	queryArgs := append([]any(nil), args...)
	queryArgs = append(queryArgs, (page-1)*pageSize, pageSize)
	query := `
SELECT m.machine_id, m.display_name,
       r.uuid, r.hostname, r.state, r.last_seen_at, r.last_source_ip, r.last_dns_status,
       c.product_version, c.core_version, c.license_kind, c.license_kind_raw, c.license_state, c.term_kind, c.is_trial,
       rp.report_id, rp.status, rp.collected_at, COALESCE(rp.applied_sources,0),
       (SELECT COUNT(*) FROM dbo.machine_users mu WHERE mu.machine_id=m.machine_id),
       (SELECT COUNT(*) FROM dbo.certificate_observations o WHERE o.machine_id=m.machine_id AND o.active=1),
       CASE WHEN EXISTS (SELECT 1 FROM dbo.registrations r2 WHERE r2.hostname_norm=r.hostname_norm AND r2.state='active' AND r2.registration_id<>r.registration_id) THEN 1 ELSE 0 END
` + baseJoin + fmt.Sprintf(` ORDER BY m.display_name OFFSET @p%d ROWS FETCH NEXT @p%d ROWS ONLY`, len(args)+1, len(args)+2)
	rows, err := s.DB.QueryContext(ctx, query, queryArgs...)
	if err != nil {
		return Page[MachineSummary]{}, err
	}
	defer rows.Close()
	items := []MachineSummary{}
	now := s.now()
	for rows.Next() {
		var item MachineSummary
		var id mssql.NullUniqueIdentifier
		var uuid mssql.NullUniqueIdentifier
		var hostname, regState sql.NullString
		var lastSeen sql.NullTime
		var ip []byte
		var dns, product, core, kind, raw, state, term, trial sql.NullString
		var reportID mssql.NullUniqueIdentifier
		var reportStatus sql.NullString
		var collected sql.NullTime
		var applied, users, certs, conflict int
		if err := rows.Scan(&id, &item.DisplayName, &uuid, &hostname, &regState, &lastSeen, &ip, &dns,
			&product, &core, &kind, &raw, &state, &term, &trial, &reportID, &reportStatus, &collected, &applied,
			&users, &certs, &conflict); err != nil {
			return Page[MachineSummary]{}, err
		}
		item.MachineID = uuidString(id.UUID)
		item.UUID = nullUUIDString(uuid)
		item.Hostname = nullString(hostname)
		item.RegistrationState = nullString(regState)
		item.LastSeenAt = nullTime(lastSeen)
		item.SourceIP = ipString(ip)
		item.DNSStatus = nullString(dns)
		item.HostnameConflict = conflict != 0
		item.ProductVersion = nullString(product)
		item.CoreVersion = nullString(core)
		item.LicenseKind = nullString(kind)
		item.LicenseKindRaw = nullString(raw)
		item.LicenseState = nullString(state)
		item.TermKind = nullString(term)
		item.IsTrial = nullString(trial)
		item.LastReportID = nullUUIDString(reportID)
		item.LastReportStatus = nullString(reportStatus)
		if collected.Valid {
			v := collected.Time.UTC()
			item.LastReportAt = &v
		}
		item.AppliedSources = applied
		item.Users = users
		item.ActiveCerts = certs
		item.Offline = item.LastSeenAt == nil || now.Sub(*item.LastSeenAt) > 20*time.Minute
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return Page[MachineSummary]{}, err
	}
	return Page[MachineSummary]{Items: items, Page: page, PageSize: pageSize, Total: total}, nil
}

type RegistrationInfo struct {
	RegistrationID int64      `json:"registration_id"`
	UUID           string     `json:"uuid"`
	Hostname       string     `json:"hostname"`
	State          string     `json:"state"`
	KeyFingerprint string     `json:"key_fingerprint"`
	CreatedAt      time.Time  `json:"created_at"`
	LastSeenAt     *time.Time `json:"last_seen_at,omitempty"`
	SourceIP       string     `json:"source_ip,omitempty"`
	DNSStatus      string     `json:"dns_status,omitempty"`
	PreviousID     *int64     `json:"previous_registration_id,omitempty"`
	ReplacedByID   *int64     `json:"replaced_by_registration_id,omitempty"`
	RevokedAt      *time.Time `json:"revoked_at,omitempty"`
}

type MachineUserInfo struct {
	MachineUserID int64     `json:"machine_user_id"`
	SID           string    `json:"sid"`
	Name          string    `json:"name"`
	ProfilePath   string    `json:"profile_path,omitempty"`
	Loaded        bool      `json:"loaded"`
	Present       bool      `json:"present"`
	FirstSeenAt   time.Time `json:"first_seen_at"`
	LastSeenAt    time.Time `json:"last_seen_at"`
}

type SourceStateInfo struct {
	SourceType      string    `json:"source_type"`
	SourceKey       string    `json:"source_key"`
	LastScanSeq     int64     `json:"last_scan_seq"`
	LastComplete    bool      `json:"last_complete"`
	LastCollectedAt time.Time `json:"last_collected_at"`
	LastReportID    string    `json:"last_report_id"`
	Stale           bool      `json:"stale"`
}

type ReportInfo struct {
	ReportID       string    `json:"report_id"`
	ScanSeq        int64     `json:"scan_seq"`
	Status         string    `json:"status"`
	Applied        bool      `json:"applied"`
	AppliedSources int       `json:"applied_sources"`
	CollectedAt    time.Time `json:"collected_at"`
	ReceivedAt     time.Time `json:"received_at"`
}

type EventInfo struct {
	EventID   int64     `json:"event_id"`
	MachineID string    `json:"machine_id,omitempty"`
	Kind      string    `json:"kind"`
	Severity  string    `json:"severity"`
	Message   string    `json:"message"`
	Details   string    `json:"details_json,omitempty"`
	CreatedAt time.Time `json:"created_at"`
}

type JobInfo struct {
	JobID       string     `json:"job_id"`
	MachineID   string     `json:"machine_id"`
	Kind        string     `json:"kind"`
	State       string     `json:"state"`
	CreatedAt   time.Time  `json:"created_at"`
	DeliveredAt *time.Time `json:"delivered_at,omitempty"`
	CompletedAt *time.Time `json:"completed_at,omitempty"`
	ReportID    string     `json:"report_id,omitempty"`
	Message     string     `json:"message,omitempty"`
}

type HostnameCompetitor struct {
	RegistrationID int64  `json:"registration_id"`
	UUID           string `json:"uuid"`
	Hostname       string `json:"hostname"`
	MachineID      string `json:"machine_id"`
	DisplayName    string `json:"display_name"`
}

type HostnameInfo struct {
	HostnameNorm        string               `json:"hostname_norm"`
	DisplayName         string               `json:"display_name"`
	OwnerRegistrationID *int64               `json:"owner_registration_id,omitempty"`
	OwnerMachineID      string               `json:"owner_machine_id,omitempty"`
	OwnerDisplayName    string               `json:"owner_display_name,omitempty"`
	Competing           []HostnameCompetitor `json:"competing"`
}

type MachineDetail struct {
	Machine       MachineSummary     `json:"machine"`
	Registrations []RegistrationInfo `json:"registrations"`
	Users         []MachineUserInfo  `json:"users"`
	Sources       []SourceStateInfo  `json:"sources"`
	CSP           map[string]any     `json:"csp"`
	Reports       []ReportInfo       `json:"reports"`
	Events        []EventInfo        `json:"events"`
	Jobs          []JobInfo          `json:"jobs"`
	Hostnames     []HostnameInfo     `json:"hostnames"`
}

func (s *Store) MachineDetail(ctx context.Context, machineID string) (*MachineDetail, error) {
	page, err := s.ListMachines(ctx, AdminMachineFilter{MachineID: machineID, Page: 1, PageSize: 1})
	if err != nil {
		return nil, err
	}
	if len(page.Items) == 0 {
		return nil, sql.ErrNoRows
	}
	detail := &MachineDetail{Machine: page.Items[0], Registrations: []RegistrationInfo{}, Users: []MachineUserInfo{}, Sources: []SourceStateInfo{}, Reports: []ReportInfo{}, Events: []EventInfo{}, Jobs: []JobInfo{}, Hostnames: []HostnameInfo{}, CSP: map[string]any{}}
	rows, err := s.DB.QueryContext(ctx, `
SELECT registration_id, uuid, hostname, state, public_key_sha256, created_at, last_seen_at, last_source_ip, last_dns_status,
       previous_registration_id, replaced_by_registration_id, revoked_at
FROM dbo.registrations WHERE machine_id=@p1 ORDER BY registration_id`, machineID)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var item RegistrationInfo
		var uuid mssql.UniqueIdentifier
		var lastSeen, revoked sql.NullTime
		var ip []byte
		var dns sql.NullString
		var prev, replaced sql.NullInt64
		if err := rows.Scan(&item.RegistrationID, &uuid, &item.Hostname, &item.State, &item.KeyFingerprint, &item.CreatedAt, &lastSeen, &ip, &dns, &prev, &replaced, &revoked); err != nil {
			rows.Close()
			return nil, err
		}
		item.UUID = uuidString(uuid)
		item.LastSeenAt = nullTime(lastSeen)
		item.RevokedAt = nullTime(revoked)
		item.SourceIP = ipString(ip)
		item.DNSStatus = nullString(dns)
		if prev.Valid {
			item.PreviousID = &prev.Int64
		}
		if replaced.Valid {
			item.ReplacedByID = &replaced.Int64
		}
		detail.Registrations = append(detail.Registrations, item)
	}
	rows.Close()
	userRows, err := s.DB.QueryContext(ctx, `
SELECT machine_user_id, sid, name, profile_path, loaded, present, first_seen_at, last_seen_at
FROM dbo.machine_users WHERE machine_id=@p1 ORDER BY name`, machineID)
	if err != nil {
		return nil, err
	}
	for userRows.Next() {
		var item MachineUserInfo
		var path sql.NullString
		if err := userRows.Scan(&item.MachineUserID, &item.SID, &item.Name, &path, &item.Loaded, &item.Present, &item.FirstSeenAt, &item.LastSeenAt); err != nil {
			userRows.Close()
			return nil, err
		}
		item.ProfilePath = nullString(path)
		detail.Users = append(detail.Users, item)
	}
	userRows.Close()
	sourceRows, err := s.DB.QueryContext(ctx, `
SELECT source_type, source_key, last_scan_seq, last_complete, last_collected_at, last_report_id
FROM dbo.source_states WHERE machine_id=@p1 ORDER BY source_type, source_key`, machineID)
	if err != nil {
		return nil, err
	}
	for sourceRows.Next() {
		var item SourceStateInfo
		var report mssql.UniqueIdentifier
		if err := sourceRows.Scan(&item.SourceType, &item.SourceKey, &item.LastScanSeq, &item.LastComplete, &item.LastCollectedAt, &report); err != nil {
			sourceRows.Close()
			return nil, err
		}
		item.LastReportID = uuidString(report)
		detail.Sources = append(detail.Sources, item)
	}
	sourceRows.Close()
	csp, err := s.cspInfo(ctx, machineID)
	if err == nil && csp != nil {
		detail.CSP = csp
	}
	reportRows, err := s.DB.QueryContext(ctx, `
SELECT TOP 20 report_id, scan_seq, status, applied, applied_sources, collected_at, received_at
FROM dbo.reports WHERE machine_id=@p1 ORDER BY scan_seq DESC`, machineID)
	if err != nil {
		return nil, err
	}
	for reportRows.Next() {
		var item ReportInfo
		var id mssql.UniqueIdentifier
		if err := reportRows.Scan(&id, &item.ScanSeq, &item.Status, &item.Applied, &item.AppliedSources, &item.CollectedAt, &item.ReceivedAt); err != nil {
			reportRows.Close()
			return nil, err
		}
		item.ReportID = uuidString(id)
		detail.Reports = append(detail.Reports, item)
	}
	reportRows.Close()
	detail.Events, _ = s.listEventsForMachine(ctx, machineID, 30)
	detail.Jobs, _ = s.listJobsForMachine(ctx, machineID, 30)
	if len(detail.Reports) > 0 {
		latestSeq := detail.Reports[0].ScanSeq
		for i := range detail.Sources {
			detail.Sources[i].Stale = detail.Sources[i].LastScanSeq < latestSeq
		}
	}
	detail.Hostnames, _ = s.ListHostnames(ctx)
	filtered := detail.Hostnames[:0]
	for _, h := range detail.Hostnames {
		if h.OwnerMachineID == machineID || hostnameInRegistrations(h.HostnameNorm, detail.Registrations) || len(h.Competing) > 0 {
			filtered = append(filtered, h)
		}
	}
	detail.Hostnames = filtered
	return detail, nil
}

func hostnameInRegistrations(norm string, regs []RegistrationInfo) bool {
	for _, r := range regs {
		if strings.EqualFold(r.Hostname, norm) {
			return true
		}
	}
	return false
}

func (s *Store) cspInfo(ctx context.Context, machineID string) (map[string]any, error) {
	var scanned, complete, present bool
	var product, core, kind, raw, source, state, validRaw, validUTC, basis, term, trial, src, errText, products, lastAttemptError, collected sql.NullString
	var lastSeq sql.NullInt64
	err := s.DB.QueryRowContext(ctx, `
SELECT scanned, complete, present, product_version, core_version, license_kind, license_kind_raw, license_kind_source,
       license_state, CONVERT(nvarchar(33), valid_to_utc, 127), valid_to_raw, time_basis, term_kind, is_trial, source, error,
       products_json, last_scan_seq, CONVERT(nvarchar(33), collected_at, 127), last_attempt_error
FROM dbo.csp_states WHERE machine_id=@p1`, machineID).Scan(&scanned, &complete, &present, &product, &core, &kind, &raw, &source, &state, &validUTC, &validRaw, &basis, &term, &trial, &src, &errText, &products, &lastSeq, &collected, &lastAttemptError)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return map[string]any{
		"scanned": scanned, "complete": complete, "present": present,
		"product_version": nullString(product), "core_version": nullString(core),
		"license_kind": nullString(kind), "license_kind_raw": nullString(raw), "license_kind_source": nullString(source),
		"license_state": nullString(state), "valid_to_utc": nullString(validUTC), "valid_to_raw": nullString(validRaw),
		"time_basis": nullString(basis), "term_kind": nullString(term), "is_trial": nullString(trial),
		"source": nullString(src), "error": nullString(errText), "products_json": nullString(products),
		"last_scan_seq": lastSeq.Int64, "collected_at": nullString(collected), "last_attempt_error": nullString(lastAttemptError),
	}, nil
}

func (s *Store) listEventsForMachine(ctx context.Context, machineID string, limit int) ([]EventInfo, error) {
	rows, err := s.DB.QueryContext(ctx, `
SELECT TOP (@p1) event_id, machine_id, kind, severity, message, details_json, created_at
FROM dbo.events WHERE machine_id=@p2 ORDER BY created_at DESC`, limit, machineID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []EventInfo{}
	for rows.Next() {
		var item EventInfo
		var mid mssql.NullUniqueIdentifier
		var details sql.NullString
		if err := rows.Scan(&item.EventID, &mid, &item.Kind, &item.Severity, &item.Message, &details, &item.CreatedAt); err != nil {
			return nil, err
		}
		item.MachineID = nullUUIDString(mid)
		item.Details = nullString(details)
		out = append(out, item)
	}
	return out, rows.Err()
}

func (s *Store) listJobsForMachine(ctx context.Context, machineID string, limit int) ([]JobInfo, error) {
	rows, err := s.DB.QueryContext(ctx, `
SELECT TOP (@p1) job_id, machine_id, kind, state, created_at, delivered_at, completed_at, report_id, message
FROM dbo.jobs WHERE machine_id=@p2 ORDER BY created_at DESC`, limit, machineID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []JobInfo{}
	for rows.Next() {
		var item JobInfo
		var id, mid mssql.UniqueIdentifier
		var delivered, completed sql.NullTime
		var report mssql.NullUniqueIdentifier
		var message sql.NullString
		if err := rows.Scan(&id, &mid, &item.Kind, &item.State, &item.CreatedAt, &delivered, &completed, &report, &message); err != nil {
			return nil, err
		}
		item.JobID = uuidString(id)
		item.MachineID = uuidString(mid)
		item.DeliveredAt = nullTime(delivered)
		item.CompletedAt = nullTime(completed)
		item.ReportID = nullUUIDString(report)
		item.Message = nullString(message)
		out = append(out, item)
	}
	return out, rows.Err()
}

func (s *Store) ListHostnames(ctx context.Context) ([]HostnameInfo, error) {
	rows, err := s.DB.QueryContext(ctx, `
SELECT h.hostname_norm, h.display_name, h.owner_registration_id, h.owner_machine_id, COALESCE(m.display_name,'')
FROM dbo.hostnames h LEFT JOIN dbo.machines m ON m.machine_id=h.owner_machine_id
ORDER BY h.hostname_norm`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []HostnameInfo{}
	for rows.Next() {
		var item HostnameInfo
		var owner sql.NullInt64
		var ownerMachine mssql.NullUniqueIdentifier
		if err := rows.Scan(&item.HostnameNorm, &item.DisplayName, &owner, &ownerMachine, &item.OwnerDisplayName); err != nil {
			return nil, err
		}
		if owner.Valid {
			item.OwnerRegistrationID = &owner.Int64
		}
		item.OwnerMachineID = nullUUIDString(ownerMachine)
		compRows, err := s.DB.QueryContext(ctx, `
SELECT r.registration_id, r.uuid, r.hostname, r.machine_id, m.display_name
FROM dbo.registrations r JOIN dbo.machines m ON m.machine_id=r.machine_id
WHERE r.hostname_norm=@p1 AND r.state='active' AND (@p2 IS NULL OR r.registration_id<>@p2)
ORDER BY r.registration_id`, item.HostnameNorm, owner)
		if err != nil {
			return nil, err
		}
		for compRows.Next() {
			var c HostnameCompetitor
			var id mssql.UniqueIdentifier
			var mid mssql.UniqueIdentifier
			if err := compRows.Scan(&c.RegistrationID, &id, &c.Hostname, &mid, &c.DisplayName); err != nil {
				compRows.Close()
				return nil, err
			}
			c.UUID = uuidString(id)
			c.MachineID = uuidString(mid)
			item.Competing = append(item.Competing, c)
		}
		compRows.Close()
		if item.Competing == nil {
			item.Competing = []HostnameCompetitor{}
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

// RevokeRegistration marks an active registration as revoked after an
// explicit administrator decision. The agent cannot revive it; a new key and
// registration are required. Hostname ownership is released so the admin can
// reassign it to the replacement machine without leaving a phantom conflict.
func (s *Store) RevokeRegistration(ctx context.Context, registrationID int64, admin string) error {
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var machineID mssql.UniqueIdentifier
	var hostname, state string
	if err := tx.QueryRowContext(ctx, `SELECT machine_id, hostname, state FROM dbo.registrations WITH (UPDLOCK,HOLDLOCK) WHERE registration_id=@p1`, registrationID).Scan(&machineID, &hostname, &state); err != nil {
		return fmt.Errorf("load registration: %w", err)
	}
	if state != "active" {
		return fmt.Errorf("registration is not active")
	}
	now := s.now()
	if _, err := tx.ExecContext(ctx, `UPDATE dbo.registrations SET state=N'revoked', revoked_at=@p1 WHERE registration_id=@p2`, now, registrationID); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE dbo.hostnames SET owner_registration_id=NULL, owner_machine_id=NULL WHERE owner_registration_id=@p1`, registrationID); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `
INSERT INTO dbo.events(machine_id,registration_id,kind,severity,message,details_json,created_at)
VALUES(@p1,@p2,N'registration_revoked',N'warning',N'administrator revoked the agent registration',@p3,@p4)`,
		uuidString(machineID), registrationID, fmt.Sprintf(`{"hostname":%q,"admin":%q}`, hostname, admin), now); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) AssignHostname(ctx context.Context, hostnameNorm string, registrationID int64, admin string) error {
	hostnameNorm = strings.ToLower(strings.TrimSpace(hostnameNorm))
	if hostnameNorm == "" {
		return fmt.Errorf("hostname is required")
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var machineID mssql.UniqueIdentifier
	var hostname string
	var state string
	if err := tx.QueryRowContext(ctx, `SELECT machine_id, hostname, state FROM dbo.registrations WITH (UPDLOCK,HOLDLOCK) WHERE registration_id=@p1`, registrationID).Scan(&machineID, &hostname, &state); err != nil {
		return fmt.Errorf("load registration: %w", err)
	}
	if state != "active" {
		return fmt.Errorf("registration is not active")
	}
	var exists int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(1) FROM dbo.hostnames WHERE hostname_norm=@p1`, hostnameNorm).Scan(&exists); err != nil {
		return err
	}
	if exists == 0 {
		_, err = tx.ExecContext(ctx, `INSERT INTO dbo.hostnames(hostname_norm,display_name,owner_registration_id,owner_machine_id,reserved_at,last_seen_at) VALUES(@p1,@p2,@p3,@p4,@p5,@p5)`, hostnameNorm, hostname, registrationID, uuidString(machineID), s.now())
	} else {
		_, err = tx.ExecContext(ctx, `UPDATE dbo.hostnames SET display_name=@p1, owner_registration_id=@p2, owner_machine_id=@p3, reserved_at=@p4 WHERE hostname_norm=@p5`, hostname, registrationID, uuidString(machineID), s.now(), hostnameNorm)
	}
	if err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `
INSERT INTO dbo.events(machine_id,kind,severity,message,details_json,created_at)
VALUES(@p1,N'hostname_assigned',N'info',N'administrator assigned hostname reservation',@p2,@p3)`,
		uuidString(machineID), fmt.Sprintf(`{"hostname":%q,"registration_id":%d,"admin":%q}`, hostnameNorm, registrationID, admin), s.now()); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) RebindRegistrationKey(ctx context.Context, machineID string, registrationID int64, publicKeyPEM, admin string) (string, error) {
	pub, err := protocol.ParsePublicKeyPEM(publicKeyPEM)
	if err != nil {
		return "", err
	}
	fingerprint, err := protocol.PublicKeyFingerprint(pub)
	if err != nil {
		return "", err
	}
	normalized, err := protocol.MarshalPublicKeyPEM(pub)
	if err != nil {
		return "", err
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return "", err
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(ctx, `
UPDATE dbo.registrations SET public_key_pem=@p1, public_key_sha256=@p2
WHERE registration_id=@p3 AND machine_id=@p4 AND state='active'`, normalized, fingerprint, registrationID, machineID)
	if err != nil {
		return "", err
	}
	affected, _ := result.RowsAffected()
	if affected == 0 {
		return "", fmt.Errorf("active registration not found for this machine")
	}
	if _, err := tx.ExecContext(ctx, `
INSERT INTO dbo.events(machine_id,registration_id,kind,severity,message,details_json,created_at)
VALUES(@p1,@p2,N'key_rebound',N'warning',N'administrator rebound the agent public key',@p3,@p4)`,
		machineID, registrationID, fmt.Sprintf(`{"key_fingerprint":%q,"admin":%q}`, fingerprint, admin), s.now()); err != nil {
		return "", err
	}
	if err := tx.Commit(); err != nil {
		return "", err
	}
	return fingerprint, nil
}

// Overview is the admin dashboard summary.
type AdminOverview struct {
	Machines            int        `json:"machines"`
	ActiveRegistrations int        `json:"active_registrations"`
	Users               int        `json:"users"`
	Certificates        int        `json:"certificates"`
	ActiveObservations  int        `json:"active_observations"`
	PendingJobs         int        `json:"pending_jobs"`
	Events24h           int        `json:"events_24h"`
	Reports24h          int        `json:"reports_24h"`
	LastReportAt        *time.Time `json:"last_report_at,omitempty"`
	ConfigVersion       int        `json:"config_version"`
	ConfigHash          string     `json:"config_hash"`
	DBOK                bool       `json:"db_ok"`
}

func (s *Store) AdminOverview(ctx context.Context) (AdminOverview, error) {
	var out AdminOverview
	queries := []struct {
		target *int
		query  string
	}{
		{&out.Machines, `SELECT COUNT(*) FROM dbo.machines`},
		{&out.ActiveRegistrations, `SELECT COUNT(*) FROM dbo.registrations WHERE state='active'`},
		{&out.Users, `SELECT COUNT(*) FROM dbo.machine_users WHERE present=1`},
		{&out.Certificates, `SELECT COUNT(*) FROM dbo.certificates`},
		{&out.ActiveObservations, `SELECT COUNT(*) FROM dbo.certificate_observations WHERE active=1`},
		{&out.PendingJobs, `SELECT COUNT(*) FROM dbo.jobs WHERE state IN ('pending','delivered')`},
		{&out.Events24h, `SELECT COUNT(*) FROM dbo.events WHERE created_at > DATEADD(day,-1,SYSUTCDATETIME())`},
		{&out.Reports24h, `SELECT COUNT(*) FROM dbo.reports WHERE received_at > DATEADD(day,-1,SYSUTCDATETIME())`},
	}
	for _, q := range queries {
		if err := s.DB.QueryRowContext(ctx, q.query).Scan(q.target); err != nil {
			return out, err
		}
	}
	var last sql.NullTime
	if err := s.DB.QueryRowContext(ctx, `SELECT MAX(received_at) FROM dbo.reports`).Scan(&last); err != nil {
		return out, err
	}
	out.LastReportAt = nullTime(last)
	var version int
	var hash string
	if err := s.DB.QueryRowContext(ctx, `SELECT version, config_hash FROM dbo.configs WHERE config_id=1`).Scan(&version, &hash); err != nil {
		return out, err
	}
	out.ConfigVersion = version
	out.ConfigHash = strings.TrimSpace(hash)
	out.DBOK = s.DB.PingContext(ctx) == nil
	return out, nil
}

// ListCertificates -------------------------------------------------------------

type CertificateSummary struct {
	Organization    string     `json:"organization,omitempty"`
	Department      string     `json:"department,omitempty"`
	IssuerCN        string     `json:"issuer_cn,omitempty"`
	SHA256          string     `json:"sha256"`
	SerialHex       string     `json:"serial_hex"`
	SerialNumber    string     `json:"serial_number"`
	Subject         string     `json:"subject"`
	Issuer          string     `json:"issuer"`
	OwnerCN         string     `json:"owner_cn,omitempty"`
	INN             string     `json:"inn,omitempty"`
	SNILS           string     `json:"snils,omitempty"`
	NotBefore       *time.Time `json:"not_before,omitempty"`
	NotAfter        *time.Time `json:"not_after,omitempty"`
	EmbeddedLicense string     `json:"embedded_license,omitempty"`
	CreatedAt       time.Time  `json:"created_at"`
	UpdatedAt       time.Time  `json:"updated_at"`
	Machines        int        `json:"machines"`
	Observations    int        `json:"observations"`
	Active          bool       `json:"active"`
}

type CertificateObservationInfo struct {
	ObservationID int64      `json:"observation_id"`
	MachineID     string     `json:"machine_id"`
	MachineName   string     `json:"machine_name"`
	UserSID       string     `json:"user_sid,omitempty"`
	UserName      string     `json:"user_name,omitempty"`
	SourceType    string     `json:"source_type"`
	SourceKey     string     `json:"source_key"`
	FilePath      string     `json:"file_path,omitempty"`
	Active        bool       `json:"active"`
	FirstSeenAt   time.Time  `json:"first_seen_at"`
	LastSeenAt    time.Time  `json:"last_seen_at"`
	RemovedAt     *time.Time `json:"removed_at,omitempty"`
	LastReportID  string     `json:"last_report_id"`
}

type CertificateDetail struct {
	Certificate  CertificateSummary           `json:"certificate"`
	Observations []CertificateObservationInfo `json:"observations"`
}

func (s *Store) ListCertificates(ctx context.Context, query, status string, page, pageSize int) (Page[CertificateSummary], error) {
	page, pageSize = normalizePage(page, pageSize)
	where := []string{"1=1"}
	args := []any{}
	add := func(format string, values ...any) {
		placeholders := make([]any, len(values))
		for i := range values {
			placeholders[i] = len(args) + i + 1
		}
		where = append(where, fmt.Sprintf(format, placeholders...))
		args = append(args, values...)
	}
	if q := strings.TrimSpace(query); q != "" {
		like := "%" + q + "%"
		add("(c.subject LIKE @p%d OR c.issuer LIKE @p%d OR c.serial_hex LIKE @p%d OR c.sha256 LIKE @p%d OR c.owner_cn LIKE @p%d)", like, like, like, like, like)
	}
	switch status {
	case "expired":
		where = append(where, "c.not_after IS NOT NULL AND c.not_after < SYSUTCDATETIME()")
	case "future":
		where = append(where, "c.not_before IS NOT NULL AND c.not_before > SYSUTCDATETIME()")
	case "valid":
		where = append(where, "c.not_before IS NOT NULL AND c.not_after IS NOT NULL AND c.not_before <= SYSUTCDATETIME() AND c.not_after >= SYSUTCDATETIME()")
	}
	base := ` FROM dbo.certificates c WHERE ` + strings.Join(where, " AND ")
	var total int
	if err := s.DB.QueryRowContext(ctx, "SELECT COUNT(1)"+base, args...).Scan(&total); err != nil {
		return Page[CertificateSummary]{}, err
	}
	queryArgs := append([]any(nil), args...)
	queryArgs = append(queryArgs, (page-1)*pageSize, pageSize)
	rows, err := s.DB.QueryContext(ctx, `
SELECT c.sha256,c.serial_hex,c.serial_number,c.subject,c.issuer,c.owner_cn,c.inn,c.snils,c.not_before,c.not_after,
       c.embedded_license,c.created_at,c.updated_at,c.der,
       (SELECT COUNT(DISTINCT o.machine_id) FROM dbo.certificate_observations o WHERE o.certificate_sha256=c.sha256 AND o.active=1),
       (SELECT COUNT(*) FROM dbo.certificate_observations o WHERE o.certificate_sha256=c.sha256 AND o.active=1)
`+base+fmt.Sprintf(` ORDER BY c.not_after DESC, c.sha256 OFFSET @p%d ROWS FETCH NEXT @p%d ROWS ONLY`, len(args)+1, len(args)+2), queryArgs...)
	if err != nil {
		return Page[CertificateSummary]{}, err
	}
	defer rows.Close()
	items := []CertificateSummary{}
	for rows.Next() {
		var item CertificateSummary
		var serial, serialNum, subject, issuer, cn, inn, snils, embedded sql.NullString
		var before, after sql.NullTime
		var machines, observations int
		var der []byte
		if err := rows.Scan(&item.SHA256, &serial, &serialNum, &subject, &issuer, &cn, &inn, &snils, &before, &after, &embedded, &item.CreatedAt, &item.UpdatedAt, &der, &machines, &observations); err != nil {
			return Page[CertificateSummary]{}, err
		}
		item.SerialHex = nullString(serial)
		item.SerialNumber = nullString(serialNum)
		item.Subject = nullString(subject)
		item.Issuer = nullString(issuer)
		item.OwnerCN = nullString(cn)
		if parsed, err := certparse.Parse(der); err == nil {
			item.Organization, _ = parsed.Subject.FindAttribute(asn1.ObjectIdentifier{2, 5, 4, 10})
			item.Department, _ = parsed.Subject.FindAttribute(asn1.ObjectIdentifier{2, 5, 4, 11})
			item.IssuerCN = parsed.Issuer.CommonName()
		}
		item.INN = nullString(inn)
		item.SNILS = nullString(snils)
		item.EmbeddedLicense = nullString(embedded)
		item.NotBefore = nullTime(before)
		item.NotAfter = nullTime(after)
		item.Machines = machines
		item.Observations = observations
		item.Active = observations > 0
		items = append(items, item)
	}
	return Page[CertificateSummary]{Items: items, Page: page, PageSize: pageSize, Total: total}, rows.Err()
}

func (s *Store) CertificateDetail(ctx context.Context, sha256 string) (*CertificateDetail, error) {
	sha256 = strings.ToLower(strings.TrimSpace(sha256))
	page, err := s.ListCertificates(ctx, sha256, "", 1, 100)
	if err != nil {
		return nil, err
	}
	var cert *CertificateSummary
	for i := range page.Items {
		if page.Items[i].SHA256 == sha256 {
			cert = &page.Items[i]
			break
		}
	}
	if cert == nil {
		return nil, sql.ErrNoRows
	}
	detail := &CertificateDetail{Certificate: *cert, Observations: []CertificateObservationInfo{}}
	rows, err := s.DB.QueryContext(ctx, `
SELECT o.observation_id,o.machine_id,m.display_name,o.machine_user_id,mu.sid,mu.name,o.source_type,o.source_key,
       o.file_path,o.active,o.first_seen_at,o.last_seen_at,o.removed_at,o.last_report_id
FROM dbo.certificate_observations o
JOIN dbo.machines m ON m.machine_id=o.machine_id
LEFT JOIN dbo.machine_users mu ON mu.machine_user_id=o.machine_user_id
WHERE o.certificate_sha256=@p1 ORDER BY o.active DESC, o.last_seen_at DESC`, sha256)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var item CertificateObservationInfo
		var mid, report mssql.UniqueIdentifier
		var userID sql.NullInt64
		var sid, name, path sql.NullString
		var removed sql.NullTime
		if err := rows.Scan(&item.ObservationID, &mid, &item.MachineName, &userID, &sid, &name, &item.SourceType, &item.SourceKey, &path, &item.Active, &item.FirstSeenAt, &item.LastSeenAt, &removed, &report); err != nil {
			return nil, err
		}
		item.MachineID = uuidString(mid)
		item.UserSID = nullString(sid)
		item.UserName = nullString(name)
		item.FilePath = nullString(path)
		item.RemovedAt = nullTime(removed)
		item.LastReportID = uuidString(report)
		detail.Observations = append(detail.Observations, item)
	}
	return detail, rows.Err()
}

// Licensing --------------------------------------------------------------------

type LicensingInfo struct {
	MachineID        string     `json:"machine_id"`
	DisplayName      string     `json:"display_name"`
	ProductVersion   string     `json:"product_version,omitempty"`
	CoreVersion      string     `json:"core_version,omitempty"`
	LicenseKind      string     `json:"license_kind,omitempty"`
	KindRaw          string     `json:"license_kind_raw,omitempty"`
	KindSource       string     `json:"license_kind_source,omitempty"`
	State            string     `json:"license_state,omitempty"`
	ValidToRaw       string     `json:"valid_to_raw,omitempty"`
	ValidToUTC       *time.Time `json:"valid_to_utc,omitempty"`
	TimeBasis        string     `json:"time_basis,omitempty"`
	TermKind         string     `json:"term_kind,omitempty"`
	IsTrial          string     `json:"is_trial,omitempty"`
	Source           string     `json:"source,omitempty"`
	Complete         bool       `json:"complete"`
	Error            string     `json:"error,omitempty"`
	LastAttemptError string     `json:"last_attempt_error,omitempty"`
	CollectedAt      *time.Time `json:"collected_at,omitempty"`
}

func (s *Store) ListLicensing(ctx context.Context, query, kind string, page, pageSize int) (Page[LicensingInfo], error) {
	page, pageSize = normalizePage(page, pageSize)
	where := []string{"1=1"}
	args := []any{}
	add := func(format string, values ...any) {
		placeholders := make([]any, len(values))
		for i := range values {
			placeholders[i] = len(args) + i + 1
		}
		where = append(where, fmt.Sprintf(format, placeholders...))
		args = append(args, values...)
	}
	if q := strings.TrimSpace(query); q != "" {
		like := "%" + q + "%"
		add("(m.display_name LIKE @p%d OR c.product_version LIKE @p%d OR c.core_version LIKE @p%d OR c.license_kind_raw LIKE @p%d)", like, like, like, like)
	}
	switch kind {
	case "client", "server", "unknown":
		add("c.license_kind=@p%d", kind)
	}
	base := ` FROM dbo.csp_states c JOIN dbo.machines m ON m.machine_id=c.machine_id WHERE ` + strings.Join(where, " AND ")
	var total int
	if err := s.DB.QueryRowContext(ctx, "SELECT COUNT(1)"+base, args...).Scan(&total); err != nil {
		return Page[LicensingInfo]{}, err
	}
	queryArgs := append([]any(nil), args...)
	queryArgs = append(queryArgs, (page-1)*pageSize, pageSize)
	rows, err := s.DB.QueryContext(ctx, `
SELECT m.machine_id,m.display_name,c.product_version,c.core_version,c.license_kind,c.license_kind_raw,c.license_kind_source,
       c.license_state,c.valid_to_raw,c.valid_to_utc,c.time_basis,c.term_kind,c.is_trial,c.source,c.complete,c.error,c.last_attempt_error,c.collected_at
`+base+fmt.Sprintf(` ORDER BY m.display_name OFFSET @p%d ROWS FETCH NEXT @p%d ROWS ONLY`, len(args)+1, len(args)+2), queryArgs...)
	if err != nil {
		return Page[LicensingInfo]{}, err
	}
	defer rows.Close()
	items := []LicensingInfo{}
	for rows.Next() {
		var item LicensingInfo
		var mid mssql.UniqueIdentifier
		var product, core, kind, raw, source, state, validRaw, basis, term, trial, src, errText, lastAttempt sql.NullString
		var validUTC, collected sql.NullTime
		if err := rows.Scan(&mid, &item.DisplayName, &product, &core, &kind, &raw, &source, &state, &validRaw, &validUTC, &basis, &term, &trial, &src, &item.Complete, &errText, &lastAttempt, &collected); err != nil {
			return Page[LicensingInfo]{}, err
		}
		item.MachineID = uuidString(mid)
		item.ProductVersion = nullString(product)
		item.CoreVersion = nullString(core)
		item.LicenseKind = nullString(kind)
		item.KindRaw = nullString(raw)
		item.KindSource = nullString(source)
		item.State = nullString(state)
		item.ValidToRaw = nullString(validRaw)
		item.ValidToUTC = nullTime(validUTC)
		item.TimeBasis = nullString(basis)
		item.TermKind = nullString(term)
		item.IsTrial = nullString(trial)
		item.Source = nullString(src)
		item.Error = nullString(errText)
		item.LastAttemptError = nullString(lastAttempt)
		item.CollectedAt = nullTime(collected)
		items = append(items, item)
	}
	return Page[LicensingInfo]{Items: items, Page: page, PageSize: pageSize, Total: total}, rows.Err()
}

// Events and jobs --------------------------------------------------------------

func (s *Store) ListEvents(ctx context.Context, machineID, severity, query string, page, pageSize int) (Page[EventInfo], error) {
	page, pageSize = normalizePage(page, pageSize)
	where := []string{"1=1"}
	args := []any{}
	add := func(format string, values ...any) {
		placeholders := make([]any, len(values))
		for i := range values {
			placeholders[i] = len(args) + i + 1
		}
		where = append(where, fmt.Sprintf(format, placeholders...))
		args = append(args, values...)
	}
	if machineID != "" {
		add("e.machine_id=@p%d", machineID)
	}
	if severity != "" {
		add("e.severity=@p%d", severity)
	}
	if q := strings.TrimSpace(query); q != "" {
		like := "%" + q + "%"
		add("(e.kind LIKE @p%d OR e.message LIKE @p%d OR e.details_json LIKE @p%d)", like, like, like)
	}
	base := ` FROM dbo.events e WHERE ` + strings.Join(where, " AND ")
	var total int
	if err := s.DB.QueryRowContext(ctx, "SELECT COUNT(1)"+base, args...).Scan(&total); err != nil {
		return Page[EventInfo]{}, err
	}
	queryArgs := append([]any(nil), args...)
	queryArgs = append(queryArgs, (page-1)*pageSize, pageSize)
	rows, err := s.DB.QueryContext(ctx, `
SELECT e.event_id,e.machine_id,e.kind,e.severity,e.message,e.details_json,e.created_at
`+base+fmt.Sprintf(` ORDER BY e.created_at DESC OFFSET @p%d ROWS FETCH NEXT @p%d ROWS ONLY`, len(args)+1, len(args)+2), queryArgs...)
	if err != nil {
		return Page[EventInfo]{}, err
	}
	defer rows.Close()
	items := []EventInfo{}
	for rows.Next() {
		var item EventInfo
		var mid mssql.NullUniqueIdentifier
		var details sql.NullString
		if err := rows.Scan(&item.EventID, &mid, &item.Kind, &item.Severity, &item.Message, &details, &item.CreatedAt); err != nil {
			return Page[EventInfo]{}, err
		}
		item.MachineID = nullUUIDString(mid)
		item.Details = nullString(details)
		items = append(items, item)
	}
	return Page[EventInfo]{Items: items, Page: page, PageSize: pageSize, Total: total}, rows.Err()
}

func (s *Store) ListJobs(ctx context.Context, machineID, state string, page, pageSize int) (Page[JobInfo], error) {
	page, pageSize = normalizePage(page, pageSize)
	where := []string{"1=1"}
	args := []any{}
	add := func(format string, values ...any) {
		placeholders := make([]any, len(values))
		for i := range values {
			placeholders[i] = len(args) + i + 1
		}
		where = append(where, fmt.Sprintf(format, placeholders...))
		args = append(args, values...)
	}
	if machineID != "" {
		add("j.machine_id=@p%d", machineID)
	}
	if state != "" {
		add("j.state=@p%d", state)
	}
	base := ` FROM dbo.jobs j WHERE ` + strings.Join(where, " AND ")
	var total int
	if err := s.DB.QueryRowContext(ctx, "SELECT COUNT(1)"+base, args...).Scan(&total); err != nil {
		return Page[JobInfo]{}, err
	}
	queryArgs := append([]any(nil), args...)
	queryArgs = append(queryArgs, (page-1)*pageSize, pageSize)
	rows, err := s.DB.QueryContext(ctx, `
SELECT j.job_id,j.machine_id,j.kind,j.state,j.created_at,j.delivered_at,j.completed_at,j.report_id,j.message
`+base+fmt.Sprintf(` ORDER BY j.created_at DESC OFFSET @p%d ROWS FETCH NEXT @p%d ROWS ONLY`, len(args)+1, len(args)+2), queryArgs...)
	if err != nil {
		return Page[JobInfo]{}, err
	}
	defer rows.Close()
	items := []JobInfo{}
	for rows.Next() {
		var item JobInfo
		var id, mid mssql.UniqueIdentifier
		var delivered, completed sql.NullTime
		var report mssql.NullUniqueIdentifier
		var message sql.NullString
		if err := rows.Scan(&id, &mid, &item.Kind, &item.State, &item.CreatedAt, &delivered, &completed, &report, &message); err != nil {
			return Page[JobInfo]{}, err
		}
		item.JobID = uuidString(id)
		item.MachineID = uuidString(mid)
		item.DeliveredAt = nullTime(delivered)
		item.CompletedAt = nullTime(completed)
		item.ReportID = nullUUIDString(report)
		item.Message = nullString(message)
		items = append(items, item)
	}
	return Page[JobInfo]{Items: items, Page: page, PageSize: pageSize, Total: total}, rows.Err()
}
