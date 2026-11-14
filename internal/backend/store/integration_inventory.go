package store

import (
	"context"
	"database/sql"
	"encoding/asn1"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	mssql "github.com/microsoft/go-mssqldb"
	"telehack2026/internal/certparse"
	"telehack2026/internal/protocol"
)

// Integration API sentinel errors. The HTTP layer maps them to 400/404.
var (
	ErrUnknownMachine = errors.New("unknown machine")
	ErrGroupNotFound  = errors.New("group not found")
)

// IntegrationMachine is the machine representation used by the integration
// API. Admin-specific fields may be added without changing this structure.
type IntegrationMachine struct {
	MachineID          string     `json:"machine_id"`
	DisplayName        string     `json:"display_name"`
	Hostname           string     `json:"hostname,omitempty"`
	UUID               string     `json:"uuid,omitempty"`
	RegistrationState  string     `json:"registration_state,omitempty"`
	FirstSeen          *time.Time `json:"first_seen,omitempty"`
	LastSeen           *time.Time `json:"last_seen,omitempty"`
	Online             bool       `json:"online"`
	Offline            bool       `json:"offline"`
	OSVersion          string     `json:"os_version,omitempty"`
	AgentVersion       string     `json:"agent_version,omitempty"`
	Architecture       string     `json:"architecture,omitempty"`
	LicenseStatus      string     `json:"license_status"`
	CSPVersion         string     `json:"csp_version,omitempty"`
	ProductVersion     string     `json:"product_version,omitempty"`
	CoreVersion        string     `json:"core_version,omitempty"`
	LicenseKind        string     `json:"license_kind,omitempty"`
	LicenseState       string     `json:"license_state,omitempty"`
	TermKind           string     `json:"term_kind,omitempty"`
	IsTrial            *bool      `json:"is_trial,omitempty"`
	Users              int        `json:"users"`
	ActiveCertificates int        `json:"active_certificates"`
	GroupIDs           []string   `json:"group_ids"`
	SourceIP           string     `json:"source_ip,omitempty"`
	DNSStatus          string     `json:"dns_status,omitempty"`
	HostnameConflict   bool       `json:"hostname_conflict"`
	LastReportID       string     `json:"last_report_id,omitempty"`
	LastReportStatus   string     `json:"last_report_status,omitempty"`
	LastReportAt       *time.Time `json:"last_report_at,omitempty"`
	AppliedSources     int        `json:"applied_sources"`
}

// IntegrationMachineFilter is used by both the list and group-detail paths.
type IntegrationMachineFilter struct {
	Online                 *bool
	OnlineThresholdMinutes int
	LicenseStatus          string
	Hostname               string
	GroupID                string
	MachineIDs             []string
	Page                   int
	PageSize               int
}

const integrationLicenseStatusExpr = `CASE
    WHEN EXISTS (SELECT 1 FROM dbo.licenses l WHERE l.machine_id=m.machine_id AND l.product='csp' AND l.license_state='active') THEN 'active'
    WHEN EXISTS (SELECT 1 FROM dbo.licenses l WHERE l.machine_id=m.machine_id AND l.product='csp' AND l.license_state='expired') THEN 'expired'
    WHEN c.license_state='error' THEN 'error'
    WHEN c.scanned=1 AND c.present=0 THEN 'not_installed'
    ELSE 'unknown'
END`

const integrationMachineBase = `
SELECT m.machine_id, m.display_name, m.created_at,
       r.uuid, r.hostname, r.state AS registration_state,
       r.last_seen_at, r.last_source_ip, r.last_dns_status,
       r.agent_version, r.os_version, r.architecture,
       c.product_version, c.core_version, c.license_kind, c.license_state, c.term_kind, c.is_trial,
       rp.report_id AS last_report_id, rp.status AS last_report_status, rp.collected_at AS last_report_at,
       COALESCE(rp.applied_sources,0) AS applied_sources,
       (SELECT COUNT(*) FROM dbo.machine_users mu WHERE mu.machine_id=m.machine_id) AS users_count,
       (SELECT COUNT(*) FROM dbo.certificate_observations o WHERE o.machine_id=m.machine_id AND o.active=1) AS active_certificates,
       CASE WHEN r.last_seen_at IS NOT NULL AND r.last_seen_at >= DATEADD(minute,-@p1,SYSUTCDATETIME()) THEN 1 ELSE 0 END AS online,
       ` + integrationLicenseStatusExpr + ` AS license_status,
       CASE WHEN EXISTS (SELECT 1 FROM dbo.registrations r2 WHERE r2.hostname_norm=r.hostname_norm AND r2.state='active' AND r2.registration_id<>r.registration_id) THEN 1 ELSE 0 END AS hostname_conflict
FROM dbo.machines m
LEFT JOIN dbo.registrations r ON r.machine_id=m.machine_id AND r.state='active'
LEFT JOIN dbo.csp_states c ON c.machine_id=m.machine_id
OUTER APPLY (SELECT TOP 1 report_id,status,collected_at,applied_sources FROM dbo.reports rep WHERE rep.machine_id=m.machine_id ORDER BY rep.scan_seq DESC) rp`

func scanIntegrationMachine(scanner interface {
	Scan(dest ...any) error
}) (IntegrationMachine, error) {
	var item IntegrationMachine
	var created time.Time
	var uuid, reportID mssql.NullUniqueIdentifier
	var hostname, regState, agentVersion, osVersion, architecture sql.NullString
	var lastSeen, reportAt sql.NullTime
	var sourceIP []byte
	var dns, product, core, kind, state, term, trial, reportStatus sql.NullString
	var licenseStatus string
	var online, conflict, users, activeCertificates, applied int
	if err := scanner.Scan(
		&item.MachineID, &item.DisplayName, &created, &uuid, &hostname, &regState,
		&lastSeen, &sourceIP, &dns, &agentVersion, &osVersion, &architecture,
		&product, &core, &kind, &state, &term, &trial,
		&reportID, &reportStatus, &reportAt, &applied, &users, &activeCertificates,
		&online, &licenseStatus, &conflict,
	); err != nil {
		return item, err
	}
	item.FirstSeen = timePointer(created)
	item.UUID = nullUUIDString(uuid)
	item.Hostname = nullString(hostname)
	item.RegistrationState = nullString(regState)
	item.LastSeen = nullTime(lastSeen)
	item.SourceIP = ipString(sourceIP)
	item.DNSStatus = nullString(dns)
	item.AgentVersion = nullString(agentVersion)
	item.OSVersion = nullString(osVersion)
	item.Architecture = nullString(architecture)
	item.ProductVersion = nullString(product)
	item.CSPVersion = item.ProductVersion
	item.CoreVersion = nullString(core)
	item.LicenseKind = nullString(kind)
	item.LicenseState = nullString(state)
	item.TermKind = nullString(term)
	item.IsTrial = parseTrial(nullString(trial))
	item.LastReportID = nullUUIDString(reportID)
	item.LastReportStatus = nullString(reportStatus)
	item.LastReportAt = nullTime(reportAt)
	item.AppliedSources = applied
	item.Users = users
	item.ActiveCertificates = activeCertificates
	item.Online = online == 1
	item.Offline = !item.Online
	item.LicenseStatus = licenseStatus
	item.HostnameConflict = conflict == 1
	item.GroupIDs = []string{}
	return item, nil
}

func timePointer(value time.Time) *time.Time {
	utc := value.UTC()
	return &utc
}

func (s *Store) ListIntegrationMachines(ctx context.Context, filter IntegrationMachineFilter) (Page[IntegrationMachine], error) {
	page, pageSize := normalizeIntegrationPage(filter.Page, filter.PageSize)
	threshold := filter.OnlineThresholdMinutes
	if threshold < 1 {
		threshold = 30
	}
	if threshold > 1440 {
		threshold = 1440
	}
	args := []any{threshold}
	where := []string{"1=1"}
	add := func(format string, values ...any) {
		placeholders := make([]any, len(values))
		for index := range values {
			placeholders[index] = len(args) + index + 1
		}
		where = append(where, fmt.Sprintf(format, placeholders...))
		args = append(args, values...)
	}
	if filter.Online != nil {
		add("q.online=@p%d", boolInt(*filter.Online))
	}
	if filter.LicenseStatus != "" {
		add("q.license_status=@p%d", filter.LicenseStatus)
	}
	if query := strings.TrimSpace(filter.Hostname); query != "" {
		add("q.hostname LIKE @p%d", "%"+query+"%")
	}
	if filter.GroupID != "" {
		add("EXISTS (SELECT 1 FROM dbo.machine_group_members gm WHERE gm.machine_id=q.machine_id AND gm.group_id=@p%d)", filter.GroupID)
	}
	if len(filter.MachineIDs) > 0 {
		placeholders := make([]string, 0, len(filter.MachineIDs))
		for _, machineID := range filter.MachineIDs {
			placeholders = append(placeholders, fmt.Sprintf("@p%d", len(args)+1))
			args = append(args, machineID)
		}
		where = append(where, "q.machine_id IN ("+strings.Join(placeholders, ",")+")")
	}
	whereSQL := strings.Join(where, " AND ")
	countArgs := append([]any(nil), args...)
	var total int
	if err := s.DB.QueryRowContext(ctx,
		"SELECT COUNT(1) FROM ("+integrationMachineBase+") q WHERE "+whereSQL, countArgs...).Scan(&total); err != nil {
		return Page[IntegrationMachine]{}, err
	}
	queryArgs := append([]any(nil), args...)
	queryArgs = append(queryArgs, (page-1)*pageSize, pageSize)
	rows, err := s.DB.QueryContext(ctx,
		"SELECT * FROM ("+integrationMachineBase+") q WHERE "+whereSQL+
			fmt.Sprintf(" ORDER BY q.display_name, q.machine_id OFFSET @p%d ROWS FETCH NEXT @p%d ROWS ONLY", len(args)+1, len(args)+2),
		queryArgs...)
	if err != nil {
		return Page[IntegrationMachine]{}, err
	}
	defer rows.Close()
	items := []IntegrationMachine{}
	for rows.Next() {
		item, err := scanIntegrationMachine(rows)
		if err != nil {
			return Page[IntegrationMachine]{}, err
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return Page[IntegrationMachine]{}, err
	}
	if err := s.attachIntegrationGroups(ctx, items); err != nil {
		return Page[IntegrationMachine]{}, err
	}
	return Page[IntegrationMachine]{Items: items, Page: page, PageSize: pageSize, Total: total}, nil
}

func (s *Store) attachIntegrationGroups(ctx context.Context, items []IntegrationMachine) error {
	if len(items) == 0 {
		return nil
	}
	index := make(map[string]int, len(items))
	for position := range items {
		index[items[position].MachineID] = position
	}
	rows, err := s.DB.QueryContext(ctx, `
SELECT machine_id, group_id FROM dbo.machine_group_members
ORDER BY machine_id, group_id`)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var machineID, groupID mssql.UniqueIdentifier
		if err := rows.Scan(&machineID, &groupID); err != nil {
			return err
		}
		if position, ok := index[uuidString(machineID)]; ok {
			items[position].GroupIDs = append(items[position].GroupIDs, uuidString(groupID))
		}
	}
	return rows.Err()
}

func boolInt(value bool) int {
	if value {
		return 1
	}
	return 0
}

// IntegrationMachineDetails is the integration card shape.
type IntegrationMachineDetails struct {
	Machine       IntegrationMachine `json:"machine"`
	Registrations []RegistrationInfo `json:"registrations"`
	Users         []MachineUserInfo  `json:"users"`
	Sources       []SourceStateInfo  `json:"sources"`
	CSP           map[string]any     `json:"csp"`
	Reports       []ReportInfo       `json:"reports"`
	Events        []IntegrationEvent `json:"events"`
	Jobs          []IntegrationJob   `json:"jobs"`
	GroupIDs      []string           `json:"group_ids"`
	Hostnames     []HostnameInfo     `json:"hostnames"`
}

func (s *Store) IntegrationMachineDetail(ctx context.Context, machineID string) (*IntegrationMachineDetails, error) {
	detail, err := s.MachineDetail(ctx, machineID)
	if err != nil {
		return nil, err
	}
	page, err := s.ListIntegrationMachines(ctx, IntegrationMachineFilter{
		MachineIDs: []string{machineID}, OnlineThresholdMinutes: 30, Page: 1, PageSize: 1,
	})
	if err != nil {
		return nil, err
	}
	if len(page.Items) == 0 {
		return nil, sql.ErrNoRows
	}
	machine := page.Items[0]
	events := make([]IntegrationEvent, 0, len(detail.Events))
	for _, event := range detail.Events {
		events = append(events, integrationEventFrom(event))
	}
	jobs := make([]IntegrationJob, 0, len(detail.Jobs))
	for _, job := range detail.Jobs {
		jobs = append(jobs, integrationJobFrom(job))
	}
	csp := detail.CSP
	if csp == nil {
		csp = map[string]any{}
	}
	return &IntegrationMachineDetails{
		Machine: machine, Registrations: detail.Registrations, Users: detail.Users,
		Sources: detail.Sources, CSP: csp, Reports: detail.Reports, Events: events,
		Jobs: jobs, GroupIDs: machine.GroupIDs, Hostnames: detail.Hostnames,
	}, nil
}

// IntegrationCertificateFilter is the certificate list filter.
type IntegrationCertificateFilter struct {
	MachineID string
	Subject   string
	Serial    string
	Validity  string
	Page      int
	PageSize  int
}

func (s *Store) ListIntegrationCertificates(ctx context.Context, filter IntegrationCertificateFilter) (Page[CertificateSummary], error) {
	page, pageSize := normalizeIntegrationPage(filter.Page, filter.PageSize)
	where := []string{"1=1"}
	args := []any{}
	add := func(format string, values ...any) {
		placeholders := make([]any, len(values))
		for index := range values {
			placeholders[index] = len(args) + index + 1
		}
		where = append(where, fmt.Sprintf(format, placeholders...))
		args = append(args, values...)
	}
	if filter.MachineID != "" {
		add("EXISTS (SELECT 1 FROM dbo.certificate_observations o WHERE o.certificate_sha256=c.sha256 AND o.machine_id=@p%d AND o.active=1)", filter.MachineID)
	}
	if query := strings.TrimSpace(filter.Subject); query != "" {
		like := "%" + query + "%"
		add("(c.subject LIKE @p%d OR c.owner_cn LIKE @p%d)", like, like)
	}
	if serial := strings.TrimSpace(filter.Serial); serial != "" {
		add("(c.serial_number=@p%d OR c.serial_hex=@p%d)", serial, serial)
	}
	switch filter.Validity {
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
`+base+fmt.Sprintf(" ORDER BY c.not_after DESC, c.sha256 OFFSET @p%d ROWS FETCH NEXT @p%d ROWS ONLY", len(args)+1, len(args)+2), queryArgs...)
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

// IntegrationEvent is the event shape with parsed details.
type IntegrationEvent struct {
	EventID     int64     `json:"event_id"`
	Type        string    `json:"type"`
	Kind        string    `json:"kind"`
	Severity    string    `json:"severity"`
	Message     string    `json:"message"`
	MachineID   string    `json:"machine_id,omitempty"`
	Details     any       `json:"details,omitempty"`
	DetailsJSON string    `json:"details_json,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
}

func integrationEventFrom(event EventInfo) IntegrationEvent {
	out := IntegrationEvent{
		EventID: event.EventID, Type: event.Kind, Kind: event.Kind, Severity: event.Severity,
		Message: event.Message, MachineID: event.MachineID, DetailsJSON: event.Details, CreatedAt: event.CreatedAt,
	}
	if strings.TrimSpace(event.Details) != "" {
		var details any
		if json.Unmarshal([]byte(event.Details), &details) == nil {
			out.Details = details
		}
	}
	return out
}

type IntegrationEventFilter struct {
	Severity  string
	Type      string
	MachineID string
	Since     *time.Time
	Until     *time.Time
	Page      int
	PageSize  int
}

func (s *Store) ListIntegrationEvents(ctx context.Context, filter IntegrationEventFilter) (Page[IntegrationEvent], error) {
	page, pageSize := normalizeIntegrationPage(filter.Page, filter.PageSize)
	where := []string{"1=1"}
	args := []any{}
	add := func(format string, values ...any) {
		placeholders := make([]any, len(values))
		for index := range values {
			placeholders[index] = len(args) + index + 1
		}
		where = append(where, fmt.Sprintf(format, placeholders...))
		args = append(args, values...)
	}
	if filter.Severity != "" {
		add("e.severity=@p%d", filter.Severity)
	}
	if filter.Type != "" {
		add("e.kind=@p%d", filter.Type)
	}
	if filter.MachineID != "" {
		add("e.machine_id=@p%d", filter.MachineID)
	}
	if filter.Since != nil {
		add("e.created_at >= @p%d", *filter.Since)
	}
	if filter.Until != nil {
		add("e.created_at <= @p%d", *filter.Until)
	}
	base := ` FROM dbo.events e WHERE ` + strings.Join(where, " AND ")
	var total int
	if err := s.DB.QueryRowContext(ctx, "SELECT COUNT(1)"+base, args...).Scan(&total); err != nil {
		return Page[IntegrationEvent]{}, err
	}
	queryArgs := append([]any(nil), args...)
	queryArgs = append(queryArgs, (page-1)*pageSize, pageSize)
	rows, err := s.DB.QueryContext(ctx, `
SELECT e.event_id,e.machine_id,e.kind,e.severity,e.message,e.details_json,e.created_at
`+base+fmt.Sprintf(" ORDER BY e.created_at DESC OFFSET @p%d ROWS FETCH NEXT @p%d ROWS ONLY", len(args)+1, len(args)+2), queryArgs...)
	if err != nil {
		return Page[IntegrationEvent]{}, err
	}
	defer rows.Close()
	items := []IntegrationEvent{}
	for rows.Next() {
		var item IntegrationEvent
		var machineID mssql.NullUniqueIdentifier
		var details sql.NullString
		if err := rows.Scan(&item.EventID, &machineID, &item.Kind, &item.Severity, &item.Message, &details, &item.CreatedAt); err != nil {
			return Page[IntegrationEvent]{}, err
		}
		item.Type = item.Kind
		item.MachineID = nullUUIDString(machineID)
		item.DetailsJSON = nullString(details)
		if item.DetailsJSON != "" {
			var parsed any
			if json.Unmarshal([]byte(item.DetailsJSON), &parsed) == nil {
				item.Details = parsed
			}
		}
		items = append(items, item)
	}
	return Page[IntegrationEvent]{Items: items, Page: page, PageSize: pageSize, Total: total}, rows.Err()
}

// IntegrationJob is the job shape returned by the integration API.
type IntegrationJob struct {
	JobID       string     `json:"job_id"`
	MachineID   string     `json:"machine_id,omitempty"`
	Kind        string     `json:"kind"`
	Status      string     `json:"status"`
	State       string     `json:"state"`
	CreatedAt   time.Time  `json:"created_at"`
	DeliveredAt *time.Time `json:"delivered_at,omitempty"`
	CompletedAt *time.Time `json:"completed_at,omitempty"`
	ReportID    string     `json:"report_id,omitempty"`
	Message     string     `json:"message,omitempty"`
}

func integrationJobFrom(job JobInfo) IntegrationJob {
	return IntegrationJob{
		JobID: job.JobID, MachineID: job.MachineID, Kind: job.Kind, Status: job.State, State: job.State,
		CreatedAt: job.CreatedAt, DeliveredAt: job.DeliveredAt, CompletedAt: job.CompletedAt,
		ReportID: job.ReportID, Message: job.Message,
	}
}

type IntegrationJobFilter struct {
	MachineID string
	Status    string
	Page      int
	PageSize  int
}

func (s *Store) ListIntegrationJobs(ctx context.Context, filter IntegrationJobFilter) (Page[IntegrationJob], error) {
	page, pageSize := normalizeIntegrationPage(filter.Page, filter.PageSize)
	where := []string{"1=1"}
	args := []any{}
	add := func(format string, values ...any) {
		placeholders := make([]any, len(values))
		for index := range values {
			placeholders[index] = len(args) + index + 1
		}
		where = append(where, fmt.Sprintf(format, placeholders...))
		args = append(args, values...)
	}
	if filter.MachineID != "" {
		add("j.machine_id=@p%d", filter.MachineID)
	}
	if filter.Status != "" {
		add("j.state=@p%d", filter.Status)
	}
	base := ` FROM dbo.jobs j WHERE ` + strings.Join(where, " AND ")
	var total int
	if err := s.DB.QueryRowContext(ctx, "SELECT COUNT(1)"+base, args...).Scan(&total); err != nil {
		return Page[IntegrationJob]{}, err
	}
	queryArgs := append([]any(nil), args...)
	queryArgs = append(queryArgs, (page-1)*pageSize, pageSize)
	rows, err := s.DB.QueryContext(ctx, `
SELECT j.job_id,j.machine_id,j.kind,j.state,j.created_at,j.delivered_at,j.completed_at,j.report_id,j.message
`+base+fmt.Sprintf(" ORDER BY j.created_at DESC OFFSET @p%d ROWS FETCH NEXT @p%d ROWS ONLY", len(args)+1, len(args)+2), queryArgs...)
	if err != nil {
		return Page[IntegrationJob]{}, err
	}
	defer rows.Close()
	items := []IntegrationJob{}
	for rows.Next() {
		var id, machineID mssql.UniqueIdentifier
		var kind, state string
		var created time.Time
		var delivered, completed sql.NullTime
		var report mssql.NullUniqueIdentifier
		var message sql.NullString
		if err := rows.Scan(&id, &machineID, &kind, &state, &created, &delivered, &completed, &report, &message); err != nil {
			return Page[IntegrationJob]{}, err
		}
		items = append(items, IntegrationJob{
			JobID: uuidString(id), MachineID: uuidString(machineID), Kind: kind,
			Status: state, State: state, CreatedAt: created, DeliveredAt: nullTime(delivered),
			CompletedAt: nullTime(completed), ReportID: nullUUIDString(report), Message: nullString(message),
		})
	}
	return Page[IntegrationJob]{Items: items, Page: page, PageSize: pageSize, Total: total}, rows.Err()
}

func (s *Store) GetIntegrationJob(ctx context.Context, jobID string) (*IntegrationJob, error) {
	var id, machineID mssql.UniqueIdentifier
	var kind, state string
	var created time.Time
	var delivered, completed sql.NullTime
	var report mssql.NullUniqueIdentifier
	var message sql.NullString
	err := s.DB.QueryRowContext(ctx, `
SELECT job_id, machine_id, kind, state, created_at, delivered_at, completed_at, report_id, message
FROM dbo.jobs WHERE job_id=@p1`, jobID).Scan(&id, &machineID, &kind, &state, &created, &delivered, &completed, &report, &message)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, sql.ErrNoRows
	}
	if err != nil {
		return nil, err
	}
	item := IntegrationJob{
		JobID: uuidString(id), MachineID: uuidString(machineID), Kind: kind, Status: state, State: state,
		CreatedAt: created, DeliveredAt: nullTime(delivered), CompletedAt: nullTime(completed),
		ReportID: nullUUIDString(report), Message: nullString(message),
	}
	return &item, nil
}

// IntegrationScanResult is the 202/207 response body.
type IntegrationScanResult struct {
	Jobs    []IntegrationJob     `json:"jobs"`
	Skipped []IntegrationSkipped `json:"skipped"`
}

type IntegrationSkipped struct {
	MachineID string `json:"machine_id"`
	JobID     string `json:"job_id,omitempty"`
	Status    string `json:"status"`
	State     string `json:"state"`
}

// CreateIntegrationScanJobs creates scan jobs for a union of machine IDs and
// group members. Machines with an existing pending/delivered scan are skipped.
func (s *Store) CreateIntegrationScanJobs(ctx context.Context, machineIDs []string, groupID, actor string) (*IntegrationScanResult, error) {
	target := make(map[string]bool, len(machineIDs))
	for _, machineID := range machineIDs {
		target[strings.ToLower(machineID)] = true
	}
	if groupID != "" {
		var exists int
		if err := s.DB.QueryRowContext(ctx, `SELECT COUNT(1) FROM dbo.machine_groups WHERE group_id=@p1`, groupID).Scan(&exists); err != nil {
			return nil, err
		}
		if exists == 0 {
			return nil, ErrGroupNotFound
		}
		rows, err := s.DB.QueryContext(ctx, `SELECT machine_id FROM dbo.machine_group_members WHERE group_id=@p1`, groupID)
		if err != nil {
			return nil, err
		}
		for rows.Next() {
			var machineID mssql.UniqueIdentifier
			if err := rows.Scan(&machineID); err != nil {
				rows.Close()
				return nil, err
			}
			target[uuidString(machineID)] = true
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return nil, err
		}
	}
	if len(target) == 0 {
		return &IntegrationScanResult{Jobs: []IntegrationJob{}, Skipped: []IntegrationSkipped{}}, nil
	}
	ordered := make([]string, 0, len(target))
	for machineID := range target {
		ordered = append(ordered, machineID)
	}
	sort.Strings(ordered)
	for _, machineID := range ordered {
		var count int
		if err := s.DB.QueryRowContext(ctx, `SELECT COUNT(1) FROM dbo.machines WHERE machine_id=@p1`, machineID).Scan(&count); err != nil {
			return nil, err
		}
		if count == 0 {
			return nil, fmt.Errorf("%w: %s", ErrUnknownMachine, machineID)
		}
	}

	tx, err := s.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	result := &IntegrationScanResult{Jobs: []IntegrationJob{}, Skipped: []IntegrationSkipped{}}
	now := s.now()
	for _, machineID := range ordered {
		var existingID mssql.UniqueIdentifier
		var existingState string
		err := tx.QueryRowContext(ctx, `
SELECT TOP 1 job_id, state FROM dbo.jobs WITH (UPDLOCK, HOLDLOCK)
WHERE machine_id=@p1 AND kind=N'scan' AND state IN (N'pending',N'delivered')
ORDER BY created_at DESC`, machineID).Scan(&existingID, &existingState)
		if err == nil {
			result.Skipped = append(result.Skipped, IntegrationSkipped{
				MachineID: machineID, JobID: uuidString(existingID), Status: existingState, State: existingState,
			})
			continue
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return nil, err
		}
		jobID := protocol.NewUUID()
		if _, err := tx.ExecContext(ctx, `
INSERT INTO dbo.jobs (job_id, machine_id, kind, state, created_at, created_by)
VALUES (@p1,@p2,N'scan',N'pending',@p3,@p4)`, jobID, machineID, now, actor); err != nil {
			return nil, err
		}
		result.Jobs = append(result.Jobs, IntegrationJob{
			JobID: jobID, MachineID: machineID, Kind: "scan", Status: "pending", State: "pending", CreatedAt: now,
		})
		_ = insertEvent(ctx, tx, machineID, nil, nil, nil, "job_created", "info", "manual scan job created by integration", map[string]any{"job_id": jobID, "actor": actor}, now)
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return result, nil
}

// RemoveGroupMembers deletes memberships and writes an admin event.
func (s *Store) RemoveGroupMembers(ctx context.Context, groupID string, machineIDs []string, admin string) error {
	if err := validateUUID(groupID); err != nil {
		return err
	}
	if err := validateIDs(machineIDs); err != nil {
		return err
	}
	tx, err := s.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var exists int
	if err := tx.QueryRowContext(ctx, `SELECT 1 FROM dbo.machine_groups WITH(UPDLOCK,HOLDLOCK) WHERE group_id=@p1`, groupID).Scan(&exists); err != nil {
		return err
	}
	for _, machineID := range machineIDs {
		if _, err := tx.ExecContext(ctx, `DELETE FROM dbo.machine_group_members WHERE group_id=@p1 AND machine_id=@p2`, groupID, machineID); err != nil {
			return err
		}
	}
	if err := insertEvent(ctx, tx, nil, nil, nil, nil, "group_members_removed", "info", "machines removed from group", map[string]any{"id": groupID, "machines": machineIDs, "admin": admin}, s.now()); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) AddPolicyMachines(ctx context.Context, policyID string, machineIDs []string, admin string) error {
	return s.changePolicyAssignments(ctx, policyID, "machines", machineIDs, true, admin)
}

func (s *Store) RemovePolicyMachines(ctx context.Context, policyID string, machineIDs []string, admin string) error {
	return s.changePolicyAssignments(ctx, policyID, "machines", machineIDs, false, admin)
}

func (s *Store) AddPolicyGroups(ctx context.Context, policyID string, groupIDs []string, admin string) error {
	return s.changePolicyAssignments(ctx, policyID, "groups", groupIDs, true, admin)
}

func (s *Store) RemovePolicyGroups(ctx context.Context, policyID string, groupIDs []string, admin string) error {
	return s.changePolicyAssignments(ctx, policyID, "groups", groupIDs, false, admin)
}

func (s *Store) changePolicyAssignments(ctx context.Context, policyID, kind string, ids []string, add bool, admin string) error {
	if err := validateUUID(policyID); err != nil {
		return err
	}
	if err := validateIDs(ids); err != nil {
		return err
	}
	table := "folder_policy_machines"
	column := "machine_id"
	eventKind := "policy_machines_added"
	if kind == "groups" {
		table = "folder_policy_groups"
		column = "group_id"
		eventKind = "policy_groups_added"
	}
	if !add {
		eventKind = strings.Replace(eventKind, "added", "removed", 1)
	}
	tx, err := s.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var exists int
	if err := tx.QueryRowContext(ctx, `SELECT 1 FROM dbo.folder_policies WITH(UPDLOCK,HOLDLOCK) WHERE policy_id=@p1`, policyID).Scan(&exists); err != nil {
		return err
	}
	for _, id := range ids {
		var err error
		if add {
			_, err = tx.ExecContext(ctx, `IF NOT EXISTS(SELECT 1 FROM dbo.`+table+` WHERE policy_id=@p1 AND `+column+`=@p2) INSERT INTO dbo.`+table+`(policy_id,`+column+`) VALUES(@p1,@p2)`, policyID, id)
		} else {
			_, err = tx.ExecContext(ctx, `DELETE FROM dbo.`+table+` WHERE policy_id=@p1 AND `+column+`=@p2`, policyID, id)
		}
		if err != nil {
			return err
		}
	}
	if err := insertEvent(ctx, tx, nil, nil, nil, nil, eventKind, "info", "folder policy assignments changed", map[string]any{"id": policyID, "ids": ids, "admin": admin}, s.now()); err != nil {
		return err
	}
	return tx.Commit()
}
