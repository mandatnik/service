package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	mssql "github.com/microsoft/go-mssqldb"
	"telehack2026/internal/protocol"
)

// applyLicensesTx replaces the current license set for one machine. The
// integration API exposes only the current state; a newer complete CSP report
// removes rows for products that are no longer present. A nil list (old agent)
// leaves existing rows untouched; an explicitly empty list clears them.
func (s *Store) applyLicensesTx(ctx context.Context, tx *sql.Tx, identity *Identity, report *protocol.Report, now time.Time) *protocol.APIError {
	desired := make(map[string]protocol.LicenseInfo, len(report.CSP.Licenses))
	for _, license := range report.CSP.Licenses {
		desired[strings.ToLower(license.LicenseID)] = license
	}

	rows, err := tx.QueryContext(ctx, `
SELECT license_id, product FROM dbo.reported_licenses WITH (UPDLOCK, HOLDLOCK) WHERE machine_id=@p1`, identity.MachineID)
	if err != nil {
		return &protocol.APIError{Code: protocol.CodeDatabase, Message: "load current licenses"}
	}
	type existingLicense struct {
		licenseID string
		product   string
	}
	var existing []existingLicense
	for rows.Next() {
		var item existingLicense
		if err := rows.Scan(&item.licenseID, &item.product); err != nil {
			rows.Close()
			return &protocol.APIError{Code: protocol.CodeDatabase, Message: "decode current license"}
		}
		existing = append(existing, item)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return &protocol.APIError{Code: protocol.CodeDatabase, Message: "iterate current licenses"}
	}
	for _, item := range existing {
		if _, keep := desired[strings.ToLower(item.licenseID)]; keep {
			continue
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM dbo.reported_licenses WHERE license_id=@p1`, item.licenseID); err != nil {
			return &protocol.APIError{Code: protocol.CodeDatabase, Message: "remove obsolete license"}
		}
	}

	for _, license := range desired {
		if apiErr := s.upsertLicenseTx(ctx, tx, identity, report, license, now); apiErr != nil {
			return apiErr
		}
	}
	return nil
}

func (s *Store) upsertLicenseTx(ctx context.Context, tx *sql.Tx, identity *Identity, report *protocol.Report, license protocol.LicenseInfo, now time.Time) *protocol.APIError {
	licenseID := strings.ToLower(license.LicenseID)
	product := strings.ToLower(license.Product)
	if product == "" {
		product = "csp"
	}
	var existingMachine mssql.UniqueIdentifier
	err := tx.QueryRowContext(ctx, `SELECT machine_id FROM dbo.reported_licenses WITH (UPDLOCK, HOLDLOCK) WHERE license_id=@p1`, licenseID).Scan(&existingMachine)
	if err == nil && uuidString(existingMachine) != identity.MachineID {
		// Same serial on two machines is a conflict by the agreed uniqueness
		// rule. Keep the first record and surface the conflict for the admin.
		_ = insertEvent(ctx, tx, identity.MachineID, identity.RegistrationID, report.ReportID, nil,
			"license_serial_conflict", "warning", "same license serial is already registered on another machine",
			map[string]any{"license_id": licenseID, "existing_machine_id": uuidString(existingMachine)}, now)
		return nil
	}
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return &protocol.APIError{Code: protocol.CodeDatabase, Message: "check existing license"}
	}

	// One current license per product per machine: remove a previous serial
	// before inserting the replacement. The unique constraint also protects
	// this invariant.
	if _, err := tx.ExecContext(ctx, `
DELETE FROM dbo.reported_licenses WHERE machine_id=@p1 AND product=@p2 AND license_id<>@p3`,
		identity.MachineID, product, licenseID); err != nil {
		return &protocol.APIError{Code: protocol.CodeDatabase, Message: "replace previous license"}
	}

	var validTo any
	if license.ValidToUTC != "" {
		if parsed, parseErr := time.Parse(time.RFC3339, license.ValidToUTC); parseErr == nil {
			validTo = parsed.UTC()
		}
	}
	productName := license.ProductName
	if productName == "" {
		productName = licenseProductName(product)
	}
	_, err = tx.ExecContext(ctx, `
MERGE dbo.reported_licenses WITH (HOLDLOCK) AS target
USING (SELECT @p1 AS license_id) AS source
ON target.license_id=source.license_id
WHEN MATCHED THEN UPDATE SET
    machine_id=@p2, product=@p3, product_code=@p4, product_name=@p5,
    serial_masked=@p6, csp_version=@p7, product_version=@p8, core_version=@p9,
    license_kind=@p10, license_state=@p11, valid_to_utc=@p12, valid_to_raw=@p13,
    term_kind=@p14, is_trial=@p15, source=@p16, complete=@p17, error=@p18,
    last_attempt_error=@p19, collected_at=@p20, updated_at=@p21
WHEN NOT MATCHED THEN INSERT
    (license_id, machine_id, product, product_code, product_name, serial_masked,
     csp_version, product_version, core_version, license_kind, license_state,
     valid_to_utc, valid_to_raw, term_kind, is_trial, source, complete, error,
     last_attempt_error, collected_at, created_at, updated_at)
VALUES (@p1,@p2,@p3,@p4,@p5,@p6,@p7,@p8,@p9,@p10,@p11,@p12,@p13,@p14,@p15,@p16,
        @p17,@p18,@p19,@p20,@p21,@p21);`,
		licenseID, identity.MachineID, product, license.ProductCode, truncate(productName, 128),
		truncate(license.SerialMasked, 64), nilIfEmpty(report.CSP.ProductVersion), nilIfEmpty(report.CSP.ProductVersion),
		nilIfEmpty(report.CSP.CoreVersion), nilIfEmpty(license.Kind), nilIfEmpty(license.State),
		validTo, nilIfEmpty(license.ValidToRaw), nilIfEmpty(license.TermKind), nilIfEmpty(license.IsTrial),
		nilIfEmpty(license.Source), license.Complete, nilIfEmpty(license.Error), nilIfEmpty(license.Error),
		parseTimeOrZero(report.CollectedAt), now)
	if err != nil {
		return &protocol.APIError{Code: protocol.CodeDatabase, Message: "upsert license"}
	}
	return nil
}

func parseTrial(value string) *bool {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "true":
		result := true
		return &result
	case "false":
		result := false
		return &result
	default:
		return nil
	}
}

func licenseProductName(product string) string {
	switch product {
	case "csp":
		return "КриптоПро CSP"
	case "ocsp":
		return "КриптоПро OCSP Client"
	case "tsp":
		return "КриптоПро TSP Client"
	default:
		return product
	}
}

// IntegrationLicense is the flat representation returned by the integration
// API. It intentionally contains both canonical fields and deprecated aliases
// required by the C# SDK.
type IntegrationLicense struct {
	LicenseID         string     `json:"license_id"`
	MachineID         string     `json:"machine_id"`
	Hostname          string     `json:"hostname,omitempty"`
	DisplayName       string     `json:"display_name,omitempty"`
	SerialMasked      string     `json:"serial_masked"`
	Product           string     `json:"product"`
	ProductCode       int        `json:"product_code"`
	ProductName       string     `json:"product_name,omitempty"`
	CSPVersion        string     `json:"csp_version,omitempty"`
	ProductVersion    string     `json:"product_version,omitempty"`
	CoreVersion       string     `json:"core_version,omitempty"`
	LicenseKind       string     `json:"license_kind,omitempty"`
	Type              string     `json:"type,omitempty"`
	LicenseState      string     `json:"license_state"`
	Status            string     `json:"status"`
	ValidToUTC        *time.Time `json:"valid_to_utc,omitempty"`
	ExpiresAt         *time.Time `json:"expires_at,omitempty"`
	ValidToRaw        string     `json:"valid_to_raw,omitempty"`
	TermKind          string     `json:"term_kind,omitempty"`
	IsTrial           *bool      `json:"is_trial,omitempty"`
	Source            string     `json:"source,omitempty"`
	Complete          bool       `json:"complete"`
	Error             string     `json:"error,omitempty"`
	LastAttemptError  string     `json:"last_attempt_error,omitempty"`
	CollectedAt       *time.Time `json:"collected_at,omitempty"`
	CreatedAt         time.Time  `json:"created_at"`
	UpdatedAt         time.Time  `json:"updated_at"`
	CSPProductVersion string     `json:"csp_product_version,omitempty"`
	CSPCoreVersion    string     `json:"csp_core_version,omitempty"`
}

func (l IntegrationLicense) withAliases() IntegrationLicense {
	l.Type = l.LicenseKind
	l.Status = l.LicenseState
	l.ExpiresAt = l.ValidToUTC
	l.CSPProductVersion = l.CSPVersion
	l.CSPCoreVersion = l.CoreVersion
	return l
}

func scanIntegrationLicense(scanner interface {
	Scan(dest ...any) error
}) (IntegrationLicense, error) {
	var item IntegrationLicense
	var machineID mssql.UniqueIdentifier
	var validTo, collected sql.NullTime
	var hostname, displayName, productName, cspVersion, productVersion, coreVersion sql.NullString
	var kind, state, validRaw, term, trial, source, errText, lastAttempt sql.NullString
	if err := scanner.Scan(
		&item.LicenseID, &machineID, &hostname, &displayName, &item.SerialMasked,
		&item.Product, &item.ProductCode, &productName, &cspVersion, &productVersion,
		&coreVersion, &kind, &state, &validTo, &validRaw, &term, &trial, &source,
		&item.Complete, &errText, &lastAttempt, &collected, &item.CreatedAt, &item.UpdatedAt,
	); err != nil {
		return item, err
	}
	item.MachineID = uuidString(machineID)
	item.Hostname = nullString(hostname)
	item.DisplayName = nullString(displayName)
	item.ProductName = nullString(productName)
	item.CSPVersion = nullString(cspVersion)
	item.ProductVersion = nullString(productVersion)
	item.CoreVersion = nullString(coreVersion)
	item.LicenseKind = nullString(kind)
	item.LicenseState = nullString(state)
	item.ValidToUTC = nullTime(validTo)
	item.ValidToRaw = nullString(validRaw)
	item.TermKind = nullString(term)
	item.IsTrial = parseTrial(nullString(trial))
	item.Source = nullString(source)
	item.Error = nullString(errText)
	item.LastAttemptError = nullString(lastAttempt)
	item.CollectedAt = nullTime(collected)
	return item.withAliases(), nil
}

const integrationLicenseSelect = `
SELECT l.license_id, l.machine_id, r.hostname, m.display_name, l.serial_masked,
       l.product, l.product_code, l.product_name, l.csp_version, l.product_version,
       l.core_version, l.license_kind, l.license_state, l.valid_to_utc, l.valid_to_raw,
       l.term_kind, l.is_trial, l.source, l.complete, l.error, l.last_attempt_error,
       l.collected_at, l.created_at, l.updated_at
FROM dbo.reported_licenses l
JOIN dbo.machines m ON m.machine_id=l.machine_id
LEFT JOIN dbo.registrations r ON r.machine_id=m.machine_id AND r.state='active'`

func (s *Store) ListIntegrationLicenses(ctx context.Context, filter IntegrationLicenseFilter) (Page[IntegrationLicense], error) {
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
		add("l.machine_id=@p%d", filter.MachineID)
	}
	if filter.Product != "" {
		add("l.product=@p%d", filter.Product)
	}
	if filter.ProductCode >= 0 {
		add("l.product_code=@p%d", filter.ProductCode)
	}
	if filter.LicenseKind != "" {
		add("l.license_kind=@p%d", filter.LicenseKind)
	}
	if filter.IsTrial != "" {
		add("l.is_trial=@p%d", filter.IsTrial)
	}
	if filter.LicenseState != "" {
		add("l.license_state=@p%d", filter.LicenseState)
	}
	if query := strings.TrimSpace(filter.CSPVersion); query != "" {
		add("l.csp_version LIKE @p%d", "%"+query+"%")
	}
	base := integrationLicenseSelect + ` WHERE ` + strings.Join(where, " AND ")
	var total int
	if err := s.DB.QueryRowContext(ctx, "SELECT COUNT(1) FROM ("+base+") counted", args...).Scan(&total); err != nil {
		return Page[IntegrationLicense]{}, err
	}
	queryArgs := append([]any(nil), args...)
	queryArgs = append(queryArgs, (page-1)*pageSize, pageSize)
	rows, err := s.DB.QueryContext(ctx, base+fmt.Sprintf(` ORDER BY m.display_name, l.product OFFSET @p%d ROWS FETCH NEXT @p%d ROWS ONLY`, len(args)+1, len(args)+2), queryArgs...)
	if err != nil {
		return Page[IntegrationLicense]{}, err
	}
	defer rows.Close()
	items := []IntegrationLicense{}
	for rows.Next() {
		item, err := scanIntegrationLicense(rows)
		if err != nil {
			return Page[IntegrationLicense]{}, err
		}
		items = append(items, item)
	}
	return Page[IntegrationLicense]{Items: items, Page: page, PageSize: pageSize, Total: total}, rows.Err()
}

func (s *Store) GetIntegrationLicense(ctx context.Context, licenseID string) (*IntegrationLicense, error) {
	row := s.DB.QueryRowContext(ctx, integrationLicenseSelect+` WHERE l.license_id=@p1`, licenseID)
	item, err := scanIntegrationLicense(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, sql.ErrNoRows
	}
	if err != nil {
		return nil, err
	}
	return &item, nil
}

type IntegrationLicenseFilter struct {
	MachineID    string
	Product      string
	ProductCode  int // -1 means no filter
	LicenseKind  string
	IsTrial      string
	LicenseState string
	CSPVersion   string
	Page         int
	PageSize     int
}

func normalizeIntegrationPage(page, pageSize int) (int, int) {
	if page < 1 {
		page = 1
	}
	if pageSize < 1 {
		pageSize = 50
	}
	if pageSize > 500 {
		pageSize = 500
	}
	return page, pageSize
}
