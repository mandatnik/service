package protocol

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
)

// Report is the complete scan result for one collection sequence. ReportID,
// ScanSeq and CollectedAt duplicate the signed data fields intentionally so a
// stored report is self-describing; the server requires them to match.
type Report struct {
	ReportID         string          `json:"report_id"`
	ScanSeq          int64           `json:"scan_seq"`
	CollectedAt      string          `json:"collected_at"`
	StartedAt        string          `json:"started_at"`
	FinishedAt       string          `json:"finished_at"`
	AgentVersion     string          `json:"agent_version"`
	Hostname         string          `json:"hostname"`
	Status           string          `json:"status"`
	ProfilesComplete bool            `json:"profiles_complete"`
	Profiles         []ProfileResult `json:"profiles"`
	Sources          []SourceResult  `json:"sources"`
	CSP              CSPResult       `json:"csp"`
	Errors           []string        `json:"errors,omitempty"`
}

// ProfileResult describes one local user profile considered by the scan.
type ProfileResult struct {
	SID          string `json:"sid"`
	Name         string `json:"name"`
	ProfilePath  string `json:"profile_path"`
	Loaded       bool   `json:"loaded"`
	StorePresent bool   `json:"store_present"`
	Complete     bool   `json:"complete"`
	Error        string `json:"error,omitempty"`
}

// SourceResult is a single independently evaluated observation area: one
// user's personal store or one configured folder. Completeness is per source;
// a partial source never causes removal of previously known certificates.
type SourceResult struct {
	SourceType   string                `json:"source_type"`
	SourceKey    string                `json:"source_key"`
	DisplayName  string                `json:"display_name,omitempty"`
	UserSID      string                `json:"user_sid,omitempty"`
	Path         string                `json:"path,omitempty"`
	Complete     bool                  `json:"complete"`
	Error        string                `json:"error,omitempty"`
	Certificates []ObservedCertificate `json:"certificates"`
	Files        []ObservedFile        `json:"files,omitempty"`
}

// ObservedCertificate is one public certificate found in a source. Private
// keys and container names are never part of this structure.
type ObservedCertificate struct {
	SHA256             string `json:"sha256"`
	DERBase64          string `json:"der_base64"`
	SerialHex          string `json:"serial_hex"`
	SerialNumber       string `json:"serial_number"`
	Subject            string `json:"subject"`
	Issuer             string `json:"issuer"`
	NotBefore          string `json:"not_before"`
	NotAfter           string `json:"not_after"`
	OwnerCN            string `json:"owner_cn,omitempty"`
	INN                string `json:"inn,omitempty"`
	SNILS              string `json:"snils,omitempty"`
	PublicKeyBits      int    `json:"public_key_bits,omitempty"`
	SignatureAlgorithm string `json:"signature_algorithm,omitempty"`
	EmbeddedLicense    string `json:"embedded_license,omitempty"`
	ParseError         string `json:"parse_error,omitempty"`
}

// ObservedFile records a parsed file and its SHA-256. Folder observations are
// stored per path; ParseError files do not reference a certificate.
type ObservedFile struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256,omitempty"`
	Error  string `json:"error,omitempty"`
}

// CSPResult contains the independently collected CryptoPro product, core and
// licensing state. A missing CSP is a successful result (Present=false), not
// a partial report.
type CSPResult struct {
	Scanned        bool          `json:"scanned"`
	Complete       bool          `json:"complete"`
	Present        bool          `json:"present"`
	ProductVersion string        `json:"product_version,omitempty"`
	CoreVersion    string        `json:"core_version,omitempty"`
	Products       []CSPProduct  `json:"products,omitempty"`
	License        LicenseInfo   `json:"license"`
	Licenses       []LicenseInfo `json:"licenses,omitempty"`
	Error          string        `json:"error,omitempty"`
}

// CSPProduct is one installed CryptoPro product entry from the uninstall
// registry. Version here is the product release, never a component DLL.
type CSPProduct struct {
	ProductGUID    string `json:"product_guid"`
	DisplayName    string `json:"display_name,omitempty"`
	DisplayVersion string `json:"display_version,omitempty"`
	Branch         string `json:"branch,omitempty"`
}

// LicenseInfo keeps independent facts: kind, raw API code/source, date and
// time basis, state and term/trial classification. Unknown is explicit.
type LicenseInfo struct {
	LicenseID    string `json:"license_id,omitempty"`
	SerialMasked string `json:"serial_masked,omitempty"`
	Product      string `json:"product,omitempty"`
	ProductCode  int    `json:"product_code"`
	ProductName  string `json:"product_name,omitempty"`
	Complete     bool   `json:"complete,omitempty"`
	Kind         string `json:"kind"`
	KindRaw      string `json:"kind_raw,omitempty"`
	KindSource   string `json:"kind_source,omitempty"`
	State        string `json:"state"`
	ValidToRaw   string `json:"valid_to_raw,omitempty"`
	ValidToUTC   string `json:"valid_to_utc,omitempty"`
	TimeBasis    string `json:"time_basis,omitempty"`
	TermKind     string `json:"term_kind,omitempty"`
	IsTrial      string `json:"is_trial,omitempty"`
	Source       string `json:"source,omitempty"`
	Error        string `json:"error,omitempty"`
}

// ComputeStatus derives the report status from its completeness flags.
func (r *Report) ComputeStatus() string {
	if !r.ProfilesComplete || !r.CSP.Complete {
		return "partial"
	}
	for _, source := range r.Sources {
		if !source.Complete {
			return "partial"
		}
	}
	return "complete"
}

// ValidateReport validates structure, limits and content hashes. It does not
// verify signatures; callers must use OpenSignedEnvelope first and must also
// require report_id/scan_seq/collected_at equality with the signed data.
func ValidateReport(report *Report) *APIError {
	if report == nil {
		return &APIError{Code: CodeReportInvalid, Message: "report is missing"}
	}
	if _, err := NormalizeUUID(report.ReportID); err != nil {
		return &APIError{Code: CodeReportInvalid, Message: "report_id: " + err.Error()}
	}
	if report.ScanSeq < 0 {
		return &APIError{Code: CodeReportInvalid, Message: "scan_seq must be non-negative"}
	}
	if _, err := ValidateTimestamp(report.CollectedAt); err != nil {
		return &APIError{Code: CodeReportInvalid, Message: "collected_at: " + err.Error()}
	}
	if _, err := ValidateTimestamp(report.StartedAt); err != nil {
		return &APIError{Code: CodeReportInvalid, Message: "started_at: " + err.Error()}
	}
	if _, err := ValidateTimestamp(report.FinishedAt); err != nil {
		return &APIError{Code: CodeReportInvalid, Message: "finished_at: " + err.Error()}
	}
	if len(report.AgentVersion) > MaxVersionBytes {
		return &APIError{Code: CodeReportInvalid, Message: "agent_version is too long"}
	}
	if _, err := NormalizeHostname(report.Hostname); err != nil {
		return &APIError{Code: CodeReportInvalid, Message: "hostname: " + err.Error()}
	}
	if report.Status != report.ComputeStatus() {
		return &APIError{Code: CodeReportInvalid, Message: fmt.Sprintf("report status %q does not match completeness flags (%q)", report.Status, report.ComputeStatus())}
	}
	if len(report.Profiles) > MaxProfilesPerReport {
		return &APIError{Code: CodeReportInvalid, Message: "too many profiles"}
	}
	if len(report.Sources) > MaxSourcesPerReport {
		return &APIError{Code: CodeReportInvalid, Message: "too many sources"}
	}
	certCount := 0
	seenSources := make(map[string]struct{}, len(report.Sources))
	for i := range report.Sources {
		source := &report.Sources[i]
		if err := validateSource(source); err != nil {
			return &APIError{Code: CodeReportInvalid, Message: fmt.Sprintf("sources[%d]: %v", i, err)}
		}
		key := source.SourceType + "\x00" + strings.ToLower(source.SourceKey)
		if _, exists := seenSources[key]; exists {
			return &APIError{Code: CodeReportInvalid, Message: fmt.Sprintf("duplicate source %s/%s", source.SourceType, source.SourceKey)}
		}
		seenSources[key] = struct{}{}
		certCount += len(source.Certificates)
	}
	if certCount > MaxCertificatesPerReport {
		return &APIError{Code: CodeReportInvalid, Message: "too many certificates in report"}
	}
	if len(report.Errors) > 100 {
		return &APIError{Code: CodeReportInvalid, Message: "too many report errors"}
	}
	for i, e := range report.Errors {
		if len(e) > MaxErrorBytes {
			return &APIError{Code: CodeReportInvalid, Message: fmt.Sprintf("errors[%d] is too long", i)}
		}
	}
	if err := validateCSP(&report.CSP); err != nil {
		return &APIError{Code: CodeReportInvalid, Message: "csp: " + err.Error()}
	}
	encoded, err := json.Marshal(report)
	if err != nil {
		return &APIError{Code: CodeReportInvalid, Message: "marshal report: " + err.Error()}
	}
	if len(encoded) > MaxReportBytes {
		return &APIError{Code: CodePayloadTooLarge, Message: "report exceeds maximum size"}
	}
	return nil
}

func validateSource(source *SourceResult) error {
	switch source.SourceType {
	case "user_store":
		if _, err := ValidateUserSID(source.SourceKey); err != nil {
			return err
		}
		if source.UserSID == "" {
			return fmt.Errorf("user_store requires user_sid")
		}
		if !strings.EqualFold(source.SourceKey, source.UserSID) {
			return fmt.Errorf("source_key must equal user_sid")
		}
	case "folder":
		if source.SourceKey == "" || len(source.SourceKey) > MaxPathBytes {
			return fmt.Errorf("folder source_key is invalid")
		}
		if source.Path == "" {
			return fmt.Errorf("folder source requires path")
		}
	default:
		return fmt.Errorf("unsupported source_type %q", source.SourceType)
	}
	if len(source.Error) > MaxErrorBytes {
		return fmt.Errorf("source error is too long")
	}
	seenCerts := make(map[string]struct{}, len(source.Certificates))
	for j := range source.Certificates {
		cert := &source.Certificates[j]
		if err := validateObservedCertificate(cert); err != nil {
			return fmt.Errorf("certificates[%d]: %v", j, err)
		}
		key := strings.ToLower(cert.SHA256)
		if _, exists := seenCerts[key]; exists {
			return fmt.Errorf("duplicate certificate %s in source", cert.SHA256)
		}
		seenCerts[key] = struct{}{}
	}
	fileCerts := make(map[string]string, len(source.Certificates))
	for _, c := range source.Certificates {
		fileCerts[strings.ToLower(c.SHA256)] = c.SHA256
	}
	for j := range source.Files {
		file := &source.Files[j]
		if file.Path == "" || len(file.Path) > MaxPathBytes {
			return fmt.Errorf("files[%d] path is invalid", j)
		}
		if len(file.Error) > MaxErrorBytes {
			return fmt.Errorf("files[%d] error is too long", j)
		}
		if file.SHA256 != "" {
			normalized := strings.ToLower(file.SHA256)
			if !isHexSHA256(normalized) {
				return fmt.Errorf("files[%d] sha256 is invalid", j)
			}
			if _, ok := fileCerts[normalized]; !ok {
				return fmt.Errorf("files[%d] references a certificate not present in source", j)
			}
		}
	}
	return nil
}

func validateObservedCertificate(cert *ObservedCertificate) error {
	normalized := strings.ToLower(cert.SHA256)
	if !isHexSHA256(normalized) {
		return fmt.Errorf("sha256 is invalid")
	}
	if cert.SHA256 != normalized {
		return fmt.Errorf("sha256 must be lower-case hex")
	}
	der, err := base64.StdEncoding.Strict().DecodeString(cert.DERBase64)
	if err != nil {
		return fmt.Errorf("der_base64: %w", err)
	}
	if len(der) == 0 || len(der) > MaxDERBytes {
		return fmt.Errorf("DER length out of range")
	}
	sum := sha256.Sum256(der)
	if hex.EncodeToString(sum[:]) != normalized {
		return fmt.Errorf("sha256 does not match DER")
	}
	if cert.ParseError == "" {
		if cert.SerialHex == "" || cert.NotBefore == "" || cert.NotAfter == "" {
			return fmt.Errorf("parsed certificate requires serial and validity")
		}
		if _, err := ValidateTimestamp(cert.NotBefore); err != nil {
			return fmt.Errorf("not_before: %w", err)
		}
		if _, err := ValidateTimestamp(cert.NotAfter); err != nil {
			return fmt.Errorf("not_after: %w", err)
		}
		if len(cert.Subject) > MaxCertificateSubject || len(cert.Issuer) > MaxCertificateSubject {
			return fmt.Errorf("subject/issuer is too long")
		}
	}
	if len(cert.ParseError) > MaxErrorBytes {
		return fmt.Errorf("parse_error is too long")
	}
	switch cert.EmbeddedLicense {
	case "", "present", "absent", "unknown":
	default:
		return fmt.Errorf("invalid embedded_license %q", cert.EmbeddedLicense)
	}
	return nil
}

// ValidateUserSID validates a Windows SID string used as a source key.
// It intentionally accepts only S-1-5-21-* local/domain user SIDs; system
// service SIDs are rejected by profile enumeration and by this validator.
func ValidateUserSID(sid string) (string, error) {
	if !strings.HasPrefix(sid, "S-1-5-21-") {
		return "", fmt.Errorf("unsupported SID %q", sid)
	}
	if len(sid) > 184 {
		return "", fmt.Errorf("SID is too long")
	}
	for _, r := range strings.TrimPrefix(sid, "S-") {
		switch {
		case r >= '0' && r <= '9':
		case r == '-':
		default:
			return "", fmt.Errorf("invalid SID character %q", r)
		}
	}
	return sid, nil
}

func validateCSP(csp *CSPResult) error {
	if !csp.Scanned && csp.Present {
		return fmt.Errorf("present cannot be true when scanned is false")
	}
	if len(csp.ProductVersion) > MaxVersionBytes || len(csp.CoreVersion) > MaxVersionBytes {
		return fmt.Errorf("CSP version is too long")
	}
	if len(csp.Error) > MaxErrorBytes {
		return fmt.Errorf("CSP error is too long")
	}
	if len(csp.Licenses) > MaxLicensesPerReport {
		return fmt.Errorf("too many license records")
	}
	for index, license := range csp.Licenses {
		if err := validateLicenseRecord(license); err != nil {
			return fmt.Errorf("licenses[%d]: %w", index, err)
		}
	}
	switch csp.License.Kind {
	case "", "client", "server", "unknown":
	default:
		return fmt.Errorf("invalid license kind %q", csp.License.Kind)
	}
	switch csp.License.State {
	case "", "active", "expired", "not_installed", "unknown", "error":
	default:
		return fmt.Errorf("invalid license state %q", csp.License.State)
	}
	switch csp.License.TermKind {
	case "", "trial", "time_limited", "perpetual", "unknown":
	default:
		return fmt.Errorf("invalid license term_kind %q", csp.License.TermKind)
	}
	switch csp.License.IsTrial {
	case "", "true", "false", "unknown":
	default:
		return fmt.Errorf("invalid is_trial %q", csp.License.IsTrial)
	}
	if len(csp.License.KindRaw) > 64 || len(csp.License.KindSource) > 128 {
		return fmt.Errorf("license raw/source is too long")
	}
	if len(csp.License.ValidToRaw) > 128 || len(csp.License.ValidToUTC) > 64 {
		return fmt.Errorf("license date is too long")
	}
	if len(csp.License.Source) > 128 || len(csp.License.Error) > MaxErrorBytes {
		return fmt.Errorf("license source/error is too long")
	}
	return nil
}

func validateLicenseRecord(license LicenseInfo) error {
	if err := ValidateLicenseID(license.LicenseID); err != nil {
		return fmt.Errorf("license_id: %w", err)
	}
	if len(license.SerialMasked) > 64 {
		return fmt.Errorf("serial_masked is too long")
	}
	if err := ValidateMaskedSerial(license.SerialMasked, license.LicenseID); err != nil {
		return fmt.Errorf("serial_masked: %w", err)
	}
	switch license.Product {
	case "csp":
		if license.ProductCode != 0 {
			return fmt.Errorf("csp product_code must be 0")
		}
	case "ocsp":
		if license.ProductCode != 1 {
			return fmt.Errorf("ocsp product_code must be 1")
		}
	case "tsp":
		if license.ProductCode != 2 {
			return fmt.Errorf("tsp product_code must be 2")
		}
	default:
		return fmt.Errorf("unsupported product %q", license.Product)
	}
	if len(license.ProductName) > 128 {
		return fmt.Errorf("product_name is too long")
	}
	switch license.Kind {
	case "", "client", "server", "unknown":
	default:
		return fmt.Errorf("invalid license kind %q", license.Kind)
	}
	switch license.State {
	case "", "active", "expired", "not_installed", "unknown", "error":
	default:
		return fmt.Errorf("invalid license state %q", license.State)
	}
	switch license.TermKind {
	case "", "trial", "time_limited", "perpetual", "unknown":
	default:
		return fmt.Errorf("invalid license term_kind %q", license.TermKind)
	}
	switch license.IsTrial {
	case "", "true", "false", "unknown":
	default:
		return fmt.Errorf("invalid is_trial %q", license.IsTrial)
	}
	if len(license.KindRaw) > 64 || len(license.KindSource) > 128 {
		return fmt.Errorf("license raw/source is too long")
	}
	if len(license.ValidToRaw) > 128 || len(license.ValidToUTC) > 64 {
		return fmt.Errorf("license date is too long")
	}
	if license.ValidToUTC != "" {
		if _, err := ValidateTimestamp(license.ValidToUTC); err != nil {
			return fmt.Errorf("valid_to_utc: %w", err)
		}
	}
	if len(license.Source) > 128 || len(license.Error) > MaxErrorBytes {
		return fmt.Errorf("license source/error is too long")
	}
	return nil
}

// ReportPayloadHash returns SHA-256 over the JCS representation of the report
// object. It is the business idempotency fingerprint for one report_id.
func ReportPayloadHash(reportRaw []byte) (string, error) {
	canonical, err := Canonicalize(reportRaw)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(canonical)
	return hex.EncodeToString(sum[:]), nil
}

// DecodeReport strictly decodes a report object: duplicate keys, unknown
// fields and trailing data are rejected, then semantic validation runs.
func DecodeReport(raw []byte) (*Report, *APIError) {
	if err := RejectDuplicateKeys(raw); err != nil {
		return nil, &APIError{Code: CodeReportInvalid, Message: err.Error()}
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var report Report
	if err := decoder.Decode(&report); err != nil {
		return nil, &APIError{Code: CodeReportInvalid, Message: "decode report: " + err.Error()}
	}
	if err := ValidateReport(&report); err != nil {
		return nil, err
	}
	return &report, nil
}
