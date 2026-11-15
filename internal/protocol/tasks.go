package protocol

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// Task kinds and states are shared by the administrator API, the agent task
// channel and the SQL model. Unknown values are rejected, never coerced.
const (
	TaskKindScan           = "scan"
	TaskKindInstallLicense = "install_license"

	TaskStateQueued         = "queued"
	TaskStateDelivered      = "delivered"
	TaskStateRunning        = "running"
	TaskStateRetryWait      = "retry_wait"
	TaskStateSucceeded      = "succeeded"
	TaskStateSkipped        = "skipped"
	TaskStateFailed         = "failed"
	TaskStateOutcomeUnknown = "outcome_unknown"
	TaskStateCancelled      = "cancelled"
	TaskStateExpired        = "expired"

	TaskAggregateQueued            = "queued"
	TaskAggregateRunning           = "running"
	TaskAggregateRequiresAttention = "requires_attention"
	TaskAggregateCompleted         = "completed"
	TaskAggregateCancelled         = "cancelled"
	TaskAggregateExpired           = "expired"
	TaskAggregatePartiallyFailed   = "partially_failed"
	TaskAggregateFailed            = "failed"

	PoolTermOneYear   = "one_year"
	PoolTermTwoYears  = "two_years"
	PoolTermPerpetual = "perpetual"

	PoolKindClient = "client"
	PoolKindServer = "server"

	LicenseStateAvailable      = "available"
	LicenseStateReserved       = "reserved"
	LicenseStateUsed           = "used"
	LicenseStateOutcomeUnknown = "outcome_unknown"
	LicenseStateBlocked        = "blocked"

	TaskCategoryActivation = "activation"
	TaskCategoryOptional   = "optional"
	TaskCategoryActivated  = "already_activated"
	TaskCategoryNeedsCheck = "needs_check"

	TaskCategoryActivationNoLicense = "activation_no_license"
	TaskCategoryActivationTrial     = "activation_trial"

	TaskCapabilityV1           = "task_v1"
	TaskCapabilityScheduleV2   = "schedule_v2"
	TaskCapabilityInstallV1    = "install_license_v1"
	TaskCapabilityScanV1       = "scan_v1"
	TaskCapabilityEnvelopeV1   = "rsa_oaep_sha256_aes_256_gcm_v1"
	EncryptionAlgorithmV1      = "RSA-OAEP-SHA256+AES-256-GCM"
	ParametersVersionV1        = 1
	TaskClaimTTLSeconds        = 300
	TaskPreviewTTLSeconds      = 600
	TaskMaxAttempts            = 3
	TaskRetryDelayFirstSecond  = 30
	TaskRetryDelaySecondSecond = 120
)

// AllTaskStates lists the per-item states used in result validation.
func IsTerminalTaskState(state string) bool {
	switch state {
	case TaskStateSucceeded, TaskStateSkipped, TaskStateFailed,
		TaskStateOutcomeUnknown, TaskStateCancelled, TaskStateExpired:
		return true
	}
	return false
}

func IsTaskState(state string) bool {
	switch state {
	case TaskStateQueued, TaskStateDelivered, TaskStateRunning, TaskStateRetryWait,
		TaskStateSucceeded, TaskStateSkipped, TaskStateFailed, TaskStateOutcomeUnknown,
		TaskStateCancelled, TaskStateExpired:
		return true
	}
	return false
}

// AgentCapabilities is the signed capability/key registration message. The
// transport identity remains ECDSA P-256; the encryption key is RSA-3072.
type AgentCapabilities struct {
	Capabilities        []string `json:"capabilities"`
	EncryptionKeyID     string   `json:"encryption_key_id"`
	EncryptionPublicKey string   `json:"encryption_public_key"`
	EncryptionAlgorithm string   `json:"encryption_algorithm"`
	EncryptionBits      int      `json:"encryption_bits"`
	EncryptionKeyRotate bool     `json:"encryption_key_rotate,omitempty"`
}

// CapabilitiesResponse confirms the active key and full configuration.
type CapabilitiesResponse struct {
	Accepted            bool         `json:"accepted"`
	ServerTime          string       `json:"server_time"`
	EncryptionKeyID     string       `json:"encryption_key_id"`
	Config              *AgentConfig `json:"config,omitempty"`
	ConfigHash          string       `json:"config_hash"`
	PollIntervalSeconds int          `json:"poll_interval_seconds"`
	TaskTTLSeconds      int          `json:"task_ttl_seconds"`
	Warnings            []string     `json:"warnings,omitempty"`
}

// EncryptedParameters is a public envelope header. Serial numbers and scan
// options live only in Ciphertext.
type EncryptedParameters struct {
	Version        int    `json:"version"`
	Algorithm      string `json:"algorithm"`
	RecipientKeyID string `json:"recipient_key_id"`
	WrappedKey     string `json:"wrapped_key"`
	Nonce          string `json:"nonce"`
	Ciphertext     string `json:"ciphertext"`
}

// TaskBinding is the exact canonical input used for both the RSA-OAEP label and
// the AES-GCM additional authenticated data. It prevents moving a ciphertext
// between tasks, items, machines, registrations or operations.
type TaskBinding struct {
	Protocol          string `json:"protocol"`
	Purpose           string `json:"purpose"`
	TaskID            string `json:"task_id"`
	ItemID            string `json:"item_id"`
	MachineID         string `json:"machine_id"`
	RegistrationID    int64  `json:"registration_id"`
	Kind              string `json:"kind"`
	ParametersVersion int    `json:"parameters_version"`
	RecipientKeyID    string `json:"recipient_key_id"`
	ExpiresAt         string `json:"expires_at"`
}

const TaskBindingProtocol = "mandatnik/task-parameters/v1"

// TaskBindingAAD returns the canonical binding bytes.
func TaskBindingAAD(binding TaskBinding) ([]byte, error) {
	raw, err := json.Marshal(binding)
	if err != nil {
		return nil, err
	}
	return Canonicalize(raw)
}

// TaskBindingHash is a public digest of the AAD, useful for diagnostics and
// cross-side test vectors. It is not a secret.
func TaskBindingHash(binding TaskBinding) (string, error) {
	aad, err := TaskBindingAAD(binding)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(aad)
	return fmt.Sprintf("%x", sum[:]), nil
}

// TaskItemDelivery is the public part of one item. ParametersEnvelope carries
// the encrypted payload; no plaintext parameters are returned by sync.
type TaskItemDelivery struct {
	TaskID             string              `json:"task_id"`
	ItemID             string              `json:"item_id"`
	MachineID          string              `json:"machine_id"`
	RegistrationID     int64               `json:"registration_id"`
	Kind               string              `json:"kind"`
	State              string              `json:"state"`
	DeliveryVersion    int                 `json:"delivery_version"`
	EncryptionKeyID    string              `json:"encryption_key_id"`
	ParametersVersion  int                 `json:"parameters_version"`
	ParametersEnvelope EncryptedParameters `json:"parameters_envelope"`
	CreatedAt          string              `json:"created_at"`
	ExpiresAt          string              `json:"expires_at"`
	CancelRequested    bool                `json:"cancel_requested"`
	ReconcileRequested bool                `json:"reconcile_requested"`
	AttemptCount       int                 `json:"attempt_count"`
	LicenseID          string              `json:"license_id,omitempty"`
}

// TaskSyncResponse is returned by the task polling endpoint.
type TaskSyncResponse struct {
	ServerTime string             `json:"server_time"`
	Items      []TaskItemDelivery `json:"items"`
	Warnings   []string           `json:"warnings,omitempty"`
}

// TaskDeliveryAck confirms that the agent durably stored the ciphertext.
type TaskDeliveryAck struct {
	ItemID          string `json:"item_id"`
	DeliveryVersion int    `json:"delivery_version"`
}

type TaskDeliveryAckResponse struct {
	Accepted   bool   `json:"accepted"`
	ItemID     string `json:"item_id"`
	State      string `json:"state"`
	Duplicate  bool   `json:"duplicate,omitempty"`
	ServerTime string `json:"server_time"`
}

// TaskClaim asks for a time-bounded permission to start a modifying action.
type TaskClaim struct {
	ItemID          string `json:"item_id"`
	DeliveryVersion int    `json:"delivery_version"`
}

type TaskClaimResponse struct {
	Granted    bool   `json:"granted"`
	ItemID     string `json:"item_id"`
	State      string `json:"state"`
	ClaimUntil string `json:"claim_until,omitempty"`
	ServerTime string `json:"server_time"`
	ReasonCode string `json:"reason_code,omitempty"`
}

// TaskProgressEvent is an allowlisted event; it never contains a serial.
type TaskProgressEvent struct {
	ItemID          string `json:"item_id"`
	AttemptNo       int    `json:"attempt_no"`
	EventType       string `json:"event_type"`
	Stage           string `json:"stage,omitempty"`
	EventCode       string `json:"event_code,omitempty"`
	WindowsError    string `json:"windows_error,omitempty"`
	DurationMillis  int64  `json:"duration_ms,omitempty"`
	OccurredAt      string `json:"occurred_at"`
	DeliveryVersion int    `json:"delivery_version,omitempty"`
}

// TaskLicenseState is the sanitized CSP observation sent with a result. It
// deliberately contains no serial number or private key information.
type TaskLicenseState struct {
	Present        bool   `json:"present"`
	Complete       bool   `json:"complete"`
	ProductVersion string `json:"product_version,omitempty"`
	CoreVersion    string `json:"core_version,omitempty"`
	Environment    string `json:"environment,omitempty"`
	Kind           string `json:"kind,omitempty"`
	KindRaw        string `json:"kind_raw,omitempty"`
	State          string `json:"state,omitempty"`
	TermKind       string `json:"term_kind,omitempty"`
	IsTrial        string `json:"is_trial,omitempty"`
	ValidToRaw     string `json:"valid_to_raw,omitempty"`
	ValidToUTC     string `json:"valid_to_utc,omitempty"`
	TimeBasis      string `json:"time_basis,omitempty"`
	Source         string `json:"source,omitempty"`
	ErrorCode      string `json:"error_code,omitempty"`
}

// TaskResult is the sanitized final/reconciliation result. Modified is one of
// no, maybe, yes and drives license release decisions. It is the agent's signed
// assertion and never includes the license number.
type TaskResult struct {
	ItemID          string              `json:"item_id"`
	DeliveryVersion int                 `json:"delivery_version"`
	State           string              `json:"state"`
	ReasonCode      string              `json:"reason_code,omitempty"`
	Message         string              `json:"message,omitempty"`
	AttemptNo       int                 `json:"attempt_no"`
	ResultVersion   int                 `json:"result_version"`
	Modified        string              `json:"modified"`
	SerialMatch     bool                `json:"serial_match"`
	ReportID        string              `json:"report_id,omitempty"`
	License         TaskLicenseState    `json:"license"`
	Reconcile       bool                `json:"reconcile,omitempty"`
	SanitizedLog    []TaskProgressEvent `json:"sanitized_events,omitempty"`
}

type TaskResultResponse struct {
	Accepted   bool   `json:"accepted"`
	ItemID     string `json:"item_id"`
	State      string `json:"state"`
	Duplicate  bool   `json:"duplicate,omitempty"`
	ServerTime string `json:"server_time"`
}

// TaskDiagnostic reports a non-secret local condition such as a corrupt
// journal. The server records it and keeps the item reserved.
type TaskDiagnostic struct {
	ItemID     string `json:"item_id,omitempty"`
	Code       string `json:"code"`
	Message    string `json:"message,omitempty"`
	OccurredAt string `json:"occurred_at"`
}

// TaskQueueStatus is a small agent-side status sent with task sync so the
// server can tell "no connection" from "delivered and being retried".
type TaskQueueStatus struct {
	Items          int    `json:"items"`
	JournalCorrupt bool   `json:"journal_corrupt"`
	JournalError   string `json:"journal_error,omitempty"`
}

// ValidateTaskResult performs structural validation only. Business rules are
// enforced by the server store against the current item.
func ValidateTaskResult(result *TaskResult) error {
	if result == nil {
		return fmt.Errorf("result is missing")
	}
	if _, err := NormalizeUUID(result.ItemID); err != nil {
		return fmt.Errorf("item_id: %w", err)
	}
	if result.DeliveryVersion < 1 {
		return fmt.Errorf("delivery_version must be positive")
	}
	if !IsTerminalTaskState(result.State) && result.State != TaskStateRetryWait {
		return fmt.Errorf("invalid result state %q", result.State)
	}
	switch result.Modified {
	case "no", "maybe", "yes":
	default:
		return fmt.Errorf("invalid modified value %q", result.Modified)
	}
	if result.AttemptNo < 0 || result.AttemptNo > TaskMaxAttempts {
		return fmt.Errorf("attempt_no out of range")
	}
	if result.ResultVersion < 1 {
		return fmt.Errorf("result_version must be positive")
	}
	if len(result.ReasonCode) > 128 || len(result.Message) > MaxErrorBytes {
		return fmt.Errorf("result text is too long")
	}
	if result.ReportID != "" {
		if _, err := NormalizeUUID(result.ReportID); err != nil {
			return fmt.Errorf("report_id: %w", err)
		}
	}
	if result.State == TaskStateSucceeded && result.ReportID == "" {
		// Scan results require a report; install results require serial_match,
		// which is checked by the server against the item kind.
	}
	if len(result.SanitizedLog) > 100 {
		return fmt.Errorf("too many sanitized events")
	}
	return nil
}

// ValidateProgressEvent validates the allowlisted progress payload.
func ValidateProgressEvent(event *TaskProgressEvent) error {
	if event == nil {
		return fmt.Errorf("event is missing")
	}
	if _, err := NormalizeUUID(event.ItemID); err != nil {
		return fmt.Errorf("item_id: %w", err)
	}
	if event.AttemptNo < 0 || event.AttemptNo > TaskMaxAttempts {
		return fmt.Errorf("attempt_no out of range")
	}
	if event.EventType == "" || len(event.EventType) > 64 {
		return fmt.Errorf("invalid event_type")
	}
	if len(event.Stage) > 64 || len(event.EventCode) > 128 || len(event.WindowsError) > 64 {
		return fmt.Errorf("event text is too long")
	}
	if event.OccurredAt == "" {
		return fmt.Errorf("occurred_at is required")
	}
	if _, err := ValidateTimestamp(event.OccurredAt); err != nil {
		return fmt.Errorf("occurred_at: %w", err)
	}
	return nil
}

// DecodeTaskProgressEvent strictly decodes a signed progress event.
func DecodeTaskProgressEvent(raw []byte) (*TaskProgressEvent, error) {
	var event TaskProgressEvent
	if err := RejectDuplicateKeys(raw); err != nil {
		return nil, err
	}
	if err := strictDecode(raw, &event); err != nil {
		return nil, err
	}
	if err := ValidateProgressEvent(&event); err != nil {
		return nil, err
	}
	return &event, nil
}

// DecodeTaskDiagnostic strictly decodes a non-secret local diagnostic.
func DecodeTaskDiagnostic(raw []byte) (*TaskDiagnostic, error) {
	var diagnostic TaskDiagnostic
	if err := RejectDuplicateKeys(raw); err != nil {
		return nil, err
	}
	if err := strictDecode(raw, &diagnostic); err != nil {
		return nil, err
	}
	if diagnostic.Code == "" || len(diagnostic.Code) > 64 || len(diagnostic.Message) > MaxErrorBytes {
		return nil, fmt.Errorf("invalid diagnostic")
	}
	if diagnostic.ItemID != "" {
		if _, err := NormalizeUUID(diagnostic.ItemID); err != nil {
			return nil, fmt.Errorf("diagnostic item_id: %w", err)
		}
	}
	if diagnostic.OccurredAt != "" {
		if _, err := ValidateTimestamp(diagnostic.OccurredAt); err != nil {
			return nil, fmt.Errorf("diagnostic occurred_at: %w", err)
		}
	}
	return &diagnostic, nil
}

// DecodeTaskResult strictly decodes the signed result object.
func DecodeTaskResult(raw []byte) (*TaskResult, error) {
	if err := RejectDuplicateKeys(raw); err != nil {
		return nil, err
	}
	var result TaskResult
	if err := strictDecode(raw, &result); err != nil {
		return nil, err
	}
	if err := ValidateTaskResult(&result); err != nil {
		return nil, err
	}
	return &result, nil
}

// DecodeTaskParameters strictly decodes decrypted plaintext parameters.
func DecodeTaskParameters(raw []byte) (kind string, scan *ScanParameters, install *InstallLicenseParameters, err error) {
	if err := RejectDuplicateKeys(raw); err != nil {
		return "", nil, nil, err
	}
	var probe struct {
		Kind string `json:"kind"`
	}
	if err := json.Unmarshal(raw, &probe); err != nil {
		return "", nil, nil, err
	}
	switch probe.Kind {
	case TaskKindScan:
		var value ScanParameters
		if err := strictDecode(raw, &value); err != nil {
			return "", nil, nil, err
		}
		return TaskKindScan, &value, nil, nil
	case TaskKindInstallLicense:
		var value InstallLicenseParameters
		if err := strictDecode(raw, &value); err != nil {
			return "", nil, nil, err
		}
		if err := value.Validate(); err != nil {
			return "", nil, nil, err
		}
		return TaskKindInstallLicense, nil, &value, nil
	default:
		return "", nil, nil, fmt.Errorf("unsupported task kind %q", probe.Kind)
	}
}

func strictDecode(raw []byte, target any) error {
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); err == nil {
		return fmt.Errorf("trailing JSON")
	}
	return nil
}

// ScanParameters are encrypted like every other item, even though they are not
// secret by themselves.
type ScanParameters struct {
	Kind    string      `json:"kind"`
	Options ScanOptions `json:"options"`
}

type ScanOptions struct {
	Force bool `json:"force"`
}

// InstallLicenseParameters is the complete, encrypted instruction for one
// machine. The server selects a single pool and never substitutes a version,
// term or client/server kind during execution.
type InstallLicenseParameters struct {
	Kind                  string          `json:"kind"`
	LicenseID             string          `json:"license_id"`
	Serial                string          `json:"serial"`
	Pool                  LicensePoolSpec `json:"pool"`
	AllowTrialReplacement bool            `json:"allow_trial_replacement"`
	ExpectedFingerprint   string          `json:"expected_fingerprint"`
}

// LicensePoolSpec is the immutable part of a pool that determines
// compatibility and the expected post-install license.
type LicensePoolSpec struct {
	PoolID          string `json:"pool_id"`
	Name            string `json:"name"`
	CSPMajorVersion int    `json:"csp_major_version"`
	LicenseKind     string `json:"license_kind"`
	Term            string `json:"term"`
}

func (p *InstallLicenseParameters) Validate() error {
	if p == nil {
		return fmt.Errorf("parameters are missing")
	}
	if p.Kind != TaskKindInstallLicense {
		return fmt.Errorf("invalid kind %q", p.Kind)
	}
	if _, err := NormalizeUUID(p.LicenseID); err != nil {
		return fmt.Errorf("license_id: %w", err)
	}
	if _, err := NormalizeUUID(p.Pool.PoolID); err != nil {
		return fmt.Errorf("pool_id: %w", err)
	}
	if p.Serial == "" || len(p.Serial) > 128 {
		return fmt.Errorf("serial is invalid")
	}
	if p.Pool.CSPMajorVersion != 4 && p.Pool.CSPMajorVersion != 5 {
		return fmt.Errorf("unsupported CSP major version")
	}
	if p.Pool.LicenseKind != PoolKindClient && p.Pool.LicenseKind != PoolKindServer {
		return fmt.Errorf("invalid license kind")
	}
	switch p.Pool.Term {
	case PoolTermOneYear, PoolTermTwoYears, PoolTermPerpetual:
	default:
		return fmt.Errorf("invalid pool term")
	}
	if p.ExpectedFingerprint != "" && len(p.ExpectedFingerprint) != 64 {
		return fmt.Errorf("invalid fingerprint")
	}
	return nil
}

// MaskSerial is the only serial representation allowed in UI HTTP responses.
func MaskSerial(serial string) string {
	normalized := NormalizeSerial(serial)
	if len(normalized) < 4 {
		return "****"
	}
	return "****-****-****-****-" + normalized[len(normalized)-4:]
}

// NormalizeSerial removes separators, uppercases and validates the 25-character
// CryptoPro CSP serial layout. Correct format does not prove the key is valid.
func NormalizeSerial(serial string) string {
	var builder strings.Builder
	for _, r := range strings.ToUpper(strings.TrimSpace(serial)) {
		switch {
		case r >= '0' && r <= '9':
			builder.WriteRune(r)
		case r >= 'A' && r <= 'Z':
			builder.WriteRune(r)
		case r == ' ' || r == '\t' || r == '-' || r == '\r' || r == '\n':
			// Accepted separators are removed.
		default:
			return ""
		}
	}
	return builder.String()
}

// ValidateSerialFormat checks the normalized 25-character format and rejects
// an all-zero placeholder. It does not contact CryptoPro.
func ValidateSerialFormat(normalized string) error {
	if len(normalized) != 25 {
		return fmt.Errorf("serial must contain 25 characters")
	}
	zeros := strings.Trim(normalized, "0")
	if zeros == "" {
		return fmt.Errorf("serial is a placeholder")
	}
	return nil
}

// EncodeEncryptedParameters serializes a public envelope.
func EncodeEncryptedParameters(value EncryptedParameters) ([]byte, error) {
	return json.Marshal(value)
}

// DecodeEncryptedParameters strictly decodes a stored public envelope.
func DecodeEncryptedParameters(raw []byte) (EncryptedParameters, error) {
	var value EncryptedParameters
	if err := RejectDuplicateKeys(raw); err != nil {
		return value, err
	}
	if err := strictDecode(raw, &value); err != nil {
		return value, err
	}
	if value.Version != ParametersVersionV1 || value.Algorithm != EncryptionAlgorithmV1 {
		return value, fmt.Errorf("unsupported parameters envelope")
	}
	if value.RecipientKeyID == "" || value.WrappedKey == "" || value.Nonce == "" || value.Ciphertext == "" {
		return value, fmt.Errorf("parameters envelope is incomplete")
	}
	return value, nil
}

// DecodeBase64Strict decodes standard padded Base64.
func DecodeBase64Strict(value string) ([]byte, error) {
	return base64.StdEncoding.Strict().DecodeString(value)
}

// FormatTaskTime is used consistently in task DTOs.
func FormatTaskTime(value time.Time) string {
	return value.UTC().Format(time.RFC3339Nano)
}
