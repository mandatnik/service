package protocol

import "time"

// Wire protocol version 1 endpoints. The base path is part of the signed
// `path` field, so changing it requires a protocol version change.
const (
	ProtocolVersion = "1"

	AgentBasePath      = "/api/agent/v1"
	PathRegister       = AgentBasePath + "/register"
	PathRename         = AgentBasePath + "/rename"
	PathSync           = AgentBasePath + "/sync"
	PathReport         = AgentBasePath + "/report"
	PathJobAck         = AgentBasePath + "/jobs/ack"
	PathCapabilities   = AgentBasePath + "/capabilities"
	PathTaskSync       = AgentBasePath + "/tasks/sync"
	PathTaskAck        = AgentBasePath + "/tasks/ack"
	PathTaskClaim      = AgentBasePath + "/tasks/claim"
	PathTaskProgress   = AgentBasePath + "/tasks/progress"
	PathTaskResult     = AgentBasePath + "/tasks/result"
	PathTaskDiagnostic = AgentBasePath + "/tasks/diagnostic"
	MethodPost         = "POST"
	ContentTypeJSON    = "application/json"
	EnvelopeFieldData  = "data"
	EnvelopeFieldSign  = "sign"
	EnvelopeFieldHost  = "host"
)

// Operations carried in the signed data. The operation must match the HTTP
// path and is checked on the server before any business change.
const (
	OpRegister       = "register"
	OpRename         = "rename"
	OpSync           = "sync"
	OpReport         = "report"
	OpJobAck         = "job_ack"
	OpCapabilities   = "capabilities"
	OpTaskSync       = "task_sync"
	OpTaskAck        = "task_ack"
	OpTaskClaim      = "task_claim"
	OpTaskProgress   = "task_progress"
	OpTaskResult     = "task_result"
	OpTaskDiagnostic = "task_diagnostic"
)

// Stable API error codes. Messages are for humans; clients may branch on
// these codes only.
const (
	CodeInvalidJSON          = "invalid_json"
	CodeInvalidEnvelope      = "invalid_envelope"
	CodeInvalidSignature     = "invalid_signature"
	CodeInvalidCurve         = "invalid_curve"
	CodeInvalidKey           = "invalid_key"
	CodeInvalidIdentity      = "invalid_identity"
	CodeUnknownIdentity      = "unknown_identity"
	CodeIdentityRevoked      = "identity_revoked"
	CodeUUIDConflict         = "uuid_conflict"
	CodeKeyConflict          = "key_conflict"
	CodeHostnameConflict     = "hostname_conflict"
	CodeHostnameMismatch     = "hostname_mismatch"
	CodeReplay               = "replay"
	CodeReportConflict       = "report_conflict"
	CodeReportInvalid        = "report_invalid"
	CodeJobConflict          = "job_conflict"
	CodeNotFound             = "not_found"
	CodeMethodNotAllowed     = "method_not_allowed"
	CodePayloadTooLarge      = "payload_too_large"
	CodeUnsupported          = "unsupported"
	CodeInternal             = "internal_error"
	CodeDatabase             = "database_error"
	CodeServerBusy           = "server_busy"
	CodeConfigInvalid        = "config_invalid"
	CodeRegistrationDeny     = "registration_denied"
	CodeProtocolVersion      = "protocol_version_unsupported"
	CodeNoPendingIdentity    = "no_pending_identity"
	CodeTaskNotFound         = "task_not_found"
	CodeTaskConflict         = "task_conflict"
	CodeTaskClaimDenied      = "task_claim_denied"
	CodeTaskExpired          = "task_expired"
	CodeTaskCanceled         = "task_canceled"
	CodePreviewStale         = "preview_stale"
	CodePreviewInvalid       = "preview_invalid"
	CodeLicenseDeficit       = "license_deficit"
	CodeLicenseUnavailable   = "license_key_unavailable"
	CodeMachineNotEligible   = "machine_not_eligible"
	CodeIdempotencyConflict  = "idempotency_conflict"
	CodeJournalCorrupted     = "journal_corrupted"
	CodeConflict             = "conflict"
	CodeInstallationPending  = "installation_pending"
	CodeInstallationRejected = "installation_rejected"
	CodeInstallationStale    = "installation_stale"
	CodeInstallationConflict = "installation_conflict"
	CodeAgentKeyUnavailable  = "agent_encryption_key_missing"
	CodeMachineBusy          = "machine_busy"
	CodeReportRequired       = "report_required"
	CodeSerialProofRequired  = "serial_proof_required"
	CodeUnauthorized         = "unauthorized"
	CodeIPNotAllowed         = "ip_not_allowed"
	CodeInvalidRequest       = "invalid_request"
	CodeInvalidFilter        = "invalid_filter"
	CodeDuplicateName        = "duplicate_name"
	CodeInvalidRules         = "invalid_rules"
	CodeRateLimited          = "rate_limited"
)

// Agreed operational constants. The legacy 10 minute poll interval remains
// only as a fallback for old protocol-1 agents; capable agents receive
// poll_interval_seconds (default 60). The two-report queue and two 10 MB text
// logs remain fixed.
const (
	AgentPollInterval                = 10 * time.Minute
	DefaultPollIntervalSeconds       = 60
	DefaultInventoryFreshnessSeconds = 86400
	DefaultTaskTTLSeconds            = 604800
	MinPollIntervalSeconds           = 10
	MaxPollIntervalSeconds           = 3600
	MinScheduleSeconds               = 60
	MaxScheduleSeconds               = 2592000
	DefaultScanIntervalDays          = 1
	QueueMaxReports                  = 2
	LogFileMaxBytes                  = 10 * 1024 * 1024
	MaxRequestBytes                  = 16 * 1024 * 1024
	MaxReportBytes                   = 8 * 1024 * 1024
	// MaxSmallRequestBytes bounds endpoints whose payload is a small signed
	// envelope (register, rename, sync, acknowledgements, task control).
	// Only report submission needs the large body limit.
	MaxSmallRequestBytes     = 1 * 1024 * 1024
	MaxCertificatesPerReport = 5000
	MaxSourcesPerReport      = 256
	MaxProfilesPerReport     = 256
	MaxLicensesPerReport     = 32
	MaxFilesPerFolder        = 10000
	MaxDERBytes              = 1024 * 1024
	MaxPublicKeyPEMBytes     = 4096
	MaxHostnameBytes         = 253
	MaxUsernameBytes         = 256
	MaxPathBytes             = 1024
	MaxVersionBytes          = 128
	MaxErrorBytes            = 2048
	MaxJobMessageBytes       = 1024
	MaxCertificateSubject    = 8192
	HTTPReadHeaderTimeout    = 10 * time.Second
	HTTPReadTimeout          = 60 * time.Second
	HTTPWriteTimeout         = 120 * time.Second
	HTTPIdleTimeout          = 120 * time.Second
	HTTPMaxHeaderBytes       = 1 << 20
	DBConnectTimeout         = 15 * time.Second
)
