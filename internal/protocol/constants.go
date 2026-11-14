package protocol

import "time"

// Wire protocol version 1 endpoints. The base path is part of the signed
// `path` field, so changing it requires a protocol version change.
const (
	ProtocolVersion = "1"

	AgentBasePath     = "/api/agent/v1"
	PathRegister      = AgentBasePath + "/register"
	PathRename        = AgentBasePath + "/rename"
	PathSync          = AgentBasePath + "/sync"
	PathReport        = AgentBasePath + "/report"
	PathJobAck        = AgentBasePath + "/jobs/ack"
	MethodPost        = "POST"
	ContentTypeJSON   = "application/json"
	EnvelopeFieldData = "data"
	EnvelopeFieldSign = "sign"
	EnvelopeFieldHost = "host"
)

// Operations carried in the signed data. The operation must match the HTTP
// path and is checked on the server before any business change.
const (
	OpRegister = "register"
	OpRename   = "rename"
	OpSync     = "sync"
	OpReport   = "report"
	OpJobAck   = "job_ack"
)

// Stable API error codes. Messages are for humans; clients may branch on
// these codes only.
const (
	CodeInvalidJSON       = "invalid_json"
	CodeInvalidEnvelope   = "invalid_envelope"
	CodeInvalidSignature  = "invalid_signature"
	CodeInvalidCurve      = "invalid_curve"
	CodeInvalidKey        = "invalid_key"
	CodeInvalidIdentity   = "invalid_identity"
	CodeUnknownIdentity   = "unknown_identity"
	CodeIdentityRevoked   = "identity_revoked"
	CodeUUIDConflict      = "uuid_conflict"
	CodeKeyConflict       = "key_conflict"
	CodeHostnameConflict  = "hostname_conflict"
	CodeHostnameMismatch  = "hostname_mismatch"
	CodeReplay            = "replay"
	CodeReportConflict    = "report_conflict"
	CodeReportInvalid     = "report_invalid"
	CodeJobConflict       = "job_conflict"
	CodeNotFound          = "not_found"
	CodeMethodNotAllowed  = "method_not_allowed"
	CodePayloadTooLarge   = "payload_too_large"
	CodeUnsupported       = "unsupported"
	CodeInternal          = "internal_error"
	CodeDatabase          = "database_error"
	CodeConfigInvalid     = "config_invalid"
	CodeRegistrationDeny  = "registration_denied"
	CodeProtocolVersion   = "protocol_version_unsupported"
	CodeNoPendingIdentity = "no_pending_identity"
)

// Agreed operational constants. The 10 minute poll interval, one day default
// scan interval, two-report queue and two 10 MB text logs are fixed by the
// requirements and are not scalable through configuration.
const (
	AgentPollInterval        = 10 * time.Minute
	DefaultScanIntervalDays  = 1
	QueueMaxReports          = 2
	LogFileMaxBytes          = 10 * 1024 * 1024
	MaxRequestBytes          = 16 * 1024 * 1024
	MaxReportBytes           = 8 * 1024 * 1024
	MaxCertificatesPerReport = 5000
	MaxSourcesPerReport      = 256
	MaxProfilesPerReport     = 256
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
