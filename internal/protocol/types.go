package protocol

import (
	"crypto/ecdsa"
	"encoding/json"
	"time"
)

// HostRef is the unsigned outer identity envelope. Its values must match the
// signed uuid/hostname fields inside Data.
type HostRef struct {
	UUID     string `json:"uuid"`
	Hostname string `json:"hostname"`
}

// Envelope is the JSON request wrapper:
//
//	{"data":{...},"sign":"base64(DER ECDSA)","host":{"uuid":"...","hostname":"..."}}
type Envelope struct {
	Data json.RawMessage `json:"data"`
	Sign string          `json:"sign"`
	Host HostRef         `json:"host"`
}

// SignedData is the complete protocol-1 signed payload. Operation-specific
// fields are optional; the server validates that the fields required by the
// operation are present and that the HTTP method/path match.
type SignedData struct {
	ProtocolVersion string `json:"protocol_version"`
	Operation       string `json:"operation"`
	RequestID       string `json:"request_id"`
	UUID            string `json:"uuid"`
	Hostname        string `json:"hostname"`
	Method          string `json:"method"`
	Path            string `json:"path"`
	IssuedAt        string `json:"issued_at"`
	AgentVersion    string `json:"agent_version,omitempty"`
	OSVersion       string `json:"os_version,omitempty"`
	Architecture    string `json:"architecture,omitempty"`

	// Registration and rename.
	PublicKey    string `json:"public_key,omitempty"`
	NewUUID      string `json:"new_uuid,omitempty"`
	NewHostname  string `json:"new_hostname,omitempty"`
	NewPublicKey string `json:"new_public_key,omitempty"`

	// Sync.
	ConfigHash string `json:"config_hash,omitempty"`

	// Report.
	ReportID    string          `json:"report_id,omitempty"`
	ScanSeq     *int64          `json:"scan_seq,omitempty"`
	CollectedAt string          `json:"collected_at,omitempty"`
	Report      json.RawMessage `json:"report,omitempty"`

	// Job acknowledgement.
	JobID       string `json:"job_id,omitempty"`
	JobStatus   string `json:"job_status,omitempty"`
	JobMessage  string `json:"job_message,omitempty"`
	JobReportID string `json:"job_report_id,omitempty"`
}

// SignedRequest is a verified, decoded request. Canonical and DataHash are
// exactly what the signature covers.
type SignedRequest struct {
	Host      HostRef
	Data      SignedData
	Canonical []byte
	DataHash  [32]byte
	Signature []byte
	Key       *ecdsa.PublicKey
}

// AgentConfig is the server-controlled collection configuration. Its
// canonical JSON hash is the cache key; the agent never computes a hash over
// a different representation.
type FolderPolicy struct {
	ID    string `json:"id"`
	Name  string `json:"name"`
	Rules string `json:"rules"`
	Level string `json:"level"` // machine or group
}

type AgentConfig struct {
	FolderPolicies   []FolderPolicy `json:"folder_policies,omitempty"`
	Version          int            `json:"version"`
	ScanIntervalDays int            `json:"scan_interval_days"`
	CertDirectories  []string       `json:"cert_directories"`
	Recursive        bool           `json:"recursive"`
	MaxFiles         int            `json:"max_files"`
	MaxFileBytes     int64          `json:"max_file_bytes"`
}

// DefaultAgentConfig returns the agreed defaults. The server stores the same
// defaults in a migration; this function is used by tests and by the agent
// when no configuration has ever been received.
func DefaultAgentConfig() AgentConfig {
	return AgentConfig{
		Version:          1,
		ScanIntervalDays: DefaultScanIntervalDays,
		CertDirectories:  []string{},
		Recursive:        true,
		MaxFiles:         2000,
		MaxFileBytes:     int64(MaxDERBytes * 10),
	}
}

// APIError is the stable error body.
type APIError struct {
	Code    string         `json:"code"`
	Message string         `json:"message"`
	Details map[string]any `json:"details,omitempty"`
}

// Error implements the error interface for convenient wrapping.
func (e *APIError) Error() string {
	if e == nil {
		return ""
	}
	return e.Code + ": " + e.Message
}

// ErrorResponse is returned for all non-2xx responses.
type ErrorResponse struct {
	Error APIError `json:"error"`
}

// RegisterResponse is returned by /register and /rename.
type RegisterResponse struct {
	MachineID    string      `json:"machine_id"`
	UUID         string      `json:"uuid"`
	Hostname     string      `json:"hostname"`
	RegisteredAt string      `json:"registered_at"`
	Config       AgentConfig `json:"config"`
	ConfigHash   string      `json:"config_hash"`
	ServerTime   string      `json:"server_time"`
	Warnings     []string    `json:"warnings,omitempty"`
}

// Job describes a pending manual scan job.
type Job struct {
	JobID     string `json:"job_id"`
	Kind      string `json:"kind"`
	CreatedAt string `json:"created_at"`
}

// SyncResponse returns configuration by hash plus all pending jobs. Jobs are
// returned even when ConfigHash is unchanged.
type SyncResponse struct {
	ServerTime string       `json:"server_time"`
	Config     *AgentConfig `json:"config,omitempty"`
	ConfigHash string       `json:"config_hash"`
	Jobs       []Job        `json:"jobs"`
	Warnings   []string     `json:"warnings,omitempty"`
}

// ReportResponse is the idempotent result of report submission.
type ReportResponse struct {
	Accepted   bool     `json:"accepted"`
	Duplicate  bool     `json:"duplicate"`
	Applied    bool     `json:"applied"`
	ReportID   string   `json:"report_id"`
	ReceivedAt string   `json:"received_at"`
	Reason     string   `json:"reason,omitempty"`
	Warnings   []string `json:"warnings,omitempty"`
}

// JobAckResponse is the idempotent result of a job acknowledgement.
type JobAckResponse struct {
	Accepted  bool   `json:"accepted"`
	JobID     string `json:"job_id"`
	State     string `json:"state"`
	Duplicate bool   `json:"duplicate,omitempty"`
}

// TimeNowUTC formats the server clock consistently.
func TimeNowUTC() string {
	return time.Now().UTC().Format(time.RFC3339Nano)
}
