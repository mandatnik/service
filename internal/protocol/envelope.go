package protocol

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// PeekEnvelope decodes and structurally validates an envelope without
// verifying its signature. The caller must subsequently call
// OpenSignedEnvelope (or OpenBootstrapEnvelope) before acting on it.
func PeekEnvelope(raw []byte) (*Envelope, *SignedData, *APIError) {
	env, data, err := decodeEnvelope(raw)
	if err != nil {
		return nil, nil, &APIError{Code: CodeInvalidEnvelope, Message: err.Error()}
	}
	if err := validateShape(data); err != nil {
		return nil, nil, &APIError{Code: CodeInvalidEnvelope, Message: err.Error()}
	}
	return env, data, nil
}

// OpenBootstrapEnvelope verifies a first-registration request using the
// public key carried inside the signed data itself. It must only be used for
// the register operation; it proves possession of a key, not prior identity.
func OpenBootstrapEnvelope(raw []byte, expectedMethod, expectedPath string) (*SignedRequest, *APIError) {
	env, data, err := decodeEnvelope(raw)
	if err != nil {
		return nil, &APIError{Code: CodeInvalidEnvelope, Message: err.Error()}
	}
	if err := validateShape(data); err != nil {
		return nil, &APIError{Code: CodeInvalidEnvelope, Message: err.Error()}
	}
	if data.Operation != OpRegister {
		return nil, &APIError{Code: CodeInvalidEnvelope, Message: "bootstrap verification is only valid for register"}
	}
	if data.PublicKey == "" {
		return nil, &APIError{Code: CodeInvalidKey, Message: "register requires public_key"}
	}
	pub, err := ParsePublicKeyPEM(data.PublicKey)
	if err != nil {
		code := CodeInvalidKey
		if errors.Is(err, ErrWrongCurve) {
			code = CodeInvalidCurve
		}
		return nil, &APIError{Code: code, Message: err.Error()}
	}
	req, apiErr := verifyEnvelope(env, data, expectedMethod, expectedPath, pub)
	if apiErr != nil {
		return nil, apiErr
	}
	return req, nil
}

// OpenSignedEnvelope verifies a request against a known identity key and the
// expected HTTP method/path. The signed method/path must match exactly.
func OpenSignedEnvelope(raw []byte, expectedMethod, expectedPath string, pub *ecdsa.PublicKey) (*SignedRequest, *APIError) {
	env, data, err := decodeEnvelope(raw)
	if err != nil {
		return nil, &APIError{Code: CodeInvalidEnvelope, Message: err.Error()}
	}
	if err := validateShape(data); err != nil {
		return nil, &APIError{Code: CodeInvalidEnvelope, Message: err.Error()}
	}
	return verifyEnvelope(env, data, expectedMethod, expectedPath, pub)
}

func verifyEnvelope(env *Envelope, data *SignedData, expectedMethod, expectedPath string, pub *ecdsa.PublicKey) (*SignedRequest, *APIError) {
	hostUUID, err := NormalizeUUID(env.Host.UUID)
	signedUUID, signedErr := NormalizeUUID(data.UUID)
	if err != nil || signedErr != nil || hostUUID != signedUUID {
		return nil, &APIError{Code: CodeHostnameMismatch, Message: "outer host.uuid does not match signed uuid"}
	}
	if !HostnamesEqual(env.Host.Hostname, data.Hostname) {
		return nil, &APIError{Code: CodeHostnameMismatch, Message: "outer host.hostname does not match signed hostname"}
	}
	if data.Method != expectedMethod {
		return nil, &APIError{Code: CodeInvalidEnvelope, Message: fmt.Sprintf("signed method %q does not match %q", data.Method, expectedMethod)}
	}
	if data.Path != expectedPath {
		return nil, &APIError{Code: CodeInvalidEnvelope, Message: fmt.Sprintf("signed path %q does not match %q", data.Path, expectedPath)}
	}
	canonical, err := Canonicalize(env.Data)
	if err != nil {
		return nil, &APIError{Code: CodeInvalidEnvelope, Message: err.Error()}
	}
	sig, err := DecodeSignatureBase64(env.Sign)
	if err != nil {
		return nil, &APIError{Code: CodeInvalidSignature, Message: err.Error()}
	}
	if err := VerifyCanonical(pub, canonical, sig); err != nil {
		code := CodeInvalidSignature
		if errors.Is(err, ErrWrongCurve) {
			code = CodeInvalidCurve
		}
		return nil, &APIError{Code: code, Message: err.Error()}
	}
	req := &SignedRequest{
		Host:      env.Host,
		Data:      *data,
		Canonical: canonical,
		DataHash:  sha256.Sum256(canonical),
		Signature: sig,
		Key:       pub,
	}
	return req, nil
}

func decodeEnvelope(raw []byte) (*Envelope, *SignedData, error) {
	if len(raw) == 0 {
		return nil, nil, errors.New("empty request body")
	}
	if len(raw) > MaxRequestBytes {
		return nil, nil, errors.New("request body exceeds limit")
	}
	if err := RejectDuplicateKeys(raw); err != nil {
		return nil, nil, err
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var env Envelope
	if err := dec.Decode(&env); err != nil {
		return nil, nil, fmt.Errorf("decode envelope: %w", err)
	}
	// The decoder above consumes the first value; the duplicate-key scanner
	// has already rejected trailing values, but require EOF explicitly.
	if dec.More() {
		return nil, nil, errors.New("trailing JSON after envelope")
	}
	if len(env.Data) == 0 {
		return nil, nil, errors.New("envelope data is missing")
	}
	if env.Sign == "" {
		return nil, nil, errors.New("envelope sign is missing")
	}
	if env.Host.UUID == "" || env.Host.Hostname == "" {
		return nil, nil, errors.New("envelope host is incomplete")
	}
	dataDec := json.NewDecoder(bytes.NewReader(env.Data))
	dataDec.DisallowUnknownFields()
	var data SignedData
	if err := dataDec.Decode(&data); err != nil {
		return nil, nil, fmt.Errorf("decode signed data: %w", err)
	}
	return &env, &data, nil
}

func validateShape(data *SignedData) error {
	if data.ProtocolVersion != ProtocolVersion {
		return fmt.Errorf("unsupported protocol_version %q", data.ProtocolVersion)
	}
	switch data.Operation {
	case OpRegister, OpRename, OpSync, OpReport, OpJobAck:
	default:
		return fmt.Errorf("unsupported operation %q", data.Operation)
	}
	if _, err := NormalizeUUID(data.RequestID); err != nil {
		return fmt.Errorf("request_id: %w", err)
	}
	if id, err := NormalizeUUID(data.UUID); err != nil {
		return fmt.Errorf("uuid: %w", err)
	} else if !isV4(id) {
		return errors.New("uuid must be a version-4 UUID")
	}
	if _, err := NormalizeHostname(data.Hostname); err != nil {
		return err
	}
	if data.Method != MethodPost {
		return fmt.Errorf("signed method must be POST")
	}
	if !strings.HasPrefix(data.Path, AgentBasePath+"/") {
		return fmt.Errorf("signed path is outside the agent API")
	}
	if _, err := ValidateTimestamp(data.IssuedAt); err != nil {
		return fmt.Errorf("issued_at: %w", err)
	}
	if len(data.AgentVersion) > MaxVersionBytes || len(data.OSVersion) > MaxVersionBytes {
		return errors.New("agent/os version is too long")
	}
	switch data.Operation {
	case OpRegister:
		if data.PublicKey == "" {
			return errors.New("register requires public_key")
		}
		if data.NewUUID != "" || data.NewHostname != "" || data.NewPublicKey != "" {
			return errors.New("register must not contain rename fields")
		}
	case OpRename:
		if data.NewUUID == "" || data.NewHostname == "" || data.NewPublicKey == "" {
			return errors.New("rename requires new_uuid, new_hostname and new_public_key")
		}
		if _, err := NormalizeUUID(data.NewUUID); err != nil {
			return fmt.Errorf("new_uuid: %w", err)
		}
		if _, err := NormalizeHostname(data.NewHostname); err != nil {
			return fmt.Errorf("new_hostname: %w", err)
		}
	case OpSync:
		if data.ConfigHash != "" && !isHexSHA256(data.ConfigHash) {
			return errors.New("config_hash must be 64 lower-case hex characters")
		}
		if data.Report != nil || data.ReportID != "" {
			return errors.New("sync must not contain a report")
		}
	case OpReport:
		if data.ReportID == "" || data.Report == nil || data.ScanSeq == nil || data.CollectedAt == "" {
			return errors.New("report requires report_id, scan_seq, collected_at and report")
		}
		if _, err := NormalizeUUID(data.ReportID); err != nil {
			return fmt.Errorf("report_id: %w", err)
		}
		if *data.ScanSeq < 0 {
			return errors.New("scan_seq must be non-negative")
		}
		if _, err := ValidateTimestamp(data.CollectedAt); err != nil {
			return fmt.Errorf("collected_at: %w", err)
		}
	case OpJobAck:
		if data.JobID == "" {
			return errors.New("job acknowledgement requires job_id")
		}
		if _, err := NormalizeUUID(data.JobID); err != nil {
			return fmt.Errorf("job_id: %w", err)
		}
		switch data.JobStatus {
		case "completed", "failed", "report_evicted":
		default:
			return fmt.Errorf("invalid job_status %q", data.JobStatus)
		}
		if len(data.JobMessage) > MaxJobMessageBytes {
			return errors.New("job_message is too long")
		}
		if data.JobReportID != "" {
			if _, err := NormalizeUUID(data.JobReportID); err != nil {
				return fmt.Errorf("job_report_id: %w", err)
			}
		}
	}
	return nil
}

func isV4(normalizedUUID string) bool {
	if len(normalizedUUID) < 15 {
		return false
	}
	return normalizedUUID[14] == '4'
}

func isHexSHA256(s string) bool {
	if len(s) != 64 {
		return false
	}
	for _, r := range s {
		switch {
		case r >= '0' && r <= '9':
		case r >= 'a' && r <= 'f':
		default:
			return false
		}
	}
	return true
}

// BuildSignedEnvelope canonicalizes and signs data, then wraps it in the
// protocol envelope. The host fields are derived from the signed data.
func BuildSignedEnvelope(key *ecdsa.PrivateKey, data SignedData) ([]byte, error) {
	if key == nil {
		return nil, errors.New("nil private key")
	}
	if err := validateShape(&data); err != nil {
		return nil, err
	}
	dataRaw, err := json.Marshal(data)
	if err != nil {
		return nil, fmt.Errorf("marshal signed data: %w", err)
	}
	canonical, err := Canonicalize(dataRaw)
	if err != nil {
		return nil, err
	}
	sig, err := SignCanonical(key, canonical)
	if err != nil {
		return nil, err
	}
	env := Envelope{
		Data: dataRaw,
		Sign: EncodeSignatureBase64(sig),
		Host: HostRef{UUID: data.UUID, Hostname: data.Hostname},
	}
	out, err := json.Marshal(env)
	if err != nil {
		return nil, fmt.Errorf("marshal envelope: %w", err)
	}
	if len(out) > MaxRequestBytes {
		return nil, errors.New("encoded request exceeds maximum size")
	}
	return out, nil
}
