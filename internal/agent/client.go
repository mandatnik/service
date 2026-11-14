package agent

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"telehack2026/internal/protocol"
	"telehack2026/internal/version"
)

// APIClient is the outbound-only agent HTTP client. TLS uses the operating
// system trust store; there is no bypass switch.
type APIClient struct {
	baseURL string
	http    *http.Client
}

func newAPIClient(serverURL string, timeout time.Duration) *APIClient {
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	return &APIClient{
		baseURL: strings.TrimRight(serverURL, "/"),
		http: &http.Client{
			Timeout: timeout,
			Transport: &http.Transport{
				TLSClientConfig:     &tls.Config{MinVersion: tls.VersionTLS12},
				ForceAttemptHTTP2:   true,
				MaxIdleConns:        4,
				IdleConnTimeout:     60 * time.Second,
				TLSHandshakeTimeout: 10 * time.Second,
			},
		},
	}
}

type response struct {
	Status int
	Body   []byte
	Error  *protocol.APIError
}

func (c *APIClient) post(ctx context.Context, path string, data protocol.SignedData, key *ecdsa.PrivateKey) response {
	envelope, err := protocol.BuildSignedEnvelope(key, data)
	if err != nil {
		return response{Error: &protocol.APIError{Code: "client_build", Message: err.Error()}}
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+path, bytes.NewReader(envelope))
	if err != nil {
		return response{Error: &protocol.APIError{Code: "client_build", Message: err.Error()}}
	}
	request.Header.Set("Content-Type", protocol.ContentTypeJSON)
	request.Header.Set("User-Agent", "Telehack2026-Agent/"+version.Version)
	httpResponse, err := c.http.Do(request)
	if err != nil {
		return response{Error: &protocol.APIError{Code: "network_error", Message: err.Error()}}
	}
	defer httpResponse.Body.Close()
	body, err := io.ReadAll(io.LimitReader(httpResponse.Body, protocol.MaxRequestBytes))
	if err != nil {
		return response{Status: httpResponse.StatusCode, Error: &protocol.APIError{Code: "network_error", Message: err.Error()}}
	}
	result := response{Status: httpResponse.StatusCode, Body: body}
	if httpResponse.StatusCode < 200 || httpResponse.StatusCode >= 300 {
		var wrapped protocol.ErrorResponse
		if json.Unmarshal(body, &wrapped) == nil && wrapped.Error.Code != "" {
			result.Error = &wrapped.Error
		} else {
			result.Error = &protocol.APIError{Code: "http_error", Message: fmt.Sprintf("HTTP %d", httpResponse.StatusCode)}
		}
	}
	return result
}

func signedData(operation, path string, identity *Identity) protocol.SignedData {
	return protocol.SignedData{
		ProtocolVersion: protocol.ProtocolVersion,
		Operation:       operation,
		RequestID:       protocol.NewUUID(),
		UUID:            identity.UUID,
		Hostname:        identity.Hostname,
		Method:          protocol.MethodPost,
		Path:            path,
		IssuedAt:        time.Now().UTC().Format(time.RFC3339Nano),
		AgentVersion:    version.Version,
		Architecture:    "amd64",
	}
}

func (c *APIClient) register(ctx context.Context, identity *Identity, osVersion string) (protocol.RegisterResponse, response) {
	data := signedData(protocol.OpRegister, protocol.PathRegister, identity)
	data.PublicKey = identity.PublicKeyPEM
	data.OSVersion = osVersion
	result := c.post(ctx, protocol.PathRegister, data, identity.Key)
	var decoded protocol.RegisterResponse
	if result.Error == nil {
		if err := json.Unmarshal(result.Body, &decoded); err != nil {
			result.Error = &protocol.APIError{Code: "client_decode", Message: err.Error()}
		}
	}
	return decoded, result
}

func (c *APIClient) rename(ctx context.Context, old, next *Identity, osVersion string) (protocol.RegisterResponse, response) {
	data := signedData(protocol.OpRename, protocol.PathRename, old)
	data.NewUUID = next.UUID
	data.NewHostname = next.Hostname
	data.NewPublicKey = next.PublicKeyPEM
	data.OSVersion = osVersion
	result := c.post(ctx, protocol.PathRename, data, old.Key)
	var decoded protocol.RegisterResponse
	if result.Error == nil {
		if err := json.Unmarshal(result.Body, &decoded); err != nil {
			result.Error = &protocol.APIError{Code: "client_decode", Message: err.Error()}
		}
	}
	return decoded, result
}

func (c *APIClient) sync(ctx context.Context, identity *Identity, configHash, osVersion string) (protocol.SyncResponse, response) {
	data := signedData(protocol.OpSync, protocol.PathSync, identity)
	data.ConfigHash = configHash
	data.OSVersion = osVersion
	result := c.post(ctx, protocol.PathSync, data, identity.Key)
	var decoded protocol.SyncResponse
	if result.Error == nil {
		if err := json.Unmarshal(result.Body, &decoded); err != nil {
			result.Error = &protocol.APIError{Code: "client_decode", Message: err.Error()}
		}
	}
	return decoded, result
}

func (c *APIClient) report(ctx context.Context, identity *Identity, item QueueItem, osVersion string) (protocol.ReportResponse, response) {
	raw, err := json.Marshal(item.Report)
	if err != nil {
		return protocol.ReportResponse{}, response{Error: &protocol.APIError{Code: "client_build", Message: err.Error()}}
	}
	seq := item.ScanSeq
	data := signedData(protocol.OpReport, protocol.PathReport, identity)
	data.ReportID = item.ReportID
	data.ScanSeq = &seq
	data.CollectedAt = item.CollectedAt
	data.Report = raw
	data.OSVersion = osVersion
	result := c.post(ctx, protocol.PathReport, data, identity.Key)
	var decoded protocol.ReportResponse
	if result.Error == nil {
		if err := json.Unmarshal(result.Body, &decoded); err != nil {
			result.Error = &protocol.APIError{Code: "client_decode", Message: err.Error()}
		}
	}
	return decoded, result
}

func (c *APIClient) ack(ctx context.Context, identity *Identity, ack jobAck, osVersion string) (protocol.JobAckResponse, response) {
	data := signedData(protocol.OpJobAck, protocol.PathJobAck, identity)
	data.JobID = ack.JobID
	data.JobStatus = ack.Status
	data.JobReportID = ack.ReportID
	data.JobMessage = ack.Message
	data.OSVersion = osVersion
	result := c.post(ctx, protocol.PathJobAck, data, identity.Key)
	var decoded protocol.JobAckResponse
	if result.Error == nil {
		if err := json.Unmarshal(result.Body, &decoded); err != nil {
			result.Error = &protocol.APIError{Code: "client_decode", Message: err.Error()}
		}
	}
	return decoded, result
}

func (c *APIClient) capabilities(ctx context.Context, identity *Identity, encryption *EncryptionIdentity, rotate bool, osVersion string) (protocol.CapabilitiesResponse, response) {
	publicPEM, err := encryption.PublicKey()
	if err != nil {
		return protocol.CapabilitiesResponse{}, response{Error: &protocol.APIError{Code: "client_build", Message: err.Error()}}
	}
	data := signedData(protocol.OpCapabilities, protocol.PathCapabilities, identity)
	data.Capabilities = []string{
		protocol.TaskCapabilityV1, protocol.TaskCapabilityScheduleV2,
		protocol.TaskCapabilityInstallV1, protocol.TaskCapabilityScanV1,
		protocol.TaskCapabilityEnvelopeV1,
	}
	data.EncryptionKeyID = encryption.ActiveID()
	data.EncryptionPublicKey = publicPEM
	data.EncryptionAlgorithm = protocol.EncryptionAlgorithmV1
	data.EncryptionBits = protocol.RSAEncryptionBits
	data.EncryptionKeyRotate = rotate
	data.OSVersion = osVersion
	result := c.post(ctx, protocol.PathCapabilities, data, identity.Key)
	var decoded protocol.CapabilitiesResponse
	if result.Error == nil {
		if err := json.Unmarshal(result.Body, &decoded); err != nil {
			result.Error = &protocol.APIError{Code: "client_decode", Message: err.Error()}
		}
	}
	return decoded, result
}

func (c *APIClient) taskSync(ctx context.Context, identity *Identity, status protocol.TaskQueueStatus, osVersion string) (protocol.TaskSyncResponse, response) {
	data := signedData(protocol.OpTaskSync, protocol.PathTaskSync, identity)
	queue, _ := json.Marshal(status)
	data.TaskQueue = queue
	data.OSVersion = osVersion
	result := c.post(ctx, protocol.PathTaskSync, data, identity.Key)
	var decoded protocol.TaskSyncResponse
	if result.Error == nil {
		if err := json.Unmarshal(result.Body, &decoded); err != nil {
			result.Error = &protocol.APIError{Code: "client_decode", Message: err.Error()}
		}
	}
	return decoded, result
}

func (c *APIClient) taskAck(ctx context.Context, identity *Identity, itemID string, version int, osVersion string) (protocol.TaskDeliveryAckResponse, response) {
	data := signedData(protocol.OpTaskAck, protocol.PathTaskAck, identity)
	data.TaskItemID = itemID
	data.TaskDeliveryVersion = version
	data.OSVersion = osVersion
	result := c.post(ctx, protocol.PathTaskAck, data, identity.Key)
	var decoded protocol.TaskDeliveryAckResponse
	if result.Error == nil {
		if err := json.Unmarshal(result.Body, &decoded); err != nil {
			result.Error = &protocol.APIError{Code: "client_decode", Message: err.Error()}
		}
	}
	return decoded, result
}

func (c *APIClient) taskClaim(ctx context.Context, identity *Identity, itemID string, version int, osVersion string) (protocol.TaskClaimResponse, response) {
	data := signedData(protocol.OpTaskClaim, protocol.PathTaskClaim, identity)
	data.TaskItemID = itemID
	data.TaskDeliveryVersion = version
	data.OSVersion = osVersion
	result := c.post(ctx, protocol.PathTaskClaim, data, identity.Key)
	var decoded protocol.TaskClaimResponse
	if result.Error == nil {
		if err := json.Unmarshal(result.Body, &decoded); err != nil {
			result.Error = &protocol.APIError{Code: "client_decode", Message: err.Error()}
		}
	}
	return decoded, result
}

func (c *APIClient) taskProgress(ctx context.Context, identity *Identity, event protocol.TaskProgressEvent, osVersion string) response {
	raw, err := json.Marshal(event)
	if err != nil {
		return response{Error: &protocol.APIError{Code: "client_build", Message: err.Error()}}
	}
	data := signedData(protocol.OpTaskProgress, protocol.PathTaskProgress, identity)
	data.TaskItemID = event.ItemID
	data.TaskEvent = raw
	data.OSVersion = osVersion
	return c.post(ctx, protocol.PathTaskProgress, data, identity.Key)
}

func (c *APIClient) taskResult(ctx context.Context, identity *Identity, result protocol.TaskResult, osVersion string) (protocol.TaskResultResponse, response) {
	raw, err := json.Marshal(result)
	if err != nil {
		return protocol.TaskResultResponse{}, response{Error: &protocol.APIError{Code: "client_build", Message: err.Error()}}
	}
	data := signedData(protocol.OpTaskResult, protocol.PathTaskResult, identity)
	data.TaskItemID = result.ItemID
	data.TaskResult = raw
	data.OSVersion = osVersion
	response := c.post(ctx, protocol.PathTaskResult, data, identity.Key)
	var decoded protocol.TaskResultResponse
	if response.Error == nil {
		if err := json.Unmarshal(response.Body, &decoded); err != nil {
			response.Error = &protocol.APIError{Code: "client_decode", Message: err.Error()}
		}
	}
	return decoded, response
}

func (c *APIClient) taskDiagnostic(ctx context.Context, identity *Identity, diagnostic protocol.TaskDiagnostic, osVersion string) response {
	raw, err := json.Marshal(diagnostic)
	if err != nil {
		return response{Error: &protocol.APIError{Code: "client_build", Message: err.Error()}}
	}
	data := signedData(protocol.OpTaskDiagnostic, protocol.PathTaskDiagnostic, identity)
	data.TaskDiagnostic = raw
	data.OSVersion = osVersion
	return c.post(ctx, protocol.PathTaskDiagnostic, data, identity.Key)
}
