package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"mandatnik/internal/protocol"
)

type client struct {
	baseURL string
	http    *http.Client
}

func newClient(baseURL, caFile string, timeout time.Duration) (*client, error) {
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12}
	if caFile != "" {
		pemBytes, err := os.ReadFile(caFile)
		if err != nil {
			return nil, fmt.Errorf("read CA file: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pemBytes) {
			return nil, fmt.Errorf("CA file has no certificates")
		}
		tlsConfig.RootCAs = pool
	}
	return &client{
		baseURL: strings.TrimRight(baseURL, "/"),
		http: &http.Client{
			Timeout: timeout,
			Transport: &http.Transport{
				TLSClientConfig:     tlsConfig,
				MaxIdleConns:        10,
				IdleConnTimeout:     30 * time.Second,
				TLSHandshakeTimeout: 10 * time.Second,
			},
		},
	}, nil
}

type apiResult struct {
	Status int
	Body   []byte
	Error  *protocol.APIError
}

func (c *client) post(ctx context.Context, path string, envelope []byte) apiResult {
	return c.raw(ctx, http.MethodPost, path, protocol.ContentTypeJSON, envelope)
}

func (c *client) raw(ctx context.Context, method, path, contentType string, body []byte) apiResult {
	request, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, bytes.NewReader(body))
	if err != nil {
		return apiResult{Error: &protocol.APIError{Code: "client_error", Message: err.Error()}}
	}
	if contentType != "" {
		request.Header.Set("Content-Type", contentType)
	}
	response, err := c.http.Do(request)
	if err != nil {
		return apiResult{Error: &protocol.APIError{Code: "network_error", Message: err.Error()}}
	}
	defer response.Body.Close()
	body, readErr := io.ReadAll(io.LimitReader(response.Body, 16*1024*1024))
	if readErr != nil {
		return apiResult{Status: response.StatusCode, Error: &protocol.APIError{Code: "client_read_error", Message: readErr.Error()}}
	}
	result := apiResult{Status: response.StatusCode, Body: body}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		var wrapped protocol.ErrorResponse
		if json.Unmarshal(body, &wrapped) == nil && wrapped.Error.Code != "" {
			result.Error = &wrapped.Error
		} else {
			result.Error = &protocol.APIError{Code: "http_error", Message: fmt.Sprintf("HTTP %d", response.StatusCode)}
		}
	}
	return result
}

func decodeResponse[T any](result apiResult) (T, error) {
	var value T
	if result.Error != nil {
		return value, result.Error
	}
	if err := json.Unmarshal(result.Body, &value); err != nil {
		return value, fmt.Errorf("decode response: %w", err)
	}
	return value, nil
}

type identity struct {
	UUID      string
	Hostname  string
	Key       *ecdsa.PrivateKey
	PublicPEM string
	MachineID string
}

func newIdentity(hostname string) (*identity, error) {
	key, err := protocol.GenerateKey()
	if err != nil {
		return nil, err
	}
	publicPEM, err := protocol.MarshalPublicKeyPEM(&key.PublicKey)
	if err != nil {
		return nil, err
	}
	return &identity{UUID: protocol.NewUUID(), Hostname: hostname, Key: key, PublicPEM: publicPEM}, nil
}

func baseData(operation, path string, id *identity) protocol.SignedData {
	return protocol.SignedData{
		ProtocolVersion: protocol.ProtocolVersion,
		Operation:       operation,
		RequestID:       protocol.NewUUID(),
		UUID:            id.UUID,
		Hostname:        id.Hostname,
		Method:          protocol.MethodPost,
		Path:            path,
		IssuedAt:        time.Now().UTC().Format(time.RFC3339Nano),
		AgentVersion:    "acceptance-0.1.0",
		OSVersion:       "acceptance-host",
		Architecture:    "amd64",
	}
}

func (c *client) register(ctx context.Context, id *identity) (protocol.RegisterResponse, apiResult, error) {
	data := baseData(protocol.OpRegister, protocol.PathRegister, id)
	data.PublicKey = id.PublicPEM
	envelope, err := protocol.BuildSignedEnvelope(id.Key, data)
	if err != nil {
		return protocol.RegisterResponse{}, apiResult{}, err
	}
	result := c.post(ctx, protocol.PathRegister, envelope)
	response, err := decodeResponse[protocol.RegisterResponse](result)
	if err == nil {
		id.MachineID = response.MachineID
	}
	return response, result, err
}

func (c *client) rename(ctx context.Context, old *identity, newID *identity) (protocol.RegisterResponse, apiResult, error) {
	data := baseData(protocol.OpRename, protocol.PathRename, old)
	data.NewUUID = newID.UUID
	data.NewHostname = newID.Hostname
	data.NewPublicKey = newID.PublicPEM
	envelope, err := protocol.BuildSignedEnvelope(old.Key, data)
	if err != nil {
		return protocol.RegisterResponse{}, apiResult{}, err
	}
	result := c.post(ctx, protocol.PathRename, envelope)
	response, err := decodeResponse[protocol.RegisterResponse](result)
	if err == nil {
		newID.MachineID = response.MachineID
	}
	return response, result, err
}

func (c *client) sync(ctx context.Context, id *identity, configHash string) (protocol.SyncResponse, apiResult, error) {
	data := baseData(protocol.OpSync, protocol.PathSync, id)
	data.ConfigHash = configHash
	envelope, err := protocol.BuildSignedEnvelope(id.Key, data)
	if err != nil {
		return protocol.SyncResponse{}, apiResult{}, err
	}
	result := c.post(ctx, protocol.PathSync, envelope)
	response, err := decodeResponse[protocol.SyncResponse](result)
	return response, result, err
}

func (c *client) syncEnvelope(ctx context.Context, id *identity, configHash string) ([]byte, error) {
	data := baseData(protocol.OpSync, protocol.PathSync, id)
	data.ConfigHash = configHash
	return protocol.BuildSignedEnvelope(id.Key, data)
}

func (c *client) report(ctx context.Context, id *identity, report protocol.Report) (protocol.ReportResponse, apiResult, error) {
	reportRaw, err := json.Marshal(report)
	if err != nil {
		return protocol.ReportResponse{}, apiResult{}, err
	}
	scanSeq := report.ScanSeq
	data := baseData(protocol.OpReport, protocol.PathReport, id)
	data.ReportID = report.ReportID
	data.ScanSeq = &scanSeq
	data.CollectedAt = report.CollectedAt
	data.Report = reportRaw
	envelope, err := protocol.BuildSignedEnvelope(id.Key, data)
	if err != nil {
		return protocol.ReportResponse{}, apiResult{}, err
	}
	result := c.post(ctx, protocol.PathReport, envelope)
	response, err := decodeResponse[protocol.ReportResponse](result)
	return response, result, err
}

func (c *client) reportEnvelope(id *identity, report protocol.Report) ([]byte, error) {
	reportRaw, err := json.Marshal(report)
	if err != nil {
		return nil, err
	}
	scanSeq := report.ScanSeq
	data := baseData(protocol.OpReport, protocol.PathReport, id)
	data.ReportID = report.ReportID
	data.ScanSeq = &scanSeq
	data.CollectedAt = report.CollectedAt
	data.Report = reportRaw
	return protocol.BuildSignedEnvelope(id.Key, data)
}

func (c *client) ack(ctx context.Context, id *identity, jobID, status, reportID, message string) (protocol.JobAckResponse, apiResult, error) {
	data := baseData(protocol.OpJobAck, protocol.PathJobAck, id)
	data.JobID = jobID
	data.JobStatus = status
	data.JobReportID = reportID
	data.JobMessage = message
	envelope, err := protocol.BuildSignedEnvelope(id.Key, data)
	if err != nil {
		return protocol.JobAckResponse{}, apiResult{}, err
	}
	result := c.post(ctx, protocol.PathJobAck, envelope)
	response, err := decodeResponse[protocol.JobAckResponse](result)
	return response, result, err
}

func (c *client) rawSyncWithSameRequest(ctx context.Context, body []byte) (apiResult, apiResult) {
	type response struct{ result apiResult }
	ch := make(chan response, 2)
	for i := 0; i < 2; i++ {
		go func() {
			ch <- response{result: c.post(ctx, protocol.PathSync, body)}
		}()
	}
	first := (<-ch).result
	second := (<-ch).result
	return first, second
}
