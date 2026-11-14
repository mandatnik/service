package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"telehack2026/internal/backend/config"
	"telehack2026/internal/backend/store"
	"telehack2026/internal/protocol"
)

// Logger is the minimal logging interface used by the API.
type Logger interface {
	Logf(format string, args ...any)
}

// Server owns both agent and administrative handlers. It is one process and
// shares the SQL pool; there is no broker or second service.
type Server struct {
	store    *store.Store
	logger   Logger
	config   config.Config
	dns      *dnsCache
	requests chan struct{}
	reports  chan struct{}
}

// New creates the API server.
func New(persistence *store.Store, logger Logger, cfg config.Config) *Server {
	return &Server{
		store:    persistence,
		logger:   logger,
		config:   cfg,
		dns:      newDNSCache(5 * time.Minute),
		requests: make(chan struct{}, cfg.MaxConcurrentRequests),
		reports:  make(chan struct{}, cfg.MaxConcurrentReports),
	}
}

// AgentHandler returns the agent API handler.
func (s *Server) AgentHandler() http.Handler {
	return http.HandlerFunc(s.handleAgent)
}

// AdminHandler returns the administrative listener handler. P07 exposes only
// health/version; authenticated administration is P08.
func (s *Server) AdminHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/healthz":
			ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
			defer cancel()
			if err := s.store.DB.PingContext(ctx); err != nil {
				writeError(w, http.StatusServiceUnavailable, protocol.CodeDatabase, "database is unavailable")
				return
			}
			writeJSON(w, http.StatusOK, map[string]any{"status": "ok", "time": time.Now().UTC().Format(time.RFC3339Nano)})
		case "/version":
			writeJSON(w, http.StatusOK, map[string]any{"protocol_version": protocol.ProtocolVersion})
		case "/":
			writeJSON(w, http.StatusOK, map[string]any{"service": "telehack-backend", "protocol_version": protocol.ProtocolVersion})
		default:
			writeError(w, http.StatusNotFound, protocol.CodeNotFound, "not found")
		}
	})
}

func (s *Server) handleAgent(w http.ResponseWriter, r *http.Request) {
	started := time.Now()
	recorder := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
	defer func() {
		if recovered := recover(); recovered != nil {
			s.logf("panic serving %s %s: %v", r.Method, r.URL.Path, recovered)
			if !recorder.wrote {
				writeError(recorder, http.StatusInternalServerError, protocol.CodeInternal, "internal error")
			}
		}
		s.logf("%s %s status=%d duration=%s remote=%s", r.Method, r.URL.Path, recorder.status, time.Since(started).Round(time.Millisecond), remoteHost(r))
	}()
	if r.Method != http.MethodPost {
		writeError(recorder, http.StatusMethodNotAllowed, protocol.CodeMethodNotAllowed, "only POST is supported")
		return
	}
	if !strings.HasPrefix(strings.ToLower(r.Header.Get("Content-Type")), protocol.ContentTypeJSON) {
		writeError(recorder, http.StatusBadRequest, protocol.CodeInvalidJSON, "Content-Type must be application/json")
		return
	}
	select {
	case s.requests <- struct{}{}:
		defer func() { <-s.requests }()
	default:
		writeError(recorder, http.StatusServiceUnavailable, protocol.CodeInternal, "server is busy")
		return
	}
	body, apiErr := readBody(recorder, r)
	if apiErr != nil {
		writeAPIError(recorder, apiErr)
		return
	}
	switch r.URL.Path {
	case protocol.PathRegister:
		s.handleRegister(recorder, r, body)
	case protocol.PathRename:
		s.handleRename(recorder, r, body)
	case protocol.PathSync:
		s.handleSync(recorder, r, body)
	case protocol.PathReport:
		s.handleReport(recorder, r, body)
	case protocol.PathJobAck:
		s.handleJobAck(recorder, r, body)
	default:
		writeError(recorder, http.StatusNotFound, protocol.CodeNotFound, "unknown agent endpoint")
	}
}

func (s *Server) handleRegister(w http.ResponseWriter, r *http.Request, body []byte) {
	request, apiErr := protocol.OpenBootstrapEnvelope(body, protocol.MethodPost, protocol.PathRegister)
	if apiErr != nil {
		writeAPIError(w, apiErr)
		return
	}
	sourceIP := sourceIP(r)
	dnsStatus := s.dns.status(r.Context(), request.Data.Hostname, sourceIP)
	result, apiErr := s.store.Register(r.Context(), request, sourceIP, dnsStatus)
	if apiErr != nil {
		writeAPIError(w, apiErr)
		return
	}
	writeJSON(w, http.StatusOK, protocol.RegisterResponse{
		MachineID: result.MachineID, UUID: result.UUID, Hostname: result.Hostname,
		RegisteredAt: result.RegisteredAt.UTC().Format(time.RFC3339Nano),
		Config:       result.Config, ConfigHash: result.ConfigHash,
		ServerTime: time.Now().UTC().Format(time.RFC3339Nano), Warnings: result.Warnings,
	})
}

func (s *Server) handleRename(w http.ResponseWriter, r *http.Request, body []byte) {
	identity, request, apiErr := s.verifyRequest(r.Context(), body, protocol.PathRename)
	if apiErr != nil {
		writeAPIError(w, apiErr)
		return
	}
	sourceIP := sourceIP(r)
	dnsStatus := s.dns.status(r.Context(), identity.Hostname, sourceIP)
	result, apiErr := s.store.Rename(r.Context(), request, sourceIP, dnsStatus)
	if apiErr != nil {
		writeAPIError(w, apiErr)
		return
	}
	writeJSON(w, http.StatusOK, protocol.RegisterResponse{
		MachineID: result.MachineID, UUID: result.UUID, Hostname: result.Hostname,
		RegisteredAt: result.RegisteredAt.UTC().Format(time.RFC3339Nano),
		Config:       result.Config, ConfigHash: result.ConfigHash,
		ServerTime: time.Now().UTC().Format(time.RFC3339Nano), Warnings: result.Warnings,
	})
}

func (s *Server) handleSync(w http.ResponseWriter, r *http.Request, body []byte) {
	identity, request, apiErr := s.verifyRequest(r.Context(), body, protocol.PathSync)
	if apiErr != nil {
		writeAPIError(w, apiErr)
		return
	}
	sourceIP := sourceIP(r)
	dnsStatus := s.dns.status(r.Context(), identity.Hostname, sourceIP)
	result, apiErr := s.store.Sync(r.Context(), identity, request, sourceIP, dnsStatus)
	if apiErr != nil {
		writeAPIError(w, apiErr)
		return
	}
	response := protocol.SyncResponse{
		ServerTime: result.ServerTime.Format(time.RFC3339Nano),
		ConfigHash: result.ConfigHash,
		Jobs:       result.Jobs,
		Warnings:   result.Warnings,
	}
	if result.Config != nil {
		cfg := *result.Config
		response.Config = &cfg
	}
	s.store.RecordDNSWarning(r.Context(), identity.MachineID, dnsStatus)
	writeJSON(w, http.StatusOK, response)
}

func (s *Server) handleReport(w http.ResponseWriter, r *http.Request, body []byte) {
	identity, request, apiErr := s.verifyRequest(r.Context(), body, protocol.PathReport)
	if apiErr != nil {
		writeAPIError(w, apiErr)
		return
	}
	select {
	case s.reports <- struct{}{}:
		defer func() { <-s.reports }()
	default:
		writeError(w, http.StatusServiceUnavailable, protocol.CodeInternal, "report processing is busy")
		return
	}
	sourceIP := sourceIP(r)
	dnsStatus := s.dns.status(r.Context(), identity.Hostname, sourceIP)
	response, apiErr := s.store.SubmitReport(r.Context(), identity, request, sourceIP, dnsStatus)
	if apiErr != nil {
		writeAPIError(w, apiErr)
		return
	}
	s.store.UpdateNetworkTrust(r.Context(), identity, sourceIP, dnsStatus)
	s.store.RecordDNSWarning(r.Context(), identity.MachineID, dnsStatus)
	writeJSON(w, http.StatusOK, response)
}

func (s *Server) handleJobAck(w http.ResponseWriter, r *http.Request, body []byte) {
	identity, request, apiErr := s.verifyRequest(r.Context(), body, protocol.PathJobAck)
	if apiErr != nil {
		writeAPIError(w, apiErr)
		return
	}
	response, apiErr := s.store.AckJob(r.Context(), identity, request)
	if apiErr != nil {
		writeAPIError(w, apiErr)
		return
	}
	writeJSON(w, http.StatusOK, response)
}

func (s *Server) verifyRequest(ctx context.Context, body []byte, path string) (*store.Identity, *protocol.SignedRequest, *protocol.APIError) {
	env, data, apiErr := protocol.PeekEnvelope(body)
	if apiErr != nil {
		return nil, nil, apiErr
	}
	_ = env
	identity, apiErr := s.store.LookupActiveIdentity(ctx, data.UUID)
	if apiErr != nil {
		return nil, nil, apiErr
	}
	publicKey, err := protocol.ParsePublicKeyPEM(identity.PublicKeyPEM)
	if err != nil {
		return nil, nil, &protocol.APIError{Code: protocol.CodeInvalidKey, Message: "stored public key is invalid"}
	}
	request, apiErr := protocol.OpenSignedEnvelope(body, protocol.MethodPost, path, publicKey)
	if apiErr != nil {
		return nil, nil, apiErr
	}
	if !strings.EqualFold(request.Data.UUID, identity.UUID) {
		return nil, nil, &protocol.APIError{Code: protocol.CodeInvalidIdentity, Message: "signed UUID does not match the registration"}
	}
	expectedOperation := map[string]string{
		protocol.PathRename: protocol.OpRename,
		protocol.PathSync:   protocol.OpSync,
		protocol.PathReport: protocol.OpReport,
		protocol.PathJobAck: protocol.OpJobAck,
	}[path]
	if expectedOperation == "" || request.Data.Operation != expectedOperation {
		return nil, nil, &protocol.APIError{Code: protocol.CodeInvalidEnvelope, Message: "signed operation does not match the endpoint"}
	}
	return identity, request, nil
}

func readBody(w http.ResponseWriter, r *http.Request) ([]byte, *protocol.APIError) {
	r.Body = http.MaxBytesReader(w, r.Body, protocol.MaxRequestBytes)
	body, err := io.ReadAll(r.Body)
	if err != nil {
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			return nil, &protocol.APIError{Code: protocol.CodePayloadTooLarge, Message: "request body exceeds limit"}
		}
		return nil, &protocol.APIError{Code: protocol.CodeInvalidJSON, Message: "could not read request body"}
	}
	if len(body) == 0 {
		return nil, &protocol.APIError{Code: protocol.CodeInvalidJSON, Message: "empty request body"}
	}
	return body, nil
}

func sourceIP(r *http.Request) net.IP {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return nil
	}
	return net.ParseIP(host)
}

func remoteHost(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", protocol.ContentTypeJSON)
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func writeError(w http.ResponseWriter, status int, code, message string) {
	writeJSON(w, status, protocol.ErrorResponse{Error: protocol.APIError{Code: code, Message: message}})
}

func writeAPIError(w http.ResponseWriter, apiErr *protocol.APIError) {
	if apiErr == nil {
		writeError(w, http.StatusInternalServerError, protocol.CodeInternal, "internal error")
		return
	}
	status := http.StatusBadRequest
	switch apiErr.Code {
	case protocol.CodeUnknownIdentity, protocol.CodeIdentityRevoked, protocol.CodeInvalidIdentity:
		status = http.StatusUnauthorized
	case protocol.CodeReplay, protocol.CodeReportConflict, protocol.CodeKeyConflict, protocol.CodeUUIDConflict, protocol.CodeHostnameMismatch, protocol.CodeJobConflict, protocol.CodeHostnameConflict:
		status = http.StatusConflict
	case protocol.CodeReportInvalid, protocol.CodeConfigInvalid:
		status = http.StatusUnprocessableEntity
	case protocol.CodePayloadTooLarge:
		status = http.StatusRequestEntityTooLarge
	case protocol.CodeNotFound:
		status = http.StatusNotFound
	case protocol.CodeMethodNotAllowed:
		status = http.StatusMethodNotAllowed
	case protocol.CodeDatabase, protocol.CodeInternal:
		status = http.StatusInternalServerError
	}
	writeJSON(w, status, protocol.ErrorResponse{Error: *apiErr})
}

type statusRecorder struct {
	http.ResponseWriter
	status int
	wrote  bool
}

func (r *statusRecorder) WriteHeader(status int) {
	if r.wrote {
		return
	}
	r.status = status
	r.wrote = true
	r.ResponseWriter.WriteHeader(status)
}

func (r *statusRecorder) Write(data []byte) (int, error) {
	if !r.wrote {
		r.WriteHeader(http.StatusOK)
	}
	return r.ResponseWriter.Write(data)
}

func (s *Server) logf(format string, args ...any) {
	if s.logger != nil {
		s.logger.Logf(format, args...)
	}
}

// dnsCache caches hostname -> source IP verification for a short period. DNS
// is a trust signal, not an authorization gate: a mismatch is accepted and
// recorded, never used to drop a correctly signed report.
type dnsCache struct {
	mu      sync.Mutex
	ttl     time.Duration
	entries map[string]dnsEntry
}

type dnsEntry struct {
	status    string
	expires   time.Time
	addresses []string
}

func newDNSCache(ttl time.Duration) *dnsCache {
	return &dnsCache{ttl: ttl, entries: make(map[string]dnsEntry)}
}

func (d *dnsCache) status(ctx context.Context, hostname string, source net.IP) string {
	if d == nil || hostname == "" || source == nil {
		return "unknown"
	}
	key := strings.ToLower(hostname)
	d.mu.Lock()
	entry, ok := d.entries[key]
	d.mu.Unlock()
	if ok && time.Now().Before(entry.expires) {
		return compareDNS(entry.addresses, source, entry.status)
	}
	lookupCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	addresses, err := net.DefaultResolver.LookupHost(lookupCtx, hostname)
	status := "verified"
	if err != nil {
		status = "error"
		addresses = nil
	} else if !containsIP(addresses, source) {
		status = "mismatch"
	}
	d.mu.Lock()
	d.entries[key] = dnsEntry{status: status, expires: time.Now().Add(d.ttl), addresses: addresses}
	d.mu.Unlock()
	return compareDNS(addresses, source, status)
}

func compareDNS(addresses []string, source net.IP, cached string) string {
	if cached == "error" || len(addresses) == 0 {
		return cached
	}
	if containsIP(addresses, source) {
		return "verified"
	}
	return "mismatch"
}

func containsIP(addresses []string, source net.IP) bool {
	for _, address := range addresses {
		if parsed := net.ParseIP(address); parsed != nil && parsed.Equal(source) {
			return true
		}
	}
	return false
}

// String is used in diagnostics without exposing request bodies.
func (s *Server) String() string {
	return fmt.Sprintf("api(requests=%d,reports=%d)", cap(s.requests), cap(s.reports))
}
