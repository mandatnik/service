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

	"mandatnik/internal/backend/config"
	"mandatnik/internal/backend/store"
	"mandatnik/internal/protocol"
)

// Logger is the minimal logging interface used by the API.
type Logger interface {
	Logf(format string, args ...any)
}

// Server owns both agent and administrative handlers. It is one process and
// shares the SQL pool; there is no broker or second service.
type Server struct {
	store        *store.Store
	logger       Logger
	config       config.Config
	dns          *dnsCache
	requests     chan struct{}
	reports      chan struct{}
	adminLimiter *adminLoginLimiter
}

// New creates the API server.
func New(persistence *store.Store, logger Logger, cfg config.Config) *Server {
	return &Server{
		store:        persistence,
		logger:       logger,
		config:       cfg,
		dns:          newDNSCache(5 * time.Minute),
		requests:     make(chan struct{}, cfg.MaxConcurrentRequests),
		reports:      make(chan struct{}, cfg.MaxConcurrentReports),
		adminLimiter: newAdminLoginLimiter(),
	}
}

// AgentHandler returns the agent API handler.
func (s *Server) AgentHandler() http.Handler {
	return http.HandlerFunc(s.handleAgent)
}

// AdminHandler returns the administrative listener handler. The same
// embedded bundle is served by the backend EXE; API calls require a local
// administrator session.
func (s *Server) AdminHandler() http.Handler {
	return http.HandlerFunc(s.handleAdmin)
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
	case protocol.PathCapabilities:
		s.handleCapabilities(recorder, r, body)
	case protocol.PathTaskSync:
		s.handleTaskSync(recorder, r, body)
	case protocol.PathTaskAck:
		s.handleTaskAck(recorder, r, body)
	case protocol.PathTaskClaim:
		s.handleTaskClaim(recorder, r, body)
	case protocol.PathTaskProgress:
		s.handleTaskProgress(recorder, r, body)
	case protocol.PathTaskResult:
		s.handleTaskResult(recorder, r, body)
	case protocol.PathTaskDiagnostic:
		s.handleTaskDiagnostic(recorder, r, body)
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
	dnsVerification := s.dns.verification(r.Context(), request.Data.Hostname, sourceIP)
	result, apiErr := s.store.Register(r.Context(), request, sourceIP, dnsVerification.Forward)
	if apiErr != nil {
		writeAPIError(w, apiErr)
		return
	}
	s.store.RecordDNSVerification(r.Context(), result.UUID, dnsVerification)
	writeJSON(w, http.StatusOK, protocol.RegisterResponse{
		MachineID: result.MachineID, UUID: result.UUID, Hostname: result.Hostname,
		RegisteredAt: result.RegisteredAt.UTC().Format(time.RFC3339Nano),
		Config:       result.Config, ConfigHash: result.ConfigHash,
		ServerTime: time.Now().UTC().Format(time.RFC3339Nano), Warnings: result.Warnings,
	})
}

func (s *Server) handleRename(w http.ResponseWriter, r *http.Request, body []byte) {
	_, request, apiErr := s.verifyRequest(r.Context(), body, protocol.PathRename)
	if apiErr != nil {
		writeAPIError(w, apiErr)
		return
	}
	sourceIP := sourceIP(r)
	dnsVerification := s.dns.verification(r.Context(), request.Data.NewHostname, sourceIP)
	result, apiErr := s.store.Rename(r.Context(), request, sourceIP, dnsVerification.Forward)
	if apiErr != nil {
		writeAPIError(w, apiErr)
		return
	}
	s.store.RecordDNSVerification(r.Context(), result.UUID, dnsVerification)
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
	dnsVerification := s.dns.verification(r.Context(), identity.Hostname, sourceIP)
	result, apiErr := s.store.Sync(r.Context(), identity, request, sourceIP, dnsVerification.Forward)
	if apiErr != nil {
		writeAPIError(w, apiErr)
		return
	}
	s.store.RecordDNSVerification(r.Context(), identity.UUID, dnsVerification)
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
	s.store.RecordDNSWarning(r.Context(), identity.MachineID, dnsVerification.Forward)
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
		w.Header().Set("Retry-After", "1")
		s.logf("report rejected: busy (capacity=%d)", cap(s.reports))
		writeError(w, http.StatusServiceUnavailable, protocol.CodeServerBusy, "report processing is busy")
		return
	}
	sourceIP := sourceIP(r)
	dnsVerification := s.dns.verification(r.Context(), identity.Hostname, sourceIP)
	response, apiErr := s.store.SubmitReport(r.Context(), identity, request, sourceIP, dnsVerification.Forward)
	if apiErr != nil {
		writeAPIError(w, apiErr)
		return
	}
	s.store.UpdateNetworkTrust(r.Context(), identity, sourceIP, dnsVerification.Forward)
	s.store.RecordDNSVerification(r.Context(), identity.UUID, dnsVerification)
	s.store.RecordDNSWarning(r.Context(), identity.MachineID, dnsVerification.Forward)
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
		protocol.PathRename:         protocol.OpRename,
		protocol.PathSync:           protocol.OpSync,
		protocol.PathReport:         protocol.OpReport,
		protocol.PathJobAck:         protocol.OpJobAck,
		protocol.PathCapabilities:   protocol.OpCapabilities,
		protocol.PathTaskSync:       protocol.OpTaskSync,
		protocol.PathTaskAck:        protocol.OpTaskAck,
		protocol.PathTaskClaim:      protocol.OpTaskClaim,
		protocol.PathTaskProgress:   protocol.OpTaskProgress,
		protocol.PathTaskResult:     protocol.OpTaskResult,
		protocol.PathTaskDiagnostic: protocol.OpTaskDiagnostic,
	}[path]
	if expectedOperation == "" || request.Data.Operation != expectedOperation {
		return nil, nil, &protocol.APIError{Code: protocol.CodeInvalidEnvelope, Message: "signed operation does not match the endpoint"}
	}
	return identity, request, nil
}

func readBody(w http.ResponseWriter, r *http.Request) ([]byte, *protocol.APIError) {
	limit := int64(protocol.MaxSmallRequestBytes)
	if r.URL.Path == protocol.PathReport {
		limit = protocol.MaxRequestBytes
	}
	r.Body = http.MaxBytesReader(w, r.Body, limit)
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
	case protocol.CodeInstallationPending, protocol.CodeInstallationStale, protocol.CodeInstallationConflict:
		status = http.StatusConflict
	case protocol.CodeInstallationRejected:
		status = http.StatusForbidden
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
	refresh chan struct{}
}

type dnsEntry struct {
	status        string
	reverseStatus string
	checkedAt     time.Time
	expires       time.Time
	addresses     []string
	refreshing    bool
}

func newDNSCache(ttl time.Duration) *dnsCache {
	return &dnsCache{ttl: ttl, entries: make(map[string]dnsEntry), refresh: make(chan struct{}, 4)}
}

func dnsCacheKey(hostname string, source net.IP) string {
	return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(hostname), ".")) + "|" + source.String()
}

// status returns the cached forward trust signal and never blocks on DNS. It
// is kept for callers that only need the hostname -> source IP direction.
func (d *dnsCache) status(ctx context.Context, hostname string, source net.IP) string {
	return d.verification(ctx, hostname, source).Forward
}

// verification returns the cached mutual DNS result and never blocks on DNS.
// A missing or expired entry is refreshed in the background; the request sees
// "unknown" or the previous value. Reverse lookup is part of the same refresh,
// so the machine list does not perform network DNS requests.
func (d *dnsCache) verification(ctx context.Context, hostname string, source net.IP) store.DNSVerification {
	verification := store.DNSVerification{
		Forward:  "unknown",
		Reverse:  "unknown",
		Hostname: strings.TrimSuffix(strings.TrimSpace(hostname), "."),
		SourceIP: source,
	}
	if d == nil || verification.Hostname == "" || source == nil {
		return verification
	}
	key := dnsCacheKey(verification.Hostname, source)
	d.mu.Lock()
	entry, ok := d.entries[key]
	d.mu.Unlock()
	if ok && time.Now().Before(entry.expires) {
		return verificationFromEntry(verification, entry)
	}
	d.refreshAsync(key, verification.Hostname, source)
	if !ok {
		return verification
	}
	return verificationFromEntry(verification, entry)
}

func verificationFromEntry(verification store.DNSVerification, entry dnsEntry) store.DNSVerification {
	verification.Forward = entry.status
	verification.Reverse = entry.reverseStatus
	verification.CheckedAt = entry.checkedAt
	return verification
}

func (d *dnsCache) refreshAsync(key, hostname string, source net.IP) {
	d.mu.Lock()
	entry, ok := d.entries[key]
	if entry.refreshing {
		d.mu.Unlock()
		return
	}
	if !ok {
		entry.status = "unknown"
		entry.reverseStatus = "unknown"
		entry.expires = time.Now()
	}
	entry.refreshing = true
	d.entries[key] = entry
	d.mu.Unlock()
	select {
	case d.refresh <- struct{}{}:
	default:
		// A bounded number of lookups is already in flight. Keep serving the
		// cached value and let the next request schedule the refresh.
		d.mu.Lock()
		entry.refreshing = false
		d.entries[key] = entry
		d.mu.Unlock()
		return
	}
	go func() {
		defer func() { <-d.refresh }()
		lookupCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		reverse := "error"
		var reverseWait sync.WaitGroup
		reverseWait.Add(1)
		go func() {
			defer reverseWait.Done()
			names, reverseErr := net.DefaultResolver.LookupAddr(lookupCtx, source.String())
			if reverseErr != nil {
				return
			}
			reverse = "mismatch"
			if reverseMatchesHostname(names, hostname) {
				reverse = "verified"
			}
		}()
		addresses, err := net.DefaultResolver.LookupHost(lookupCtx, hostname)
		status := "verified"
		if err != nil {
			status = "error"
			addresses = nil
		}
		reverseWait.Wait()
		forward := compareDNS(addresses, source, status)
		checkedAt := time.Now().UTC()
		d.mu.Lock()
		d.entries[key] = dnsEntry{
			status: forward, reverseStatus: reverse, checkedAt: checkedAt,
			expires: time.Now().Add(d.ttl), addresses: addresses,
		}
		d.mu.Unlock()
	}()
}

// reverseMatchesHostname accepts the exact PTR name or an FQDN whose first
// label is the short hostname. This keeps short NetBIOS-style names useful
// without treating an unrelated prefix such as "ws-10" as "ws-1".
func reverseMatchesHostname(names []string, hostname string) bool {
	host := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(hostname), "."))
	if host == "" {
		return false
	}
	for _, raw := range names {
		name := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(raw), "."))
		if name == host {
			return true
		}
		// A PTR usually returns an FQDN even when the agent reports a short
		// NetBIOS-style name. Accept that only for short names; an FQDN must
		// match exactly, otherwise "example.com.evil" would match
		// "example.com".
		if !strings.Contains(host, ".") && strings.HasPrefix(name, host+".") {
			return true
		}
	}
	return false
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
