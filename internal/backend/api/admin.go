package api

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"
	"telehack2026/internal/backend/store"
	"telehack2026/internal/backend/web"
	"telehack2026/internal/protocol"
)

const (
	adminSessionCookie = "telehack_admin"
	adminCSRFCookie    = "telehack_csrf"
	adminAPIPrefix     = "/api/admin/v1/"
	adminLoginFailures = 5
	adminLoginWindow   = 5 * time.Minute
)

var dummyPasswordHash = func() []byte {
	hash, err := bcrypt.GenerateFromPassword([]byte("telehack-invalid-password"), 12)
	if err != nil {
		panic(err)
	}
	return hash
}()

type adminLoginLimiter struct {
	mu       sync.Mutex
	failures map[string][]time.Time
}

func newAdminLoginLimiter() *adminLoginLimiter {
	return &adminLoginLimiter{failures: make(map[string][]time.Time)}
}

func (l *adminLoginLimiter) blocked(key string, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	entries := l.failures[key]
	cutoff := now.Add(-adminLoginWindow)
	kept := entries[:0]
	for _, entry := range entries {
		if entry.After(cutoff) {
			kept = append(kept, entry)
		}
	}
	l.failures[key] = kept
	return len(kept) >= adminLoginFailures
}

func (l *adminLoginLimiter) fail(key string, now time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.failures[key] = append(l.failures[key], now)
}

func (l *adminLoginLimiter) reset(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.failures, key)
}

func (s *Server) handleAdmin(w http.ResponseWriter, r *http.Request) {
	started := time.Now()
	recorder := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
	defer func() {
		if recovered := recover(); recovered != nil {
			s.logf("panic serving admin %s %s: %v", r.Method, r.URL.Path, recovered)
			if !recorder.wrote {
				writeAdminError(recorder, http.StatusInternalServerError, "internal_error", "internal error")
			}
		}
		s.logf("admin %s %s status=%d duration=%s remote=%s", r.Method, r.URL.Path, recorder.status, time.Since(started).Round(time.Millisecond), remoteHost(r))
	}()
	setAdminSecurityHeaders(recorder)
	switch {
	case r.URL.Path == "/healthz":
		s.adminHealth(recorder, r)
	case r.URL.Path == "/version":
		writeAdminJSON(recorder, http.StatusOK, map[string]any{"protocol_version": protocol.ProtocolVersion})
	case r.URL.Path == "/favicon.ico":
		recorder.WriteHeader(http.StatusNoContent)
	case strings.HasPrefix(r.URL.Path, adminAPIPrefix):
		s.handleAdminAPI(recorder, r)
	case r.Method == http.MethodGet:
		s.serveAdminStatic(recorder, r)
	default:
		writeAdminError(recorder, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
	}
}

func setAdminSecurityHeaders(w http.ResponseWriter) {
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
	w.Header().Set("Strict-Transport-Security", "max-age=31536000")
	w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
}

func (s *Server) adminHealth(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := contextWithTimeout(r, 5*time.Second)
	defer cancel()
	if err := s.store.DB.PingContext(ctx); err != nil {
		writeAdminError(w, http.StatusServiceUnavailable, "database_error", "database is unavailable")
		return
	}
	writeAdminJSON(w, http.StatusOK, map[string]any{"status": "ok", "time": time.Now().UTC().Format(time.RFC3339Nano)})
}

func webReadFile(fsys fs.FS, name string) ([]byte, error) {
	return fs.ReadFile(fsys, name)
}

func (s *Server) serveAdminStatic(w http.ResponseWriter, r *http.Request) {
	assets, err := web.FS()
	if err != nil {
		writeAdminError(w, http.StatusInternalServerError, "internal_error", "admin bundle is unavailable")
		return
	}
	name := strings.TrimPrefix(r.URL.Path, "/")
	if name == "" {
		name = "index.html"
	}
	switch name {
	case "index.html", "app.js", "app.css", "favicon.ico":
	default:
		http.NotFound(w, r)
		return
	}
	data, err := webReadFile(assets, name)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	contentType := "application/octet-stream"
	switch {
	case strings.HasSuffix(name, ".html"):
		contentType = "text/html; charset=utf-8"
		w.Header().Set("Cache-Control", "no-store")
	case strings.HasSuffix(name, ".js"):
		contentType = "text/javascript; charset=utf-8"
		w.Header().Set("Cache-Control", "no-cache")
	case strings.HasSuffix(name, ".css"):
		contentType = "text/css; charset=utf-8"
		w.Header().Set("Cache-Control", "no-cache")
	case strings.HasSuffix(name, ".ico"):
		contentType = "image/x-icon"
	}
	w.Header().Set("Content-Type", contentType)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(data)
}

func (s *Server) handleAdminAPI(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, adminAPIPrefix)
	if path == "login" && r.Method == http.MethodPost {
		s.adminLogin(w, r)
		return
	}
	session, csrf, ok := s.requireAdmin(w, r)
	if !ok {
		return
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		if !validAdminCSRF(r, csrf) {
			writeAdminError(w, http.StatusForbidden, "csrf_invalid", "CSRF token is missing or invalid")
			return
		}
	}
	parts := strings.Split(strings.Trim(path, "/"), "/")
	switch {
	case parts[0] == "inventory-settings" || parts[0] == "groups" || parts[0] == "folder-policies":
		s.adminInventory(w, r, session, parts)
	case path == "session" && r.Method == http.MethodGet:
		writeAdminJSON(w, http.StatusOK, map[string]any{"username": session.Username, "expires_at": session.ExpiresAt, "csrf_token": csrf})
	case path == "logout" && r.Method == http.MethodPost:
		s.adminLogout(w, r, session, csrf)
	case path == "overview" && r.Method == http.MethodGet:
		s.adminOverview(w, r)
	case path == "machines" && r.Method == http.MethodGet:
		s.adminMachines(w, r)
	case len(parts) == 2 && parts[0] == "machines" && r.Method == http.MethodGet:
		s.adminMachineDetail(w, r, parts[1])
	case len(parts) == 3 && parts[0] == "machines" && parts[2] == "jobs" && r.Method == http.MethodPost:
		s.adminCreateJob(w, r, session, parts[1])
	case path == "certificates" && r.Method == http.MethodGet:
		s.adminCertificates(w, r)
	case len(parts) == 2 && parts[0] == "certificates" && r.Method == http.MethodGet:
		s.adminCertificateDetail(w, r, parts[1])
	case path == "licensing" && r.Method == http.MethodGet:
		s.adminLicensing(w, r)
	case path == "events" && r.Method == http.MethodGet:
		s.adminEvents(w, r)
	case path == "jobs" && r.Method == http.MethodGet:
		s.adminJobs(w, r)
	case path == "config" && r.Method == http.MethodGet:
		s.adminGetConfig(w, r)
	case path == "config" && r.Method == http.MethodPut:
		s.adminPutConfig(w, r, session)
	case path == "hostnames" && r.Method == http.MethodGet:
		s.adminHostnames(w, r)
	case len(parts) == 3 && parts[0] == "hostnames" && parts[2] == "assign" && r.Method == http.MethodPost:
		s.adminAssignHostname(w, r, session, parts[1])
	case len(parts) == 3 && parts[0] == "registrations" && parts[2] == "rebind" && r.Method == http.MethodPost:
		s.adminRebind(w, r, session, parts[1])
	case len(parts) == 3 && parts[0] == "registrations" && parts[2] == "revoke" && r.Method == http.MethodPost:
		s.adminRevokeRegistration(w, r, session, parts[1])
	default:
		writeAdminError(w, http.StatusNotFound, protocol.CodeNotFound, "not found")
	}
}

func (s *Server) requireAdmin(w http.ResponseWriter, r *http.Request) (*store.AdminSession, string, bool) {
	cookie, err := r.Cookie(adminSessionCookie)
	if err != nil || cookie.Value == "" {
		writeAdminError(w, http.StatusUnauthorized, "unauthorized", "administrator authentication required")
		return nil, "", false
	}
	ctx, cancel := contextWithTimeout(r, 5*time.Second)
	defer cancel()
	session, err := s.store.ValidateAdminSession(ctx, store.TokenHash(cookie.Value))
	if errors.Is(err, sql.ErrNoRows) {
		clearAdminCookies(w)
		writeAdminError(w, http.StatusUnauthorized, "unauthorized", "administrator session is invalid or expired")
		return nil, "", false
	}
	if err != nil {
		s.logf("admin session validation failed: %v", err)
		writeAdminError(w, http.StatusServiceUnavailable, protocol.CodeDatabase, "could not validate administrator session")
		return nil, "", false
	}
	csrf := ""
	if c, err := r.Cookie(adminCSRFCookie); err == nil {
		csrf = c.Value
	}
	return session, csrf, true
}

func validAdminCSRF(r *http.Request, cookieValue string) bool {
	header := r.Header.Get("X-CSRF-Token")
	if cookieValue == "" || header == "" {
		return false
	}
	if len(cookieValue) != len(header) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(cookieValue), []byte(header)) == 1
}

func (s *Server) adminLogin(w http.ResponseWriter, r *http.Request) {
	if !strings.HasPrefix(strings.ToLower(r.Header.Get("Content-Type")), "application/json") {
		writeAdminError(w, http.StatusBadRequest, protocol.CodeInvalidJSON, "Content-Type must be application/json")
		return
	}
	var input struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := readAdminJSON(w, r, &input); err != nil {
		writeAdminError(w, http.StatusBadRequest, protocol.CodeInvalidJSON, err.Error())
		return
	}
	input.Username = strings.TrimSpace(input.Username)
	if input.Username == "" || input.Password == "" {
		writeAdminError(w, http.StatusUnauthorized, "invalid_credentials", "invalid username or password")
		return
	}
	key := remoteHost(r)
	now := time.Now()
	if s.adminLimiter.blocked(key, now) {
		writeAdminError(w, http.StatusTooManyRequests, "rate_limited", "too many failed login attempts; try again later")
		return
	}
	ctx, cancel := contextWithTimeout(r, 10*time.Second)
	defer cancel()
	account, err := s.store.AdminByUsername(ctx, input.Username)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		s.logf("admin login lookup failed: %v", err)
		writeAdminError(w, http.StatusServiceUnavailable, protocol.CodeDatabase, "could not query administrator")
		return
	}
	hash := dummyPasswordHash
	if err == nil && !account.Disabled {
		hash = []byte(account.PasswordHash)
	}
	if bcrypt.CompareHashAndPassword(hash, []byte(input.Password)) != nil || err != nil || account.Disabled {
		s.adminLimiter.fail(key, now)
		writeAdminError(w, http.StatusUnauthorized, "invalid_credentials", "invalid username or password")
		return
	}
	s.adminLimiter.reset(key)
	token, err := randomToken()
	if err != nil {
		writeAdminError(w, http.StatusInternalServerError, protocol.CodeInternal, "could not create session")
		return
	}
	csrf, err := randomToken()
	if err != nil {
		writeAdminError(w, http.StatusInternalServerError, protocol.CodeInternal, "could not create session")
		return
	}
	ttl := time.Duration(s.config.AdminSessionHours) * time.Hour
	if ttl <= 0 {
		ttl = 12 * time.Hour
	}
	expires, err := s.store.CreateAdminSession(ctx, account.ID, store.TokenHash(token), ttl)
	if err != nil {
		s.logf("admin session creation failed: %v", err)
		writeAdminError(w, http.StatusServiceUnavailable, protocol.CodeDatabase, "could not create administrator session")
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name: adminSessionCookie, Value: token, Path: "/", HttpOnly: true, Secure: true,
		SameSite: http.SameSiteStrictMode, MaxAge: int(ttl.Seconds()),
	})
	http.SetCookie(w, &http.Cookie{
		Name: adminCSRFCookie, Value: csrf, Path: "/", HttpOnly: false, Secure: true,
		SameSite: http.SameSiteStrictMode, MaxAge: int(ttl.Seconds()),
	})
	writeAdminJSON(w, http.StatusOK, map[string]any{"username": account.Username, "expires_at": expires, "csrf_token": csrf})
}

func (s *Server) adminLogout(w http.ResponseWriter, r *http.Request, session *store.AdminSession, csrf string) {
	cookie, _ := r.Cookie(adminSessionCookie)
	ctx, cancel := contextWithTimeout(r, 5*time.Second)
	defer cancel()
	if cookie != nil {
		if err := s.store.RevokeAdminSession(ctx, store.TokenHash(cookie.Value)); err != nil {
			s.logf("admin logout revoke failed: %v", err)
		}
	}
	clearAdminCookies(w)
	writeAdminJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func clearAdminCookies(w http.ResponseWriter) {
	for _, name := range []string{adminSessionCookie, adminCSRFCookie} {
		http.SetCookie(w, &http.Cookie{Name: name, Value: "", Path: "/", HttpOnly: name == adminSessionCookie, Secure: true, SameSite: http.SameSiteStrictMode, MaxAge: -1, Expires: time.Unix(1, 0)})
	}
}

func randomToken() (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

func (s *Server) adminOverview(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := contextWithTimeout(r, 10*time.Second)
	defer cancel()
	overview, err := s.store.AdminOverview(ctx)
	if err != nil {
		s.logf("admin overview failed: %v", err)
		writeAdminError(w, http.StatusServiceUnavailable, protocol.CodeDatabase, "could not load overview")
		return
	}
	writeAdminJSON(w, http.StatusOK, overview)
}

func (s *Server) adminMachines(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := contextWithTimeout(r, 10*time.Second)
	defer cancel()
	page, err := s.store.ListMachines(ctx, store.AdminMachineFilter{
		Query: r.URL.Query().Get("query"), Status: r.URL.Query().Get("status"),
		Page: queryInt(r, "page", 1), PageSize: queryInt(r, "page_size", 25),
	})
	if err != nil {
		s.logf("admin machines failed: %v", err)
		writeAdminError(w, http.StatusServiceUnavailable, protocol.CodeDatabase, "could not load machines")
		return
	}
	writeAdminJSON(w, http.StatusOK, page)
}

func (s *Server) adminMachineDetail(w http.ResponseWriter, r *http.Request, machineID string) {
	id, err := protocol.NormalizeUUID(machineID)
	if err != nil {
		writeAdminError(w, http.StatusBadRequest, "invalid_machine", "invalid machine identifier")
		return
	}
	ctx, cancel := contextWithTimeout(r, 15*time.Second)
	defer cancel()
	detail, err := s.store.MachineDetail(ctx, id)
	if errors.Is(err, sql.ErrNoRows) {
		writeAdminError(w, http.StatusNotFound, protocol.CodeNotFound, "machine not found")
		return
	}
	if err != nil {
		s.logf("admin machine detail failed: %v", err)
		writeAdminError(w, http.StatusServiceUnavailable, protocol.CodeDatabase, "could not load machine")
		return
	}
	writeAdminJSON(w, http.StatusOK, detail)
}

func (s *Server) adminCreateJob(w http.ResponseWriter, r *http.Request, session *store.AdminSession, machineID string) {
	id, err := protocol.NormalizeUUID(machineID)
	if err != nil {
		writeAdminError(w, http.StatusBadRequest, "invalid_machine", "invalid machine identifier")
		return
	}
	ctx, cancel := contextWithTimeout(r, 10*time.Second)
	defer cancel()
	jobID, err := s.store.AddAdminJob(ctx, id, session.Username)
	if err != nil {
		s.logf("admin create job failed: %v", err)
		writeAdminError(w, http.StatusServiceUnavailable, protocol.CodeDatabase, "could not create scan job")
		return
	}
	writeAdminJSON(w, http.StatusAccepted, map[string]any{"job_id": jobID, "state": "pending"})
}

func (s *Server) adminCertificates(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := contextWithTimeout(r, 15*time.Second)
	defer cancel()
	page, err := s.store.ListCertificates(ctx, r.URL.Query().Get("query"), r.URL.Query().Get("status"), queryInt(r, "page", 1), queryInt(r, "page_size", 25))
	if err != nil {
		s.logf("admin certificates failed: %v", err)
		writeAdminError(w, http.StatusServiceUnavailable, protocol.CodeDatabase, "could not load certificates")
		return
	}
	writeAdminJSON(w, http.StatusOK, page)
}

func (s *Server) adminCertificateDetail(w http.ResponseWriter, r *http.Request, fingerprint string) {
	fingerprint = strings.ToLower(strings.TrimSpace(fingerprint))
	if len(fingerprint) != 64 {
		writeAdminError(w, http.StatusBadRequest, "invalid_certificate", "invalid certificate fingerprint")
		return
	}
	if _, err := hexDecode(fingerprint); err != nil {
		writeAdminError(w, http.StatusBadRequest, "invalid_certificate", "invalid certificate fingerprint")
		return
	}
	ctx, cancel := contextWithTimeout(r, 15*time.Second)
	defer cancel()
	detail, err := s.store.CertificateDetail(ctx, fingerprint)
	if errors.Is(err, sql.ErrNoRows) {
		writeAdminError(w, http.StatusNotFound, protocol.CodeNotFound, "certificate not found")
		return
	}
	if err != nil {
		s.logf("admin certificate detail failed: %v", err)
		writeAdminError(w, http.StatusServiceUnavailable, protocol.CodeDatabase, "could not load certificate")
		return
	}
	writeAdminJSON(w, http.StatusOK, detail)
}

func (s *Server) adminLicensing(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := contextWithTimeout(r, 15*time.Second)
	defer cancel()
	page, err := s.store.ListLicensing(ctx, r.URL.Query().Get("query"), r.URL.Query().Get("kind"), queryInt(r, "page", 1), queryInt(r, "page_size", 25))
	if err != nil {
		s.logf("admin licensing failed: %v", err)
		writeAdminError(w, http.StatusServiceUnavailable, protocol.CodeDatabase, "could not load licensing data")
		return
	}
	writeAdminJSON(w, http.StatusOK, page)
}

func (s *Server) adminEvents(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := contextWithTimeout(r, 15*time.Second)
	defer cancel()
	page, err := s.store.ListEvents(ctx, r.URL.Query().Get("machine_id"), r.URL.Query().Get("severity"), r.URL.Query().Get("query"), queryInt(r, "page", 1), queryInt(r, "page_size", 30))
	if err != nil {
		s.logf("admin events failed: %v", err)
		writeAdminError(w, http.StatusServiceUnavailable, protocol.CodeDatabase, "could not load events")
		return
	}
	writeAdminJSON(w, http.StatusOK, page)
}

func (s *Server) adminJobs(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := contextWithTimeout(r, 10*time.Second)
	defer cancel()
	page, err := s.store.ListJobs(ctx, r.URL.Query().Get("machine_id"), r.URL.Query().Get("state"), queryInt(r, "page", 1), queryInt(r, "page_size", 25))
	if err != nil {
		s.logf("admin jobs failed: %v", err)
		writeAdminError(w, http.StatusServiceUnavailable, protocol.CodeDatabase, "could not load jobs")
		return
	}
	writeAdminJSON(w, http.StatusOK, page)
}

func (s *Server) adminGetConfig(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := contextWithTimeout(r, 10*time.Second)
	defer cancel()
	cfg, hash, err := s.store.Config(ctx)
	if err != nil {
		s.logf("admin config read failed: %v", err)
		writeAdminError(w, http.StatusServiceUnavailable, protocol.CodeDatabase, "could not load configuration")
		return
	}
	writeAdminJSON(w, http.StatusOK, map[string]any{"config": cfg, "config_hash": hash})
}

func (s *Server) adminPutConfig(w http.ResponseWriter, r *http.Request, session *store.AdminSession) {
	var cfg protocol.AgentConfig
	if err := readAdminJSON(w, r, &cfg); err != nil {
		writeAdminError(w, http.StatusBadRequest, protocol.CodeInvalidJSON, err.Error())
		return
	}
	ctx, cancel := contextWithTimeout(r, 15*time.Second)
	defer cancel()
	_, oldHash, _ := s.store.Config(ctx)
	updated, hash, err := s.store.SetConfig(ctx, cfg, session.Username)
	if err != nil {
		writeAdminError(w, http.StatusUnprocessableEntity, protocol.CodeConfigInvalid, err.Error())
		return
	}
	s.store.InsertAdminEvent(ctx, nil, "config_changed", "warning", "administrator changed collection configuration", map[string]any{
		"admin": session.Username, "old_hash": oldHash, "new_hash": hash,
		"scan_interval_days": updated.ScanIntervalDays, "cert_directories": updated.CertDirectories,
	})
	writeAdminJSON(w, http.StatusOK, map[string]any{"config": updated, "config_hash": hash})
}

func (s *Server) adminHostnames(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := contextWithTimeout(r, 15*time.Second)
	defer cancel()
	hostnames, err := s.store.ListHostnames(ctx)
	if err != nil {
		s.logf("admin hostnames failed: %v", err)
		writeAdminError(w, http.StatusServiceUnavailable, protocol.CodeDatabase, "could not load hostnames")
		return
	}
	writeAdminJSON(w, http.StatusOK, map[string]any{"items": hostnames})
}

func (s *Server) adminAssignHostname(w http.ResponseWriter, r *http.Request, session *store.AdminSession, rawHostname string) {
	hostname, err := url.PathUnescape(rawHostname)
	if err != nil {
		writeAdminError(w, http.StatusBadRequest, "invalid_hostname", "invalid hostname")
		return
	}
	var input struct {
		RegistrationID int64 `json:"registration_id"`
	}
	if err := readAdminJSON(w, r, &input); err != nil {
		writeAdminError(w, http.StatusBadRequest, protocol.CodeInvalidJSON, err.Error())
		return
	}
	ctx, cancel := contextWithTimeout(r, 10*time.Second)
	defer cancel()
	if err := s.store.AssignHostname(ctx, hostname, input.RegistrationID, session.Username); err != nil {
		writeAdminError(w, http.StatusUnprocessableEntity, "hostname_assign_failed", err.Error())
		return
	}
	writeAdminJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) adminRevokeRegistration(w http.ResponseWriter, r *http.Request, session *store.AdminSession, rawID string) {
	registrationID, err := strconv.ParseInt(rawID, 10, 64)
	if err != nil || registrationID <= 0 {
		writeAdminError(w, http.StatusBadRequest, "invalid_registration", "invalid registration identifier")
		return
	}
	ctx, cancel := contextWithTimeout(r, 10*time.Second)
	defer cancel()
	if err := s.store.RevokeRegistration(ctx, registrationID, session.Username); err != nil {
		writeAdminError(w, http.StatusUnprocessableEntity, "revoke_failed", err.Error())
		return
	}
	writeAdminJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) adminRebind(w http.ResponseWriter, r *http.Request, session *store.AdminSession, rawID string) {
	registrationID, err := strconv.ParseInt(rawID, 10, 64)
	if err != nil || registrationID <= 0 {
		writeAdminError(w, http.StatusBadRequest, "invalid_registration", "invalid registration identifier")
		return
	}
	var input struct {
		MachineID    string `json:"machine_id"`
		PublicKeyPEM string `json:"public_key_pem"`
	}
	if err := readAdminJSON(w, r, &input); err != nil {
		writeAdminError(w, http.StatusBadRequest, protocol.CodeInvalidJSON, err.Error())
		return
	}
	machineID, err := protocol.NormalizeUUID(input.MachineID)
	if err != nil {
		writeAdminError(w, http.StatusBadRequest, "invalid_machine", "invalid machine identifier")
		return
	}
	ctx, cancel := contextWithTimeout(r, 10*time.Second)
	defer cancel()
	fingerprint, err := s.store.RebindRegistrationKey(ctx, machineID, registrationID, input.PublicKeyPEM, session.Username)
	if err != nil {
		writeAdminError(w, http.StatusUnprocessableEntity, "rebind_failed", err.Error())
		return
	}
	writeAdminJSON(w, http.StatusOK, map[string]any{"ok": true, "key_fingerprint": fingerprint})
}

func readAdminJSON(w http.ResponseWriter, r *http.Request, target any) error {
	r.Body = http.MaxBytesReader(w, r.Body, 256*1024)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		if errors.Is(err, io.EOF) {
			return fmt.Errorf("empty request body")
		}
		return fmt.Errorf("invalid JSON: %v", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return fmt.Errorf("request body contains trailing JSON")
	}
	return nil
}

func queryInt(r *http.Request, name string, fallback int) int {
	value := r.URL.Query().Get(name)
	if value == "" {
		return fallback
	}
	n, err := strconv.Atoi(value)
	if err != nil {
		return fallback
	}
	return n
}

func writeAdminJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", protocol.ContentTypeJSON)
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func writeAdminError(w http.ResponseWriter, status int, code, message string) {
	writeAdminJSON(w, status, protocol.ErrorResponse{Error: protocol.APIError{Code: code, Message: message}})
}

// hexDecode only validates fingerprint syntax; the store canonicalizes keys.
func hexDecode(value string) ([]byte, error) {
	out := make([]byte, len(value)/2)
	for i := 0; i < len(out); i++ {
		hi, ok1 := hexNibble(value[i*2])
		lo, ok2 := hexNibble(value[i*2+1])
		if !ok1 || !ok2 {
			return nil, fmt.Errorf("not hexadecimal")
		}
		out[i] = hi<<4 | lo
	}
	if len(value)%2 != 0 {
		return nil, fmt.Errorf("odd length")
	}
	return out, nil
}

func hexNibble(ch byte) (byte, bool) {
	switch {
	case ch >= '0' && ch <= '9':
		return ch - '0', true
	case ch >= 'a' && ch <= 'f':
		return ch - 'a' + 10, true
	case ch >= 'A' && ch <= 'F':
		return ch - 'A' + 10, true
	}
	return 0, false
}

// contextWithTimeout keeps admin handlers bounded even if a client stalls.
func contextWithTimeout(r *http.Request, timeout time.Duration) (ctx context.Context, cancel context.CancelFunc) {
	return context.WithTimeout(r.Context(), timeout)
}
