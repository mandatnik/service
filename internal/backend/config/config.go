// Package config loads and validates the backend configuration. Secrets are
// referenced by environment variable name and never stored in the JSON file.
package config

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"telehack2026/internal/platform"
	"telehack2026/internal/protocol"
)

// DB describes the SQL Server connection.
type DB struct {
	Server                 string `json:"server"`
	Port                   int    `json:"port"`
	Database               string `json:"database"`
	User                   string `json:"user"`
	PasswordEnv            string `json:"password_env"`
	PasswordFile           string `json:"password_file"`
	Encrypt                bool   `json:"encrypt"`
	TrustServerCertificate bool   `json:"trust_server_certificate"`
	AllowInsecureDBTLS     bool   `json:"allow_insecure_db_tls"`
	ServerName             string `json:"server_name"`
	CAFile                 string `json:"ca_file"`
	ConnectTimeoutSeconds  int    `json:"connect_timeout_seconds"`
}

// Config is the backend bootstrap configuration.
type Config struct {
	AgentListen           string `json:"agent_listen"`
	AdminListen           string `json:"admin_listen"`
	TLSCertFile           string `json:"tls_cert_file"`
	TLSKeyFile            string `json:"tls_key_file"`
	LogFile               string `json:"log_file"`
	MaxConcurrentReports  int    `json:"max_concurrent_reports"`
	MaxConcurrentRequests int    `json:"max_concurrent_requests"`
	AdminSessionHours     int    `json:"admin_session_hours"`
	DB                    DB     `json:"db"`

	// Path is filled by Load and is not part of the JSON schema.
	Path string `json:"-"`
}

// Load reads and validates a backend configuration. An empty path uses the
// ProgramData default.
func Load(path string) (Config, error) {
	if path == "" {
		path = platform.BackendConfigPath()
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return Config{}, fmt.Errorf("read backend config %s: %w", path, err)
	}
	if err := protocol.RejectDuplicateKeys(raw); err != nil {
		return Config{}, fmt.Errorf("backend config %s: %w", path, err)
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var cfg Config
	if err := decoder.Decode(&cfg); err != nil {
		return Config{}, fmt.Errorf("decode backend config %s: %w", path, err)
	}
	cfg.Path = path
	if err := cfg.Validate(); err != nil {
		return Config{}, fmt.Errorf("backend config %s: %w", path, err)
	}
	return cfg, nil
}

// Validate checks all required values and safe defaults.
func (c *Config) Validate() error {
	if err := validateListen("agent_listen", c.AgentListen); err != nil {
		return err
	}
	if err := validateListen("admin_listen", c.AdminListen); err != nil {
		return err
	}
	if c.AgentListen == c.AdminListen {
		return fmt.Errorf("agent_listen and admin_listen must differ")
	}
	if c.TLSCertFile == "" || c.TLSKeyFile == "" {
		return fmt.Errorf("tls_cert_file and tls_key_file are required")
	}
	if c.LogFile == "" {
		c.LogFile = filepath.Join(platform.BackendLogDir(), "backend.txt")
	}
	if c.MaxConcurrentReports == 0 {
		c.MaxConcurrentReports = 8
	}
	if c.MaxConcurrentReports < 1 || c.MaxConcurrentReports > 128 {
		return fmt.Errorf("max_concurrent_reports must be between 1 and 128")
	}
	if c.MaxConcurrentRequests == 0 {
		c.MaxConcurrentRequests = 64
	}
	if c.MaxConcurrentRequests < 1 || c.MaxConcurrentRequests > 1024 {
		return fmt.Errorf("max_concurrent_requests must be between 1 and 1024")
	}
	if c.AdminSessionHours == 0 {
		c.AdminSessionHours = 12
	}
	if c.AdminSessionHours < 1 || c.AdminSessionHours > 72 {
		return fmt.Errorf("admin_session_hours must be between 1 and 72")
	}
	if err := c.DB.Validate(); err != nil {
		return err
	}
	return nil
}

// Validate checks DB connectivity settings.
func (d *DB) Validate() error {
	if strings.TrimSpace(d.Server) == "" {
		return fmt.Errorf("db.server is required")
	}
	if d.Port == 0 {
		d.Port = 1433
	}
	if d.Port < 1 || d.Port > 65535 {
		return fmt.Errorf("db.port is invalid")
	}
	if strings.TrimSpace(d.Database) == "" {
		return fmt.Errorf("db.database is required")
	}
	switch strings.ToLower(d.Database) {
	case "master", "tempdb", "model", "msdb":
		return fmt.Errorf("db.database must be an application database, not %q", d.Database)
	}
	if strings.TrimSpace(d.User) == "" {
		return fmt.Errorf("db.user is required")
	}
	if strings.TrimSpace(d.PasswordEnv) == "" && strings.TrimSpace(d.PasswordFile) == "" {
		return fmt.Errorf("db.password_env or db.password_file is required")
	}
	if !d.Encrypt {
		return fmt.Errorf("db.encrypt=false is not supported; SQL TLS is required")
	}
	if d.TrustServerCertificate && !d.AllowInsecureDBTLS {
		return fmt.Errorf("db.trust_server_certificate requires explicit allow_insecure_db_tls")
	}
	if d.ConnectTimeoutSeconds == 0 {
		d.ConnectTimeoutSeconds = 15
	}
	if d.ConnectTimeoutSeconds < 3 || d.ConnectTimeoutSeconds > 120 {
		return fmt.Errorf("db.connect_timeout_seconds must be between 3 and 120")
	}
	return nil
}

// Password reads the runtime DB password from the configured environment
// variable. The value is never logged or returned in diagnostics.
func (d DB) Password() (string, error) {
	if d.PasswordEnv != "" {
		if value := os.Getenv(d.PasswordEnv); value != "" {
			return strings.TrimRight(value, "\r\n"), nil
		}
	}
	if d.PasswordFile != "" {
		raw, err := os.ReadFile(d.PasswordFile)
		if err != nil {
			return "", fmt.Errorf("read db.password_file: %w", err)
		}
		value := strings.TrimSpace(string(raw))
		if value == "" {
			return "", fmt.Errorf("db.password_file is empty")
		}
		return value, nil
	}
	return "", fmt.Errorf("database password is not available")
}

func validateListen(name, value string) error {
	if strings.TrimSpace(value) == "" {
		return fmt.Errorf("%s is required", name)
	}
	host, port, err := net.SplitHostPort(value)
	if err != nil {
		return fmt.Errorf("%s must be host:port: %w", name, err)
	}
	if host == "" {
		// 0.0.0.0 is required for an intentional listener; an empty host in
		// net.Listen means all interfaces, which is equivalent and allowed.
	}
	number, err := strconv.Atoi(port)
	if err != nil || number < 1 || number > 65535 {
		return fmt.Errorf("%s has an invalid port", name)
	}
	return nil
}
