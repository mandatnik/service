package agent

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"strings"

	"mandatnik/internal/platform"
	"mandatnik/internal/protocol"
)

// FileConfig is the small bootstrap file managed by GPO or created manually
// for a non-domain test. It intentionally contains no TLS bypass switch.
type FileConfig struct {
	ServerURL             string `json:"server_url"`
	RequestTimeoutSeconds int    `json:"request_timeout_seconds,omitempty"`
}

// LoadFileConfig reads the agent bootstrap file. An explicit empty path uses
// the ProgramData default.
func LoadFileConfig(path string) (FileConfig, error) {
	if path == "" {
		path = platform.AgentConfigPath()
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return FileConfig{}, fmt.Errorf("read agent config %s: %w", path, err)
	}
	if err := protocol.RejectDuplicateKeys(raw); err != nil {
		return FileConfig{}, fmt.Errorf("agent config %s: %w", path, err)
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var cfg FileConfig
	if err := decoder.Decode(&cfg); err != nil {
		return FileConfig{}, fmt.Errorf("decode agent config %s: %w", path, err)
	}
	if err := cfg.Validate(); err != nil {
		return FileConfig{}, fmt.Errorf("agent config %s: %w", path, err)
	}
	return cfg, nil
}

// Validate checks the bootstrap URL and timeout bounds.
func (c *FileConfig) Validate() error {
	c.ServerURL = strings.TrimSpace(c.ServerURL)
	if c.ServerURL == "" {
		return fmt.Errorf("server_url is required")
	}
	parsed, err := url.Parse(c.ServerURL)
	if err != nil {
		return fmt.Errorf("server_url: %w", err)
	}
	if parsed.Scheme != "https" {
		return fmt.Errorf("server_url must use https")
	}
	if parsed.Host == "" {
		return fmt.Errorf("server_url has no host")
	}
	if parsed.User != nil {
		return fmt.Errorf("server_url must not contain credentials")
	}
	if parsed.Path != "" && parsed.Path != "/" {
		return fmt.Errorf("server_url must not contain a path")
	}
	if c.RequestTimeoutSeconds == 0 {
		c.RequestTimeoutSeconds = 30
	}
	if c.RequestTimeoutSeconds < 5 || c.RequestTimeoutSeconds > 120 {
		return fmt.Errorf("request_timeout_seconds must be between 5 and 120")
	}
	c.ServerURL = strings.TrimRight(c.ServerURL, "/")
	return nil
}
