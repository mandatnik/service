package protocol

import (
	"fmt"
	"strings"
	"telehack2026/internal/folderpolicy"
	"time"

	"github.com/google/uuid"
)

// NormalizeUUID parses a canonical UUID and returns its lower-case form.
func NormalizeUUID(value string) (string, error) {
	id, err := uuid.Parse(value)
	if err != nil {
		return "", fmt.Errorf("invalid UUID %q: %w", value, err)
	}
	if id == uuid.Nil {
		return "", fmt.Errorf("nil UUID is not allowed")
	}
	return strings.ToLower(id.String()), nil
}

// NewUUID returns a random version-4 UUID in lower-case canonical form.
func NewUUID() string {
	return strings.ToLower(uuid.NewString())
}

// NormalizeHostname validates a DNS/NetBIOS hostname and removes a single
// trailing dot. Case is preserved; comparisons use EqualFold.
func NormalizeHostname(value string) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", fmt.Errorf("empty hostname")
	}
	if len(value) > MaxHostnameBytes+1 {
		return "", fmt.Errorf("hostname is too long")
	}
	value = strings.TrimSuffix(value, ".")
	if len(value) == 0 || len(value) > MaxHostnameBytes {
		return "", fmt.Errorf("hostname length out of range")
	}
	for _, r := range value {
		switch {
		case r >= 'a' && r <= 'z':
		case r >= 'A' && r <= 'Z':
		case r >= '0' && r <= '9':
		case r == '-' || r == '.':
		default:
			return "", fmt.Errorf("hostname contains unsupported character %q", r)
		}
	}
	for _, label := range strings.Split(value, ".") {
		if label == "" {
			return "", fmt.Errorf("hostname has an empty label")
		}
		if len(label) > 63 {
			return "", fmt.Errorf("hostname label exceeds 63 bytes")
		}
		if label[0] == '-' || label[len(label)-1] == '-' {
			return "", fmt.Errorf("hostname label starts or ends with '-'")
		}
	}
	return value, nil
}

// HostnamesEqual compares hostnames case-insensitively with an optional
// trailing dot removed.
func HostnamesEqual(a, b string) bool {
	na, errA := NormalizeHostname(a)
	nb, errB := NormalizeHostname(b)
	if errA != nil || errB != nil {
		return strings.EqualFold(strings.TrimSuffix(a, "."), strings.TrimSuffix(b, "."))
	}
	return strings.EqualFold(na, nb)
}

// ValidateTimestamp checks a protocol timestamp expressed as RFC 3339. The
// protocol deliberately has no freshness window; this is a format check.
func ValidateTimestamp(value string) (time.Time, error) {
	if value == "" {
		return time.Time{}, fmt.Errorf("empty timestamp")
	}
	t, err := time.Parse(time.RFC3339Nano, value)
	if err != nil {
		return time.Time{}, fmt.Errorf("invalid RFC3339 timestamp %q: %w", value, err)
	}
	if t.Year() < 2000 || t.Year() > 2200 {
		return time.Time{}, fmt.Errorf("timestamp year %d out of supported range", t.Year())
	}
	return t.UTC(), nil
}

// ValidateConfig validates and normalizes a server-provided configuration.
func ValidateConfig(cfg *AgentConfig) error {
	if cfg == nil {
		return fmt.Errorf("nil configuration")
	}
	if cfg.Version < 1 || cfg.Version > 1<<30 {
		return fmt.Errorf("configuration version must be positive")
	}
	if cfg.ScanIntervalDays < 1 || cfg.ScanIntervalDays > 365 {
		return fmt.Errorf("scan_interval_days must be between 1 and 365")
	}
	if cfg.MaxFiles < 1 || cfg.MaxFiles > MaxFilesPerFolder {
		return fmt.Errorf("max_files must be between 1 and %d", MaxFilesPerFolder)
	}
	if cfg.MaxFileBytes < 1024 || cfg.MaxFileBytes > LogFileMaxBytes {
		return fmt.Errorf("max_file_bytes must be between 1024 and %d", LogFileMaxBytes)
	}
	if cfg.CertDirectories == nil {
		cfg.CertDirectories = []string{}
	}
	if len(cfg.CertDirectories) > 64 {
		return fmt.Errorf("too many certificate directories")
	}
	seen := make(map[string]struct{}, len(cfg.CertDirectories))
	normalized := make([]string, 0, len(cfg.CertDirectories))
	for _, dir := range cfg.CertDirectories {
		dir = strings.TrimSpace(dir)
		if dir == "" {
			return fmt.Errorf("empty certificate directory")
		}
		if len(dir) > MaxPathBytes {
			return fmt.Errorf("certificate directory path is too long")
		}
		if strings.ContainsRune(dir, 0) {
			return fmt.Errorf("certificate directory contains NUL")
		}
		key := strings.ToLower(strings.TrimRight(dir, `\/`))
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		normalized = append(normalized, dir)
	}
	if len(cfg.FolderPolicies) > 128 {
		return fmt.Errorf("too many folder policies")
	}
	policyIDs := map[string]bool{}
	for _, p := range cfg.FolderPolicies {
		if p.ID == "" || len(p.ID) > 128 || len([]rune(p.Name)) > 200 || (p.Level != "machine" && p.Level != "group") {
			return fmt.Errorf("invalid folder policy")
		}
		key := p.ID + ":" + p.Level
		if policyIDs[key] {
			return fmt.Errorf("duplicate folder policy")
		}
		policyIDs[key] = true
		if _, err := folderpolicy.Compile(p.Rules); err != nil {
			return err
		}
	}
	cfg.CertDirectories = normalized
	return nil
}
