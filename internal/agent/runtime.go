package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"

	"telehack2026/internal/platform"
	"telehack2026/internal/protocol"
	"telehack2026/internal/version"
)

// diagnosticRuntime is the P02 service runtime: it proves the collector works
// as LocalSystem in session 0 and writes evidence files. P06 replaces the loop
// body with identity, registration, scheduling, queue and delivery while
// keeping the same service lifecycle.
type diagnosticRuntime struct {
	configPath string
	diagDirs   []string
	logger     *Logger
	collector  Collector
}

// runDiagnosticRuntime is the temporary service loop used until the P06 agent
// cycle is wired in. It is not a delivery path and makes no network calls.
func runDiagnosticRuntime(ctx context.Context, configPath string, diagDirs []string) error {
	runtime, err := newDiagnosticRuntime(configPath, diagDirs)
	if err != nil {
		return err
	}
	defer runtime.logger.Close()
	runtime.logger.Logf("agent service starting: %s", version.String())
	if identity, err := currentSystemIdentity(); err == nil {
		runtime.logger.Logf("service identity: user=%s sid=%s session=%d os=%q host=%s", identity.User, identity.SID, identity.SessionID, identity.OSVersion, identity.Hostname)
	} else {
		runtime.logger.Logf("service identity unavailable: %v", err)
	}
	if config, err := LoadFileConfig(configPath); err == nil {
		runtime.logger.Logf("server_url configured: %s", config.ServerURL)
	} else {
		runtime.logger.Logf("agent config not loaded: %v", err)
	}
	runtime.collectOnce(ctx)
	ticker := time.NewTicker(protocol.AgentPollInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			runtime.logger.Logf("agent service stopping")
			return nil
		case <-ticker.C:
			runtime.collectOnce(ctx)
		}
	}
}

func newDiagnosticRuntime(configPath string, diagDirs []string) (*diagnosticRuntime, error) {
	dir := platform.AgentDir()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("create agent state directory: %w", err)
	}
	logger, err := OpenLogger(platform.AgentLogDir())
	if err != nil {
		return nil, err
	}
	secureAgentState(logger)
	return &diagnosticRuntime{
		configPath: configPath,
		diagDirs:   diagDirs,
		logger:     logger,
		collector:  NewCollector(logger),
	}, nil
}

func (r *diagnosticRuntime) collectOnce(ctx context.Context) {
	started := time.Now()
	defer func() {
		if recovered := recover(); recovered != nil {
			r.logger.Logf("panic during collection: %v", recovered)
		}
	}()
	cfg := protocol.DefaultAgentConfig()
	cfg.CertDirectories = append([]string(nil), r.diagDirs...)
	if err := protocol.ValidateConfig(&cfg); err != nil {
		r.logger.Logf("diagnostic configuration invalid: %v", err)
		cfg = protocol.DefaultAgentConfig()
	}
	collection, err := r.collector.Collect(ctx, cfg)
	if err != nil {
		r.logger.Logf("collection failed: %v", err)
		return
	}
	payload := diagnosticFile{
		CapturedAt: time.Now().UTC(),
		Version:    version.String(),
		Identity:   mustSystemIdentity(),
		Collection: collection,
	}
	directory := filepath.Join(platform.AgentDir(), "diagnostics")
	if err := os.MkdirAll(directory, 0o755); err != nil {
		r.logger.Logf("diagnostics directory: %v", err)
		return
	}
	name := filepath.Join(directory, "collect-"+time.Now().UTC().Format("20060102T150405.000Z")+".json")
	raw, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		r.logger.Logf("encode diagnostics: %v", err)
		return
	}
	if err := os.WriteFile(name, raw, 0o600); err != nil {
		r.logger.Logf("write diagnostics: %v", err)
		return
	}
	secureAgentState(r.logger)
	pruneDiagnostics(directory, 20, r.logger)
	profileCount := len(collection.Profiles)
	certCount := 0
	for _, source := range collection.Sources {
		certCount += len(source.Certificates)
	}
	r.logger.Logf("collection finished in %s: profiles=%d sources=%d certificates=%d csp_present=%t csp_complete=%t errors=%d",
		time.Since(started).Round(time.Millisecond), profileCount, len(collection.Sources), certCount, collection.CSP.Present, collection.CSP.Complete, len(collection.Errors))
	for _, message := range collection.Errors {
		r.logger.Logf("collection error: %s", message)
	}
}

type diagnosticFile struct {
	CapturedAt time.Time      `json:"captured_at"`
	Version    string         `json:"version"`
	Identity   SystemIdentity `json:"identity"`
	Collection Collection     `json:"collection"`
}

func pruneDiagnostics(directory string, keep int, logger *Logger) {
	entries, err := os.ReadDir(directory)
	if err != nil {
		return
	}
	var names []string
	for _, entry := range entries {
		if !entry.IsDir() && len(entry.Name()) > 8 && entry.Name()[:8] == "collect-" {
			names = append(names, entry.Name())
		}
	}
	sort.Strings(names)
	for len(names) > keep {
		_ = os.Remove(filepath.Join(directory, names[0]))
		names = names[1:]
	}
}
