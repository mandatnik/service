// Package platform contains paths and platform capability declarations shared
// by the agent and backend.
package platform

import (
	"os"
	"path/filepath"
	"runtime"
)

// ProgramDataDir returns the root directory for product state. The GPO-managed
// agent configuration and the backend configuration live here on Windows.
func ProgramDataDir() string {
	if runtime.GOOS == "windows" {
		if value := os.Getenv("ProgramData"); value != "" {
			return filepath.Join(value, "Telehack2026")
		}
		return `C:\ProgramData\Telehack2026`
	}
	base, err := os.UserConfigDir()
	if err != nil || base == "" {
		base = os.TempDir()
	}
	return filepath.Join(base, "telehack2026")
}

func AgentDir() string          { return filepath.Join(ProgramDataDir(), "Agent") }
func AgentConfigPath() string   { return filepath.Join(ProgramDataDir(), "agent-config.json") }
func AgentLogDir() string       { return filepath.Join(AgentDir(), "logs") }
func AgentQueueDir() string     { return filepath.Join(AgentDir(), "queue") }
func AgentIdentityPath() string { return filepath.Join(AgentDir(), "identity.dpapi") }
func AgentPublicIdentityPath() string {
	return filepath.Join(AgentDir(), "identity-public.json")
}
func AgentStatePath() string { return filepath.Join(AgentDir(), "state.json") }
func AgentJobsPath() string  { return filepath.Join(AgentDir(), "jobs.json") }
func AgentPendingRenamePath() string {
	return filepath.Join(AgentDir(), "pending_rename.dpapi")
}
func AgentPendingRenameAcceptedPath() string {
	return filepath.Join(AgentDir(), "pending_rename.accepted")
}
func BackendDir() string        { return filepath.Join(ProgramDataDir(), "Backend") }
func BackendConfigPath() string { return filepath.Join(BackendDir(), "backend.json") }
func BackendLogDir() string     { return filepath.Join(BackendDir(), "logs") }

// Supported reports whether this build has a real collector for the current
// platform. The unsupported-platform response is explicit, not a mock.
func Supported() bool {
	return runtime.GOOS == "windows"
}
