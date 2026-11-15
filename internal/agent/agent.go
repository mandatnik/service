package agent

import (
	"mandatnik/internal/platform"
)

// SystemIdentity is diagnostic context for service-only evidence.
type SystemIdentity struct {
	User      string `json:"user"`
	SID       string `json:"sid"`
	SessionID uint32 `json:"session_id"`
	OSVersion string `json:"os_version"`
	Hostname  string `json:"hostname"`
}

func mustSystemIdentity() SystemIdentity {
	identity, err := currentSystemIdentity()
	if err != nil {
		return SystemIdentity{OSVersion: err.Error()}
	}
	return identity
}

func secureAgentState(logger *Logger) {
	if err := secureState(platform.AgentDir()); err != nil && logger != nil {
		logger.Logf("state ACL: %v", err)
	}
}

// Run starts the agent. On Windows this is a real SCM service when launched by
// the service control manager, and a console loop for diagnostics otherwise.
func Run(configPath string) error {
	return runPlatform(configPath)
}
