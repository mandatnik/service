//go:build windows

package agent

import "mandatnik/internal/agent/winapi"

func agentOSVersion() string { return winapi.InstalledOSVersion() }
