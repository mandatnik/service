//go:build windows

package agent

import "telehack2026/internal/agent/winapi"

func agentOSVersion() string { return winapi.InstalledOSVersion() }
