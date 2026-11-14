//go:build windows

package agent

import "telehack2026/internal/agent/winapi"

func currentSystemIdentity() (SystemIdentity, error) {
	identity := winapi.CurrentSystemIdentity()
	return SystemIdentity{
		User:      identity.User,
		SID:       identity.SID,
		SessionID: identity.SessionID,
		OSVersion: identity.OSVersion,
		Hostname:  identity.Hostname,
	}, nil
}

func secureState(path string) error {
	return winapi.SecureTree(path)
}
