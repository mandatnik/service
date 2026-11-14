//go:build windows

package agent

import "telehack2026/internal/agent/winapi"

func protectIdentity(plain []byte) ([]byte, error) {
	return winapi.ProtectData(plain)
}

func unprotectIdentity(blob []byte) ([]byte, error) {
	return winapi.UnprotectData(blob)
}

func securePath(path string) error {
	return winapi.SecureFile(path)
}
