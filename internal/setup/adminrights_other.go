//go:build !windows

package setup

// requireAdmin is a Windows-only precheck.
func requireAdmin() error { return ErrWindowsOnly }
