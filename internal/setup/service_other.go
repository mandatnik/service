//go:build !windows

package setup

import (
	"time"
)

// ServiceStatus placeholder for non-Windows builds (tests).
type ServiceStatus struct {
	Installed bool
	Running   bool
	State     string
}

// Windows-only service operations are unavailable off Windows.
func InstallService(string, []string) error        { return ErrWindowsOnly }
func ConfigureServiceAccount(string, string) error { return ErrWindowsOnly }
func StartService(time.Duration) error             { return ErrWindowsOnly }
func StopService(time.Duration) error              { return ErrWindowsOnly }
func UninstallService() error                      { return ErrWindowsOnly }
func QueryService() (*ServiceStatus, error)        { return &ServiceStatus{}, nil }
func CreateLocalAccount(string, string) error      { return ErrWindowsOnly }
func IsServiceContext() (bool, error)              { return false, nil }
