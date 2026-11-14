//go:build !windows

package agent

import "fmt"

func InstallService(string) error {
	return fmt.Errorf("%w: Windows service", ErrUnsupportedPlatform)
}
func UninstallService(bool) error { return fmt.Errorf("%w: Windows service", ErrUnsupportedPlatform) }
func StartService() error         { return fmt.Errorf("%w: Windows service", ErrUnsupportedPlatform) }
func StopService() error          { return fmt.Errorf("%w: Windows service", ErrUnsupportedPlatform) }
func QueryService() (ServiceInfo, error) {
	return ServiceInfo{}, fmt.Errorf("%w: Windows service", ErrUnsupportedPlatform)
}
func ResetIdentity() (string, error) {
	return "", fmt.Errorf("%w: Windows service", ErrUnsupportedPlatform)
}
func Diagnostics() (string, error) {
	return "", fmt.Errorf("%w: Windows service", ErrUnsupportedPlatform)
}

// UninstallProduct falls back to the local service removal off Windows.
func UninstallProduct(purge bool) (string, error) {
	if err := UninstallService(purge); err != nil {
		return "", err
	}
	return "local service removed", nil
}

// ConfigureServiceRecovery is only meaningful for the Windows SCM service.
func ConfigureServiceRecovery() error {
	return fmt.Errorf("service configuration is supported on Windows only")
}
