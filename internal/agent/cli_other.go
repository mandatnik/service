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
