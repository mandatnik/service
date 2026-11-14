//go:build !windows

package agent

import (
	"telehack2026/internal/protocol"
)

func newInstallExecutor() InstallExecutor { return unsupportedInstallExecutor{} }

type unsupportedInstallExecutor struct{}

func (unsupportedInstallExecutor) Inspect(string, protocol.LicensePoolSpec) (InstallSnapshot, error) {
	return InstallSnapshot{}, ErrInstallUnsupported
}
func (unsupportedInstallExecutor) Write(InstallSnapshot, string) error { return ErrInstallUnsupported }
func (unsupportedInstallExecutor) Verify(string, protocol.LicensePoolSpec) (InstallSnapshot, bool, error) {
	return InstallSnapshot{}, false, ErrInstallUnsupported
}
func (unsupportedInstallExecutor) Restore(InstallSnapshot) error { return ErrInstallUnsupported }
