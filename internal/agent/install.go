package agent

import (
	"fmt"
	"time"

	"telehack2026/internal/protocol"
)

// InstallSnapshot is the in-memory state read before/after a license write. The
// full current serial is used only for comparison and is never logged or sent.
type InstallSnapshot struct {
	Present           bool
	ProductMajor      int
	ProductVersion    string
	ProductGUID       string
	PackedProductGUID string
	CurrentSerial     string
	SerialMatch       bool
	OriginalType      uint32
	OriginalPresent   bool
	License           protocol.LicenseInfo
	Environment       string
	CollectedAt       time.Time
}

// InstallExecutor is the native no-window license adapter. Errors are
// classified by the caller; a write success code alone is never success.
type InstallExecutor interface {
	Inspect(expectedSerial string, spec protocol.LicensePoolSpec) (InstallSnapshot, error)
	Write(snapshot InstallSnapshot, serial string) error
	Verify(expectedSerial string, spec protocol.LicensePoolSpec) (InstallSnapshot, bool, error)
	Restore(snapshot InstallSnapshot) error
}

// ErrInstallUnsupported is returned on builds without a Windows CSP adapter.
var ErrInstallUnsupported = fmt.Errorf("%w: license installation is Windows-only", ErrUnsupportedPlatform)
