// Package version exposes the product version and build metadata.
package version

import "fmt"

// Version is the product version. It is independent of any installed
// CryptoPro CSP version and of the protocol version.
const Version = "0.1.0"

// Commit and BuildDate are injected at build time:
//
//	go build -ldflags "-X telehack2026/internal/version.Commit=<sha>"
var (
	Commit    = "dev"
	BuildDate = "unknown"
)

// String returns a human-readable build identification.
func String() string {
	return fmt.Sprintf("%s (commit %s, built %s)", Version, Commit, BuildDate)
}
