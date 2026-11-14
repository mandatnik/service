package licenseclass

import "time"

// TrialFromInstallExpiry derives the trial flag from the install and expiry
// dates exposed by CPCSPLicense. CryptoPro CSP ships with a three-month demo
// period (roughly 90 days); commercial time-limited licenses are one or two
// years. A clear three-month span is reported as trial, a span of 300+ days as
// non-trial, and anything else stays unknown instead of guessing.
func TrialFromInstallExpiry(install, expiry time.Time) string {
	if install.IsZero() || expiry.IsZero() || !expiry.After(install) {
		return "unknown"
	}
	days := expiry.Sub(install).Hours() / 24
	switch {
	case days >= 80 && days <= 100:
		return "true"
	case days >= 300:
		return "false"
	default:
		return "unknown"
	}
}
