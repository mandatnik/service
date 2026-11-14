package licenseclass

import "time"

// KindFromRaw maps the documented CPCSPLicense.GetType codes for the
// researched CSP 4/5 builds. Any other value is explicitly unknown; the raw
// code is always stored by the caller.
func KindFromRaw(raw int32) string {
	switch raw {
	case 0:
		return "client"
	case 1:
		return "server"
	default:
		return "unknown"
	}
}

// StateFromWallClock classifies a COM date whose time basis is not
// documented. The caller passes the wall-clock value interpreted in the local
// zone and marks time_basis accordingly; no UTC value is invented here.
func StateFromWallClock(expiresLocal time.Time, now time.Time) string {
	if expiresLocal.IsZero() {
		return "unknown"
	}
	if expiresLocal.Before(now) {
		return "expired"
	}
	return "active"
}

// TermKind derives only the directly observable term class: a readable
// expiry date means time-limited. Trial status is intentionally not inferred.
func TermKind(hasExpiry bool) string {
	if hasExpiry {
		return "time_limited"
	}
	return "unknown"
}
