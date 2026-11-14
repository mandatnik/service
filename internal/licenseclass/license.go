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

// IsOLEZeroDate reports the OLE Automation zero value used by CryptoPro CSP 5
// for a perpetual license. It must not be classified as an expired 1899 date.
func IsOLEZeroDate(value time.Time) bool {
	return value.IsZero() || (value.Year() == 1899 && value.Month() == time.December && value.Day() == 30)
}

// TermKind derives only the directly observable term class: a readable
// non-zero expiry date means time-limited, the OLE zero date means perpetual,
// and a missing/unreadable date is unknown.
func TermKind(hasExpiry bool) string {
	if hasExpiry {
		return "time_limited"
	}
	return "unknown"
}
