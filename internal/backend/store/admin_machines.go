package store

import (
	"net"
	"strings"
	"time"

	"mandatnik/internal/protocol"
)

const dnsVerificationMaxAge = 15 * time.Minute

// Machine status values returned by the admin machine list. The UI maps them
// to labels and tones without duplicating the precedence rules below.
const (
	MachineStatusCSPMissing      = "csp_missing"
	MachineStatusTrial           = "trial"
	MachineStatusLicenseRequired = "license_required"
	MachineStatusOK              = "ok"
)

func machineDisplayName(displayName, uuid, machineID string) string {
	if name := strings.TrimSpace(displayName); name != "" {
		return name
	}
	if uuid != "" {
		return uuid
	}
	return machineID
}

func trialFlag(value string) bool {
	return strings.EqualFold(value, "true") || strings.EqualFold(value, "yes")
}

func licenseIsActiveNonTrial(state, trial string) bool {
	return strings.EqualFold(state, "active") && !trialFlag(trial)
}

func licenseIsActiveTrial(state, trial string) bool {
	return strings.EqualFold(state, "active") && trialFlag(trial)
}

// deriveMachineStatus applies the documented precedence for certificate and
// license coverage. Connection state is intentionally not part of it: the
// online/offline indicator lives in a separate column and must not hide the
// machine's licensing status.
func deriveMachineStatus(cspPresent bool, licenseState, trial string, registryCerts, licensedCerts int) string {
	if !cspPresent {
		return MachineStatusCSPMissing
	}
	activeNonTrial := licenseIsActiveNonTrial(licenseState, trial)
	if registryCerts > licensedCerts && registryCerts != 0 {
		if activeNonTrial {
			return MachineStatusOK
		}
		if licenseIsActiveTrial(licenseState, trial) {
			return MachineStatusTrial
		}
		return MachineStatusLicenseRequired
	}
	return MachineStatusOK
}

// dnsVerificationConfirmed is deliberately conservative: only a mutual DNS
// result recorded for the same hostname and source IP, and recent enough to
// describe the current connection, may turn into the green "Проверен DNS"
// badge. Legacy rows with a forward-only "verified" value have no reverse
// result and remain unconfirmed.
func dnsVerificationConfirmed(forward, reverse, verifiedHostname, hostname, verifiedIP, sourceIP string, checkedAt *time.Time, now time.Time) bool {
	if !strings.EqualFold(forward, "verified") || !strings.EqualFold(reverse, "verified") {
		return false
	}
	if checkedAt == nil || checkedAt.IsZero() {
		return false
	}
	if now.Sub(*checkedAt) > dnsVerificationMaxAge {
		return false
	}
	if checkedAt.After(now.Add(time.Minute)) {
		return false
	}
	if sourceIP == "" || verifiedIP == "" || !sameIPAddress(verifiedIP, sourceIP) {
		return false
	}
	return protocol.HostnamesEqual(verifiedHostname, hostname)
}

func sameIPAddress(a, b string) bool {
	parsedA, parsedB := net.ParseIP(a), net.ParseIP(b)
	if parsedA != nil && parsedB != nil {
		return parsedA.Equal(parsedB)
	}
	return strings.EqualFold(a, b)
}
