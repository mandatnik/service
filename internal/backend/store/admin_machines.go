package store

import "strings"

// Machine status values returned by the admin machine list. The UI maps them
// to labels and tones without duplicating the precedence rules below.
const (
	MachineStatusOffline         = "offline"
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

func licenseIsActiveNonTrial(state, trial string) bool {
	return strings.EqualFold(state, "active") && !strings.EqualFold(trial, "yes")
}

func licenseIsActiveTrial(state, trial string) bool {
	return strings.EqualFold(state, "active") && strings.EqualFold(trial, "yes")
}

// deriveMachineStatus applies the precedence documented for the machine list:
// connection first, then CSP presence, then certificate/license coverage.
func deriveMachineStatus(offline, cspPresent bool, licenseState, trial string, registryCerts, licensedCerts int) string {
	if offline {
		return MachineStatusOffline
	}
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
