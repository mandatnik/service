package store

import (
	"testing"
	"time"
)

func TestMachineOffline(t *testing.T) {
	now := time.Date(2026, 11, 15, 12, 0, 0, 0, time.UTC)
	recent := now.Add(-2*time.Minute - 59*time.Second)
	threshold := now.Add(-3 * time.Minute)
	stale := now.Add(-30 * time.Minute)
	future := now.Add(time.Minute)
	cases := []struct {
		name     string
		lastSeen *time.Time
		want     bool
	}{
		{"never seen", nil, true},
		{"recent contact", &recent, false},
		{"contact exactly three minutes ago", &threshold, true},
		{"contact thirty minutes ago", &stale, true},
		{"future contact", &future, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := machineOffline(tc.lastSeen, now); got != tc.want {
				t.Fatalf("machineOffline() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestMachineDisplayName(t *testing.T) {
	const uuid = "528ad917-d441-4c84-8490-380c30e0986f"
	const machineID = "53f71d1d-ea32-49ef-a849-c0b91ecb371a"
	cases := []struct {
		name        string
		displayName string
		uuid        string
		machineID   string
		want        string
	}{
		{"explicit name wins", "WORKSTATION-1", uuid, machineID, "WORKSTATION-1"},
		{"trimmed name wins", "  WORKSTATION-1  ", uuid, machineID, "WORKSTATION-1"},
		{"empty name falls back to registration UUID", "", uuid, machineID, uuid},
		{"whitespace name falls back to registration UUID", "   ", uuid, machineID, uuid},
		{"no registration falls back to machine UUID", "", "", machineID, machineID},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := machineDisplayName(tc.displayName, tc.uuid, tc.machineID); got != tc.want {
				t.Fatalf("machineDisplayName() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestDNSVerificationConfirmed(t *testing.T) {
	now := time.Date(2026, 11, 15, 12, 0, 0, 0, time.UTC)
	fresh := now.Add(-2 * time.Minute)
	stale := now.Add(-dnsVerificationMaxAge - time.Second)
	future := now.Add(2 * time.Minute)
	cases := []struct {
		name       string
		forward    string
		reverse    string
		verifiedHN string
		hostname   string
		verifiedIP string
		sourceIP   string
		checkedAt  *time.Time
		want       bool
	}{
		{"mutual fresh binding", "verified", "verified", "ws-1", "WS-1", "192.0.2.10", "192.0.2.10", &fresh, true},
		{"forward only is not confirmation", "verified", "", "ws-1", "ws-1", "192.0.2.10", "192.0.2.10", &fresh, false},
		{"unknown reverse is not confirmation", "verified", "unknown", "ws-1", "ws-1", "192.0.2.10", "192.0.2.10", &fresh, false},
		{"mismatch is not confirmation", "mismatch", "verified", "ws-1", "ws-1", "192.0.2.10", "192.0.2.10", &fresh, false},
		{"stale result is not confirmation", "verified", "verified", "ws-1", "ws-1", "192.0.2.10", "192.0.2.10", &stale, false},
		{"future timestamp is rejected", "verified", "verified", "ws-1", "ws-1", "192.0.2.10", "192.0.2.10", &future, false},
		{"changed IP invalidates result", "verified", "verified", "ws-1", "ws-1", "192.0.2.10", "192.0.2.11", &fresh, false},
		{"changed hostname invalidates result", "verified", "verified", "ws-1", "ws-2", "192.0.2.10", "192.0.2.10", &fresh, false},
		{"missing check timestamp", "verified", "verified", "ws-1", "ws-1", "192.0.2.10", "192.0.2.10", nil, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := dnsVerificationConfirmed(tc.forward, tc.reverse, tc.verifiedHN, tc.hostname, tc.verifiedIP, tc.sourceIP, tc.checkedAt, now)
			if got != tc.want {
				t.Fatalf("dnsVerificationConfirmed() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestDeriveMachineStatus(t *testing.T) {
	cases := []struct {
		name          string
		cspPresent    bool
		licenseState  string
		trial         string
		registryCerts int
		licensedCerts int
		want          string
	}{
		{
			name:       "7.1 missing CSP is reported regardless of certificate coverage",
			cspPresent: false, licenseState: "active", trial: "false", registryCerts: 5,
			want: MachineStatusCSPMissing,
		},
		{
			name:       "7.2 active trial and uncovered certificates",
			cspPresent: true, licenseState: "active", trial: "true",
			registryCerts: 3, licensedCerts: 1,
			want: MachineStatusTrial,
		},
		{
			name:       "7.2 legacy yes trial flag is accepted",
			cspPresent: true, licenseState: "active", trial: "yes",
			registryCerts: 1, licensedCerts: 0,
			want: MachineStatusTrial,
		},
		{
			name:       "7.3 expired license and uncovered certificates",
			cspPresent: true, licenseState: "expired", trial: "false",
			registryCerts: 3, licensedCerts: 1,
			want: MachineStatusLicenseRequired,
		},
		{
			name:       "7.3 no license and uncovered certificates",
			cspPresent: true, licenseState: "not_installed", trial: "unknown",
			registryCerts: 1, licensedCerts: 0,
			want: MachineStatusLicenseRequired,
		},
		{
			name:       "7.4 all certificates have embedded licenses",
			cspPresent: true, licenseState: "expired", trial: "false",
			registryCerts: 2, licensedCerts: 2,
			want: MachineStatusOK,
		},
		{
			name:       "7.4 zero certificates need no license",
			cspPresent: true, licenseState: "expired", trial: "false",
			registryCerts: 0, licensedCerts: 0,
			want: MachineStatusOK,
		},
		{
			name:       "7.4 active non-trial license covers uncovered certificates",
			cspPresent: true, licenseState: "active", trial: "false",
			registryCerts: 4, licensedCerts: 1,
			want: MachineStatusOK,
		},
		{
			name:       "unknown trial flag on an active license is treated as non-trial",
			cspPresent: true, licenseState: "active", trial: "unknown",
			registryCerts: 4, licensedCerts: 1,
			want: MachineStatusOK,
		},
		{
			name:       "trial flag on an expired license is not a trial version",
			cspPresent: true, licenseState: "expired", trial: "true",
			registryCerts: 2, licensedCerts: 0,
			want: MachineStatusLicenseRequired,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := deriveMachineStatus(tc.cspPresent, tc.licenseState, tc.trial, tc.registryCerts, tc.licensedCerts)
			if got != tc.want {
				t.Fatalf("deriveMachineStatus() = %q, want %q", got, tc.want)
			}
		})
	}
}
