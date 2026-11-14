package store

import "testing"

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
