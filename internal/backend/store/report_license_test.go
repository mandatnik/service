package store

import (
	"testing"

	"mandatnik/internal/protocol"
)

func TestLicensesCollectionApplicable(t *testing.T) {
	cases := []struct {
		name string
		csp  protocol.CSPResult
		want bool
	}{
		{"old agent omits field", protocol.CSPResult{}, false},
		{"complete empty list clears rows", protocol.CSPResult{Licenses: []protocol.LicenseInfo{}}, true},
		{"COM error keeps rows", protocol.CSPResult{
			Licenses: []protocol.LicenseInfo{},
			License:  protocol.LicenseInfo{State: "error"},
		}, false},
		{"GetType error keeps rows", protocol.CSPResult{
			Licenses: []protocol.LicenseInfo{},
			License:  protocol.LicenseInfo{Error: "GetType({GUID}): access denied"},
		}, false},
		{"missing serial clears stale row", protocol.CSPResult{
			Licenses: []protocol.LicenseInfo{},
			License:  protocol.LicenseInfo{State: "active", Error: "serial: ProductID not found"},
		}, true},
		{"valid record applies", protocol.CSPResult{
			Licenses: []protocol.LicenseInfo{{LicenseID: "a5dc754d2ff42421ccbfaa9b91f1cb0bbb980b7534a8ec42b32e6fce31ae3fc6"}},
		}, true},
	}
	for _, testCase := range cases {
		if got := licensesCollectionApplicable(&testCase.csp); got != testCase.want {
			t.Errorf("%s: got %v, want %v", testCase.name, got, testCase.want)
		}
	}
}
