package store

import "testing"

func TestValidateAdminMachineFilter(t *testing.T) {
	for _, filter := range []AdminMachineFilter{
		{Monitor: "all; DROP TABLE machines"}, {SourceIP: "192.0.2.999"}, {GroupID: "not-a-uuid"}, {License: "invalid"}, {MachineStatus: "offline"},
	} {
		if ValidateAdminMachineFilter(filter) == nil {
			t.Fatalf("accepted invalid filter: %+v", filter)
		}
	}
	if err := ValidateAdminMachineFilter(AdminMachineFilter{Monitor: "needs_license", Connection: "online", CSP: "present", License: "trial", Certificate: "expired_recent", MachineStatus: "trial", GroupID: "11111111-1111-4111-8111-111111111111", SourceIP: "2001:db8::1"}); err != nil {
		t.Fatal(err)
	}
}
