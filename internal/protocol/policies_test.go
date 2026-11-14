package protocol

import "testing"

func TestPolicyConfigurationHashAndValidation(t *testing.T) {
	cfg := DefaultAgentConfig()
	initial, err := ConfigHash(cfg)
	if err != nil {
		t.Fatal(err)
	}
	cfg.FolderPolicies = []FolderPolicy{{ID: NewUUID(), Name: "Сертификаты", Rules: "C:/Users/*/certs/\n!C:/Users/*/certs/trash", Level: "group"}}
	group, err := ConfigHash(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if initial == group {
		t.Fatal("policy not in hash")
	}
	raw, err := CanonicalConfig(cfg)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeConfig(raw)
	if err != nil {
		t.Fatal(err)
	}
	roundtrip, _ := ConfigHash(decoded)
	if group != roundtrip {
		t.Fatal("config roundtrip changed hash")
	}
	cfg.FolderPolicies[0].Level = "machine"
	direct, err := ConfigHash(cfg)
	if err != nil || direct == group {
		t.Fatal("assignment level not in hash", err)
	}
	cfg.FolderPolicies[0].Rules = "relative/path"
	if ValidateConfig(&cfg) == nil {
		t.Fatal("invalid rule accepted")
	}
}
