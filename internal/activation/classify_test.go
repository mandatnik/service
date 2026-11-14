package activation

import (
	"testing"

	"telehack2026/internal/protocol"
)

func base(environment string) MachineFacts {
	return MachineFacts{
		MachineID: "11111111-1111-4111-8111-111111111111", DisplayName: "WS", Hostname: "WS",
		RegistrationID: 1, AgentCapable: true, CSPFresh: true, CSPComplete: true, CSPPresent: true,
		CSPMajor: 5, CSPEnvironment: environment, LicenseState: "not_installed",
		PersonalFresh: true, PersonalComplete: true, ProfilesComplete: true,
	}
}

func pool(kind string) PoolSpec {
	return PoolSpec{ID: "pool", Name: "p", CSPMajorVersion: 5, LicenseKind: kind, Term: protocol.PoolTermPerpetual}
}

func TestFourLists(t *testing.T) {
	noLicense := base("workstation")
	noLicense.SuitableCertificate = true
	got := Classify(noLicense, pool(protocol.PoolKindClient))
	if got.Category != protocol.TaskCategoryActivation || got.Subtype != protocol.TaskCategoryActivationNoLicense || !got.Selectable || !got.DefaultSelected {
		t.Fatalf("no-license: %+v", got)
	}

	trial := base("workstation")
	trial.LicenseState, trial.IsTrial, trial.LicenseKind, trial.SuitableCertificate = "active", "true", "client", true
	got = Classify(trial, pool(protocol.PoolKindClient))
	if got.Category != protocol.TaskCategoryActivation || got.Subtype != protocol.TaskCategoryActivationTrial || !got.Selectable || got.DefaultSelected {
		t.Fatalf("trial: %+v", got)
	}
	if !AllowTrialReplacement(got) {
		t.Fatal("explicit trial selection should allow replacement")
	}

	purchased := base("workstation")
	purchased.LicenseState, purchased.IsTrial, purchased.LicenseKind = "active", "false", "client"
	got = Classify(purchased, pool(protocol.PoolKindClient))
	if got.Category != protocol.TaskCategoryActivated || got.Selectable || got.DefaultSelected {
		t.Fatalf("purchased: %+v", got)
	}
	if SelectionAllowed(got) || AllowTrialReplacement(got) {
		t.Fatal("purchased list must never be selectable")
	}

	unknownTrial := base("workstation")
	unknownTrial.LicenseState, unknownTrial.IsTrial, unknownTrial.LicenseKind = "active", "unknown", "client"
	got = Classify(unknownTrial, pool(protocol.PoolKindClient))
	if got.Category != protocol.TaskCategoryNeedsCheck || got.ReasonCode != "license_mode_unknown" || got.Selectable {
		t.Fatalf("unknown trial: %+v", got)
	}

	optional := base("workstation")
	got = Classify(optional, pool(protocol.PoolKindClient))
	if got.Category != protocol.TaskCategoryOptional || !got.Selectable || got.DefaultSelected {
		t.Fatalf("optional: %+v", got)
	}

	uncertain := base("workstation")
	uncertain.UnknownCertificate = true
	got = Classify(uncertain, pool(protocol.PoolKindClient))
	if got.Category != protocol.TaskCategoryNeedsCheck || got.ReasonCode != "certificate_provider_unknown" {
		t.Fatalf("uncertain: %+v", got)
	}

	stale := base("workstation")
	stale.CSPFresh = false
	got = Classify(stale, pool(protocol.PoolKindClient))
	if got.Category != protocol.TaskCategoryNeedsCheck || got.ReasonCode != "inventory_stale" {
		t.Fatalf("stale: %+v", got)
	}
}

func TestCompatibilityAndEnvironment(t *testing.T) {
	serverOnWorkstation := base("workstation")
	serverOnWorkstation.SuitableCertificate = true
	got := Classify(serverOnWorkstation, pool(protocol.PoolKindServer))
	if !got.Incompatible || got.ReasonCode != "server_pool_requires_server" {
		t.Fatalf("server pool on workstation: %+v", got)
	}
	major := base("workstation")
	major.SuitableCertificate = true
	other := pool(protocol.PoolKindClient)
	other.CSPMajorVersion = 4
	got = Classify(major, other)
	if !got.Incompatible || got.ReasonCode != "csp_major_mismatch" {
		t.Fatalf("major: %+v", got)
	}
	noCSP := base("workstation")
	noCSP.CSPPresent = false
	got = Classify(noCSP, pool(protocol.PoolKindClient))
	if !got.Incompatible || got.ReasonCode != "csp_not_installed" {
		t.Fatalf("no CSP: %+v", got)
	}
	oldAgent := base("workstation")
	oldAgent.AgentCapable = false
	got = Classify(oldAgent, pool(protocol.PoolKindClient))
	if !got.Incompatible || got.ReasonCode != "agent_update_required" {
		t.Fatalf("old agent: %+v", got)
	}
}

func TestBuildPreviewDeduplicatesDefaults(t *testing.T) {
	a := base("workstation")
	a.MachineID = "11111111-1111-4111-8111-111111111111"
	a.SuitableCertificate = true
	b := base("workstation")
	b.MachineID = "22222222-2222-4222-8222-222222222222"
	b.SuitableCertificate = true
	preview := BuildPreview([]MachineFacts{a, b}, pool(protocol.PoolKindClient))
	if preview.RequiredKeys != 2 || len(preview.DefaultSelected) != 2 || preview.Compatible != 2 {
		t.Fatalf("preview: %+v", preview)
	}
}
