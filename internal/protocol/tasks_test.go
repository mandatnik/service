package protocol

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

func testBinding(t *testing.T, keyID, expires string) TaskBinding {
	t.Helper()
	return TaskBinding{
		Protocol: TaskBindingProtocol, Purpose: "task_item_parameters",
		TaskID: NewUUID(), ItemID: NewUUID(), MachineID: NewUUID(), RegistrationID: 7,
		Kind: TaskKindInstallLicense, ParametersVersion: ParametersVersionV1,
		RecipientKeyID: keyID, ExpiresAt: expires,
	}
}

func TestTaskEnvelopeBindingAndTamper(t *testing.T) {
	key, err := GenerateTaskEncryptionKey()
	if err != nil {
		t.Fatal(err)
	}
	publicPEM, err := MarshalTaskPublicKeyPEM(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseTaskPublicKeyPEM(publicPEM)
	if err != nil {
		t.Fatal(err)
	}
	keyID, err := TaskPublicKeyID(parsed)
	if err != nil {
		t.Fatal(err)
	}
	binding := testBinding(t, keyID, "2030-01-01T00:00:00Z")
	plaintext := []byte(`{"kind":"install_license","serial":"00000-00000-00000-00000-00001"}`)
	envelope, err := SealTaskParameters(parsed, binding, plaintext)
	if err != nil {
		t.Fatal(err)
	}
	opened, err := OpenTaskParameters(key, binding, envelope)
	if err != nil {
		t.Fatal(err)
	}
	if string(opened) != string(plaintext) {
		t.Fatalf("plaintext mismatch: %s", opened)
	}
	otherKey, err := GenerateTaskEncryptionKey()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := OpenTaskParameters(otherKey, binding, envelope); err == nil {
		t.Fatal("another RSA key opened the envelope")
	}

	mutations := []struct {
		name   string
		change func(*TaskBinding)
	}{
		{"task", func(b *TaskBinding) { b.TaskID = NewUUID() }},
		{"item", func(b *TaskBinding) { b.ItemID = NewUUID() }},
		{"machine", func(b *TaskBinding) { b.MachineID = NewUUID() }},
		{"registration", func(b *TaskBinding) { b.RegistrationID++ }},
		{"kind", func(b *TaskBinding) { b.Kind = TaskKindScan }},
		{"version", func(b *TaskBinding) { b.ParametersVersion = 2 }},
		{"expiry", func(b *TaskBinding) { b.ExpiresAt = "2031-01-01T00:00:00Z" }},
		{"key", func(b *TaskBinding) { b.RecipientKeyID = strings.Repeat("0", 64) }},
	}
	for _, mutation := range mutations {
		changed := binding
		mutation.change(&changed)
		if _, err := OpenTaskParameters(key, changed, envelope); err == nil {
			t.Fatalf("binding mutation %s was accepted", mutation.name)
		}
	}
	rawCipher, _ := base64.StdEncoding.DecodeString(envelope.Ciphertext)
	rawCipher[0] ^= 0x01
	changed := envelope
	changed.Ciphertext = base64.StdEncoding.EncodeToString(rawCipher)
	if _, err := OpenTaskParameters(key, binding, changed); err == nil {
		t.Fatal("modified ciphertext was accepted")
	}
	changed = envelope
	changed.Nonce = base64.StdEncoding.EncodeToString(make([]byte, 12))
	if _, err := OpenTaskParameters(key, binding, changed); err == nil {
		t.Fatal("modified nonce was accepted")
	}
}

func TestSerialMaskNeverContainsFullSerial(t *testing.T) {
	const serial = "12345-67890-12345-67890-12345"
	normalized := NormalizeSerial(serial)
	if normalized != "1234567890123456789012345" {
		t.Fatalf("normalized=%s", normalized)
	}
	if err := ValidateSerialFormat(normalized); err != nil {
		t.Fatal(err)
	}
	mask := MaskSerial(serial)
	if strings.Contains(mask, normalized) {
		t.Fatalf("mask exposes full serial: %s", mask)
	}
	if !strings.HasSuffix(mask, "2345") {
		t.Fatalf("mask lost last four: %s", mask)
	}
	if NormalizeSerial("1234") != "1234" || ValidateSerialFormat("1234") == nil {
		t.Fatal("short serial accepted")
	}
	if ValidateSerialFormat(strings.Repeat("0", 25)) == nil {
		t.Fatal("placeholder serial accepted")
	}
}

func TestTaskResultScanSuccessNeedsReportOnlyAtStore(t *testing.T) {
	raw, _ := json.Marshal(TaskResult{
		ItemID: NewUUID(), DeliveryVersion: 1, State: TaskStateSucceeded, Modified: "no",
		AttemptNo: 0, ResultVersion: 1, ReportID: NewUUID(),
	})
	result, err := DecodeTaskResult(raw)
	if err != nil {
		t.Fatal(err)
	}
	if result.State != TaskStateSucceeded {
		t.Fatalf("state=%s", result.State)
	}
}

func TestLegacyConfigProjectionKeepsHash(t *testing.T) {
	legacy := DefaultAgentConfig()
	legacy.CertDirectories = []string{`C:\certs`}
	legacyHash, err := ConfigHash(legacy)
	if err != nil {
		t.Fatal(err)
	}
	full := legacy.WithScheduleDefaults()
	fullHash, err := ConfigHash(full)
	if err != nil {
		t.Fatal(err)
	}
	if legacyHash == fullHash {
		t.Fatal("schedule settings must participate in the capable config hash")
	}
	projectedHash, err := LegacyConfigHash(full)
	if err != nil {
		t.Fatal(err)
	}
	if projectedHash != legacyHash {
		t.Fatalf("legacy projection changed hash: %s != %s", projectedHash, legacyHash)
	}
}
