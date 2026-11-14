package licensecrypto

import (
	"bytes"
	"path/filepath"
	"testing"
)

func TestKeyringRoundTripAndRotation(t *testing.T) {
	dir := t.TempDir()
	keyringPath := filepath.Join(dir, "keyring.json")
	fingerprintPath := filepath.Join(dir, "fingerprint.key")
	keyID, err := InitKeyring(keyringPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := InitFingerprintKey(fingerprintPath); err != nil {
		t.Fatal(err)
	}
	ring, err := LoadKeyring(keyringPath)
	if err != nil {
		t.Fatal(err)
	}
	fingerprint, err := LoadFingerprintKey(fingerprintPath)
	if err != nil {
		t.Fatal(err)
	}
	if ring.ActiveKeyID() != keyID {
		t.Fatalf("active key id mismatch")
	}
	binding := LicenseBinding{LicenseID: "11111111-1111-4111-8111-111111111111", PoolID: "22222222-2222-4222-8222-222222222222", CSPMajorVersion: 5, LicenseKind: "client", Term: "perpetual"}
	aad, err := LicenseAAD(binding)
	if err != nil {
		t.Fatal(err)
	}
	const serial = "1234567890123456789012345"
	sealed, err := ring.Encrypt(serial, aad)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(sealed, []byte(serial)) {
		t.Fatal("sealed blob contains plaintext serial")
	}
	opened, err := ring.Decrypt(sealed, aad)
	if err != nil || opened != serial {
		t.Fatalf("decrypt: %q %v", opened, err)
	}
	other := binding
	other.LicenseID = "33333333-3333-4333-8333-333333333333"
	otherAAD, _ := LicenseAAD(other)
	if _, err := ring.Decrypt(sealed, otherAAD); err == nil {
		t.Fatal("wrong AAD accepted")
	}
	firstFingerprint := fingerprint.Fingerprint(serial)
	rotatedID, err := ring.Rotate()
	if err != nil {
		t.Fatal(err)
	}
	if rotatedID == keyID {
		t.Fatal("rotation did not change the active key")
	}
	reloaded, err := LoadKeyring(keyringPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := reloaded.Decrypt(sealed, aad); err != nil {
		t.Fatalf("old key lost after rotation: %v", err)
	}
	if got, _ := reloaded.Decrypt(sealed, aad); got != serial {
		t.Fatal("old ciphertext changed")
	}
	if reloaded.ActiveKeyID() != rotatedID {
		t.Fatal("rotated key is not active")
	}
	rotatedSealed, err := reloaded.Encrypt(serial, aad)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(rotatedSealed, []byte(rotatedID)) {
		t.Fatal("new ciphertext does not reference the new key id")
	}
	if !bytes.Equal(firstFingerprint, fingerprint.Fingerprint(serial)) {
		t.Fatal("encryption rotation changed deduplication fingerprint")
	}
}
