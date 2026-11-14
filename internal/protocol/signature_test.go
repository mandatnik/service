package protocol

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

type signatureVector struct {
	Description     string `json:"description"`
	CanonicalUTF8   string `json:"canonical_utf8"`
	PublicKeyPEM    string `json:"public_key_pem"`
	SignatureBase64 string `json:"signature_base64"`
}

func TestFixedSignatureVector(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("testdata", "signature_vector.json"))
	if err != nil {
		t.Fatal(err)
	}
	var vector signatureVector
	if err := json.Unmarshal(raw, &vector); err != nil {
		t.Fatal(err)
	}
	pub, err := ParsePublicKeyPEM(vector.PublicKeyPEM)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := DecodeSignatureBase64(vector.SignatureBase64)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyCanonical(pub, []byte(vector.CanonicalUTF8), sig); err != nil {
		t.Fatalf("fixed signature vector did not verify: %v", err)
	}
	if err := VerifyCanonical(pub, []byte(vector.CanonicalUTF8+" "), sig); err == nil {
		t.Fatal("fixed signature verified after a one-byte change")
	}
}
