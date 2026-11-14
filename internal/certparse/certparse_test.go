package certparse

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

type manifestCertificate struct {
	File          string `json:"file"`
	PEM           string `json:"pem"`
	Subject       string `json:"subject"`
	SerialHex     string `json:"serial_hex"`
	SHA256        string `json:"sha256_der"`
	PublicKeyBits int    `json:"public_key_bits"`
	NotBefore     string `json:"not_before"`
	NotAfter      string `json:"not_after"`
}

type manifest struct {
	Certificates []manifestCertificate `json:"certificates"`
	RootSHA256   string                `json:"root_sha256_der"`
	RootBefore   string                `json:"root_not_before"`
	RootAfter    string                `json:"root_not_after"`
}

func loadManifest(t *testing.T) manifest {
	t.Helper()
	path := filepath.Join("..", "..", "test-data", "certificates-2026-11-14", "manifest.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read manifest: %v", err)
	}
	var m manifest
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("decode manifest: %v", err)
	}
	return m
}

func TestFixturesMatchManifest(t *testing.T) {
	m := loadManifest(t)
	base := filepath.Join("..", "..", "test-data", "certificates-2026-11-14")
	for _, expected := range m.Certificates {
		expected := expected
		t.Run(filepath.Base(expected.File), func(t *testing.T) {
			der, err := os.ReadFile(filepath.Join(base, expected.File))
			if err != nil {
				t.Fatalf("read DER: %v", err)
			}
			cert, err := Parse(der)
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			if cert.SHA256 != expected.SHA256 {
				t.Errorf("SHA-256 = %s, want %s", cert.SHA256, expected.SHA256)
			}
			if cert.SerialHex != expected.SerialHex {
				t.Errorf("serial = %s, want %s", cert.SerialHex, expected.SerialHex)
			}
			if cert.SubjectString != expected.Subject {
				t.Errorf("subject:\n got %s\nwant %s", cert.SubjectString, expected.Subject)
			}
			if cert.PublicKeyBits != expected.PublicKeyBits {
				t.Errorf("public key bits = %d, want %d", cert.PublicKeyBits, expected.PublicKeyBits)
			}
			before, _ := time.Parse(time.RFC3339, expected.NotBefore)
			after, _ := time.Parse(time.RFC3339, expected.NotAfter)
			if !cert.NotBefore.Equal(before) {
				t.Errorf("not_before = %s, want %s", cert.NotBefore, before)
			}
			if !cert.NotAfter.Equal(after) {
				t.Errorf("not_after = %s, want %s", cert.NotAfter, after)
			}
			if cert.IsCA {
				t.Errorf("leaf certificate unexpectedly has CA basic constraint")
			}
			if cert.EmbeddedLicense {
				t.Errorf("fixture unexpectedly declares an embedded CryptoPro license")
			}

			pemBytes, err := os.ReadFile(filepath.Join(base, expected.PEM))
			if err != nil {
				t.Fatalf("read PEM: %v", err)
			}
			parsedPEM, err := ParseFile(pemBytes)
			if err != nil {
				t.Fatalf("parse PEM: %v", err)
			}
			if len(parsedPEM) != 1 || parsedPEM[0].SHA256 != expected.SHA256 {
				t.Fatalf("PEM certificate does not match DER fixture")
			}
		})
	}

	rootDER, err := os.ReadFile(filepath.Join(base, "root", "root-ca.cer"))
	if err != nil {
		t.Fatalf("read root: %v", err)
	}
	root, err := Parse(rootDER)
	if err != nil {
		t.Fatalf("parse root: %v", err)
	}
	if root.SHA256 != m.RootSHA256 {
		t.Errorf("root SHA-256 = %s, want %s", root.SHA256, m.RootSHA256)
	}
	if !root.IsCA {
		t.Errorf("root must have CA basic constraint")
	}
	for _, expected := range m.Certificates {
		der, err := os.ReadFile(filepath.Join(base, expected.File))
		if err != nil {
			t.Fatal(err)
		}
		cert, err := Parse(der)
		if err != nil {
			t.Fatal(err)
		}
		if cert.IssuerString != root.SubjectString {
			t.Errorf("%s issuer = %q, want root subject %q", expected.File, cert.IssuerString, root.SubjectString)
		}
	}
}

func TestEmbeddedLicenseExtensionDetection(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(42),
		Subject:      pkix.Name{CommonName: "synthetic-extension-detection"},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(time.Hour),
		ExtraExtensions: []pkix.Extension{
			{Id: OIDEmbeddedCryptoProLicense, Value: []byte{0x05, 0x00}},
		},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := Parse(der)
	if err != nil {
		t.Fatal(err)
	}
	if !cert.EmbeddedLicense {
		t.Fatalf("documented embedded-license OID was not detected")
	}
	// This is a synthetic extension-presence test, not a real license fixture.
}

func TestRejectsMalformedInput(t *testing.T) {
	if _, err := Parse(nil); err == nil {
		t.Fatal("expected empty DER error")
	}
	if _, err := Parse([]byte{0x30, 0x00}); err == nil {
		t.Fatal("expected malformed certificate error")
	}
	sum := sha256.Sum256([]byte("not a certificate"))
	_ = sum
	if _, err := ParseFile([]byte("-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n")); err == nil {
		t.Fatal("expected invalid PEM body error")
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte{1, 2, 3}})
	if _, err := ParseFile(pemBytes); err == nil {
		t.Fatal("expected no-certificate PEM error")
	}
}
