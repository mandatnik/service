package setup

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func testKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func testCert(t *testing.T, modify func(*x509.Certificate), hosts ...string) (*rsa.PrivateKey, *x509.Certificate) {
	t.Helper()
	key := testKey(t)
	template := &x509.Certificate{
		SerialNumber:          mustSerial(t),
		Subject:               pkix.Name{CommonName: hosts[0]},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().AddDate(1, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	dns, ips, err := splitHosts(hosts)
	if err != nil {
		t.Fatal(err)
	}
	template.DNSNames = dns
	template.IPAddresses = ips
	if modify != nil {
		modify(template)
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return key, cert
}

func mustSerial(t *testing.T) (serial *big.Int) {
	t.Helper()
	s, err := NewSerial()
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// TestValidateServerCertSAN checks SAN coverage, IP SAN and the CN-only case.
func TestValidateServerCertSAN(t *testing.T) {
	_, cert := testCert(t, nil, "backend.telehack.test", "192.168.189.138")
	check, err := ValidateServerCert(cert, nil, []string{"backend.telehack.test", "192.168.189.138"}, nil, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if !check.OK {
		t.Fatalf("expected OK, problems=%v", check.Problems)
	}
	// A missing host must be rejected.
	check, err = ValidateServerCert(cert, nil, []string{"other.example.com"}, nil, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if check.OK {
		t.Fatal("expected failure for missing SAN")
	}
	if len(check.Problems) != 1 || !strings.Contains(check.Problems[0], "SAN") {
		t.Fatalf("unexpected problems: %v", check.Problems)
	}
}

// TestValidateServerCertCNOnly verifies CN is never trusted instead of SAN.
func TestValidateServerCertCNOnly(t *testing.T) {
	_, cert := testCert(t, func(c *x509.Certificate) {
		c.DNSNames = nil
		c.IPAddresses = nil
	}, "backend.telehack.test")
	check, err := ValidateServerCert(cert, nil, []string{"backend.telehack.test"}, nil, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if check.OK {
		t.Fatal("CN-only certificate must be rejected")
	}
}

// TestValidateServerCertExpiryAndEKU covers expiry and server-auth checks.
func TestValidateServerCertExpiryAndEKU(t *testing.T) {
	_, expired := testCert(t, func(c *x509.Certificate) {
		c.NotBefore = time.Now().Add(-48 * time.Hour)
		c.NotAfter = time.Now().Add(-24 * time.Hour)
	}, "backend.telehack.test")
	check, _ := ValidateServerCert(expired, nil, []string{"backend.telehack.test"}, nil, time.Now())
	if check.OK || !check.Expired {
		t.Fatal("expired certificate must fail")
	}
	_, noEKU := testCert(t, func(c *x509.Certificate) { c.ExtKeyUsage = nil }, "backend.telehack.test")
	check, _ = ValidateServerCert(noEKU, nil, []string{"backend.telehack.test"}, nil, time.Now())
	if check.OK {
		t.Fatal("missing ServerAuth EKU must fail")
	}
}

// TestValidateServerCertWeakKey checks the RSA-2048 minimum.
func TestValidateServerCertWeakKey(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber:          mustSerial(t),
		Subject:               pkix.Name{CommonName: "weak"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().AddDate(1, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"backend.telehack.test"},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	check, _ := ValidateServerCert(cert, nil, []string{"backend.telehack.test"}, nil, time.Now())
	if check.OK {
		t.Fatal("RSA-1024 must be rejected")
	}
}

// TestKeyMatch tests the private-key/certificate pairing check.
func TestKeyMatch(t *testing.T) {
	key, cert := testCert(t, nil, "backend.telehack.test")
	if err := KeyMatchesTLS(cert, key); err != nil {
		t.Fatalf("matching key rejected: %v", err)
	}
	other := testKey(t)
	if err := KeyMatchesTLS(cert, other); err == nil {
		t.Fatal("mismatched key accepted")
	}
}

// TestCADraftIssueAndValidate covers the installation CA lifecycle.
func TestCADraftIssueAndValidate(t *testing.T) {
	caCert, caKey, err := CreateInstallationCA("Test CA", 1825)
	if err != nil {
		t.Fatal(err)
	}
	cert, key, err := IssueServerCert(caCert, caKey, "backend.telehack.test", []string{"backend.telehack.test", "10.0.0.5"}, 397)
	if err != nil {
		t.Fatal(err)
	}
	check, err := ValidateServerCert(cert, nil, []string{"backend.telehack.test", "10.0.0.5"}, []*x509.Certificate{caCert}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if !check.OK {
		t.Fatalf("issued certificate rejected: %v", check.Problems)
	}
	if err := KeyMatchesTLS(cert, key); err != nil {
		t.Fatal(err)
	}
	// Encrypted export roundtrip.
	dir := t.TempDir()
	certPath := filepath.Join(dir, "ca.crt")
	keyPath := filepath.Join(dir, "ca.key.enc")
	if err := WriteCAFiles(certPath, keyPath, caCert, caKey, "passphrase-1"); err != nil {
		t.Fatal(err)
	}
	opened, err := DecryptPEMKey(keyPath, "passphrase-1")
	if err != nil {
		t.Fatal(err)
	}
	if opened == nil {
		t.Fatal("decrypted key is nil")
	}
	if _, err := DecryptPEMKey(keyPath, "wrong"); err == nil {
		t.Fatal("wrong passphrase accepted")
	}
}

// TestDraftResumeAndMarker covers draft persistence, resumability and the
// completed-installation guard.
func TestDraftResumeAndMarker(t *testing.T) {
	paths := NewPaths(t.TempDir())
	if err := os.MkdirAll(paths.Root, 0o700); err != nil {
		t.Fatal(err)
	}
	draft := &Draft{Mode: "install", Steps: map[string]StepState{}}
	draft.SetStep(StepIntro, StatusDone, "")
	if err := draft.Save(paths); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadDraft(paths)
	if err != nil {
		t.Fatal(err)
	}
	if loaded == nil || !loaded.IsDone(StepIntro) {
		t.Fatal("draft step lost")
	}
	if pending := loaded.PendingSteps(); len(pending) == 0 || pending[0] != StepRights {
		t.Fatalf("unexpected pending steps: %v", pending)
	}
	// Marker stays absent until completion.
	if got := MarkerStatus(paths); got != MarkerNone && got != MarkerDraft {
		t.Fatalf("unexpected marker status %q", got)
	}
	if err := SaveMarker(paths, Marker{Status: MarkerCompleted, Mode: "install"}); err != nil {
		t.Fatal(err)
	}
	if MarkerStatus(paths) != MarkerCompleted {
		t.Fatal("marker not recorded")
	}
}

// TestDraftExpiry covers the stale-draft detection.
func TestDraftExpiry(t *testing.T) {
	draft := &Draft{CreatedAt: time.Now().Add(-31 * 24 * time.Hour).Format(time.RFC3339)}
	if !draft.DraftExpired(time.Now()) {
		t.Fatal("31-day-old draft must be expired")
	}
	draft.CreatedAt = time.Now().Format(time.RFC3339)
	if draft.DraftExpired(time.Now()) {
		t.Fatal("fresh draft must not be expired")
	}
}

// TestBundleRoundtrip covers export, read-back verification and wrong
// passphrase behaviour.
func TestBundleRoundtrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "recovery.mndk")
	manifest := &BundleManifest{}
	files := []BundleFile{{Name: "license-keyring.json", Role: "key", Data: []byte(`{"version":1}`)}}
	if err := BuildBundle(path, manifest, files, "bundle-pass-123"); err != nil {
		t.Fatal(err)
	}
	opened, filesOut, err := OpenBundle(path, "bundle-pass-123")
	if err != nil {
		t.Fatal(err)
	}
	if len(filesOut) != 1 || opened.CreatedAt == "" {
		t.Fatal("bundle content mismatch")
	}
	if _, _, err := OpenBundle(path, "wrong"); err == nil {
		t.Fatal("wrong passphrase accepted")
	}
	// Corruption must be detected: flip the first byte of the ciphertext hex.
	raw, _ := os.ReadFile(path)
	flipped := strings.Replace(string(raw), `"ciphertext": "0`, `"ciphertext": "1`, 1)
	if flipped == string(raw) {
		flipped = strings.Replace(string(raw), `"ciphertext":"0`, `"ciphertext":"1`, 1)
	}
	if flipped != string(raw) {
		_ = os.WriteFile(path, []byte(flipped), 0o600)
		if _, _, err := OpenBundle(path, "bundle-pass-123"); err == nil {
			t.Fatal("corrupted bundle accepted")
		}
		_ = os.WriteFile(path, raw, 0o600)
	}
}

// TestClassifyTables covers the database classification rules, including the
// own service objects.
func TestClassifyTables(t *testing.T) {
	if got := classifyTables(nil); got != "empty" {
		t.Fatalf("empty: %q", got)
	}
	if got := classifyTables([]string{"machines", "registrations"}); got != "mandatnik" {
		t.Fatalf("mandatnik: %q", got)
	}
	if got := classifyTables([]string{"schema_migrations"}); got != "mandatnik" {
		t.Fatalf("own service object: %q", got)
	}
	if got := classifyTables([]string{"customers", "orders"}); got != "foreign" {
		t.Fatalf("foreign: %q", got)
	}
}

// TestSecretStoreRoundtrip verifies the sealed store on the current platform.
func TestSecretStoreRoundtrip(t *testing.T) {
	paths := NewPaths(t.TempDir())
	store, err := NewDraftSecrets(paths)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Put(SecretDBPassword, []byte("s3cret-value")); err != nil {
		t.Fatal(err)
	}
	value, err := store.Get(SecretDBPassword)
	if err != nil || string(value) != "s3cret-value" {
		t.Fatalf("roundtrip failed: %v", err)
	}
	if _, err := store.Get("missing"); err == nil {
		t.Fatal("missing secret accepted")
	}
}

// TestCheckPorts covers conflicts and bindability.
func TestCheckPorts(t *testing.T) {
	if err := CheckPorts([]string{"127.0.0.1:0", "127.0.0.1:0"}); err != nil {
		t.Fatalf("port 0 probe rejected: %v", err)
	}
	if err := CheckPorts([]string{"invalid"}); err == nil {
		t.Fatal("malformed address accepted")
	}
}
