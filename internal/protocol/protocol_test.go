package protocol

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"strings"
	"testing"
	"time"

	"telehack2026/internal/certparse"
)

func testKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func TestKeyPEMAndSignatureRoundTrip(t *testing.T) {
	key := testKey(t)
	pemText, err := MarshalPublicKeyPEM(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(pemText, "-----BEGIN PUBLIC KEY-----") {
		t.Fatalf("unexpected public key PEM: %s", pemText)
	}
	parsed, err := ParsePublicKeyPEM(pemText)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.X.Cmp(key.PublicKey.X) != 0 || parsed.Y.Cmp(key.PublicKey.Y) != 0 {
		t.Fatal("public key round trip mismatch")
	}
	fp1, err := PublicKeyFingerprint(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	fp2, err := PublicKeyFingerprint(parsed)
	if err != nil {
		t.Fatal(err)
	}
	if fp1 != fp2 || len(fp1) != 64 {
		t.Fatalf("fingerprint mismatch: %s %s", fp1, fp2)
	}
	payload := []byte(`{"hostname":"WORKSTATION-1","имя":"Тест"}`)
	sig, err := SignCanonical(key, payload)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyCanonical(parsed, payload, sig); err != nil {
		t.Fatalf("signature did not verify: %v", err)
	}
	if err := VerifyCanonical(parsed, []byte(`{"hostname":"WORKSTATION-2","имя":"Тест"}`), sig); err == nil {
		t.Fatal("signature verified for changed payload")
	}
	if err := VerifyCanonical(parsed, payload, append([]byte(nil), sig[:len(sig)-1]...)); err == nil {
		t.Fatal("truncated signature verified")
	}
}

func TestPublicKeyRejectsWrongCurveAndType(t *testing.T) {
	p384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&p384.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	pemText := string(pemEncode("PUBLIC KEY", der))
	if _, err := ParsePublicKeyPEM(pemText); !errors.Is(err, ErrWrongCurve) {
		t.Fatalf("P-384 key error = %v, want ErrWrongCurve", err)
	}
	certDER := testCertificateDER(t)
	if _, err := ParsePublicKeyPEM(string(pemEncode("CERTIFICATE", certDER))); err == nil {
		t.Fatal("certificate PEM accepted as a public key")
	}
	if _, err := ParsePublicKeyPEM("not a pem"); err == nil {
		t.Fatal("garbage accepted as a public key")
	}
}

func pemEncode(kind string, der []byte) []byte {
	return pemEncodeStd(kind, der)
}

func pemEncodeStd(kind string, der []byte) []byte {
	out := []byte("-----BEGIN " + kind + "-----\n")
	enc := base64.StdEncoding.EncodeToString(der)
	for len(enc) > 64 {
		out = append(out, enc[:64]...)
		out = append(out, '\n')
		enc = enc[64:]
	}
	out = append(out, enc...)
	out = append(out, "\n-----END "+kind+"-----\n"...)
	return out
}

func testCertificateDER(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(0x1234),
		Subject:      pkix.Name{Country: []string{"RU"}, Organization: []string{"Тестовая организация"}, CommonName: "Тестовый Пользователь"},
		NotBefore:    now.Add(-24 * time.Hour).Truncate(time.Second),
		NotAfter:     now.Add(24 * time.Hour).Truncate(time.Second),
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func observedFromDER(t *testing.T, der []byte) ObservedCertificate {
	t.Helper()
	cert, err := certparse.Parse(der)
	if err != nil {
		t.Fatal(err)
	}
	return ObservedCertificate{
		SHA256:             cert.SHA256,
		DERBase64:          base64.StdEncoding.EncodeToString(der),
		SerialHex:          cert.SerialHex,
		SerialNumber:       cert.SerialNumber,
		Subject:            cert.SubjectString,
		Issuer:             cert.IssuerString,
		NotBefore:          cert.NotBefore.Format(time.RFC3339),
		NotAfter:           cert.NotAfter.Format(time.RFC3339),
		OwnerCN:            cert.Subject.CommonName(),
		PublicKeyBits:      cert.PublicKeyBits,
		SignatureAlgorithm: certparse.SignatureAlgorithmName(cert.SignatureAlgorithm),
		EmbeddedLicense:    "absent",
	}
}

func baseSignedData(t *testing.T, op string) SignedData {
	t.Helper()
	key := testKey(t)
	pemKey, err := MarshalPublicKeyPEM(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return SignedData{
		ProtocolVersion: ProtocolVersion,
		Operation:       op,
		RequestID:       NewUUID(),
		UUID:            NewUUID(),
		Hostname:        "WORKSTATION-1",
		Method:          MethodPost,
		Path:            PathRegister,
		IssuedAt:        time.Now().UTC().Format(time.RFC3339Nano),
		AgentVersion:    "0.1.0",
		OSVersion:       "Windows 10 19045",
		Architecture:    "amd64",
		PublicKey:       pemKey,
	}
}

func TestEnvelopeRegisterRoundTrip(t *testing.T) {
	data := baseSignedData(t, OpRegister)
	key := testKey(t)
	// Replace the bootstrap key with the actual signing key so the embedded
	// public key matches the signature.
	pemKey, err := MarshalPublicKeyPEM(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	data.PublicKey = pemKey
	raw, err := BuildSignedEnvelope(key, data)
	if err != nil {
		t.Fatal(err)
	}
	req, apiErr := OpenBootstrapEnvelope(raw, MethodPost, PathRegister)
	if apiErr != nil {
		t.Fatalf("bootstrap verify: %+v", apiErr)
	}
	if req.Data.UUID != data.UUID || req.Host.UUID != data.UUID {
		t.Fatal("identity mismatch")
	}
	if len(req.Canonical) == 0 || req.DataHash == [32]byte{} {
		t.Fatal("canonical bytes/hash missing")
	}
	// A normal lookup against the same key must also work.
	if _, apiErr := OpenSignedEnvelope(raw, MethodPost, PathRegister, &key.PublicKey); apiErr != nil {
		t.Fatalf("normal verify: %+v", apiErr)
	}
	// Method/path binding must be exact.
	if _, apiErr := OpenSignedEnvelope(raw, MethodPost, PathSync, &key.PublicKey); apiErr == nil {
		t.Fatal("path substitution accepted")
	}
	if _, apiErr := OpenSignedEnvelope(raw, "GET", PathRegister, &key.PublicKey); apiErr == nil {
		t.Fatal("method substitution accepted")
	}
	// Wrong identity key must fail.
	other := testKey(t)
	if _, apiErr := OpenSignedEnvelope(raw, MethodPost, PathRegister, &other.PublicKey); apiErr == nil {
		t.Fatal("wrong key accepted")
	}
}

func TestEnvelopeHostAndTamperChecks(t *testing.T) {
	key := testKey(t)
	data := baseSignedData(t, OpSync)
	data.Path = PathSync
	pemKey, _ := MarshalPublicKeyPEM(&key.PublicKey)
	data.PublicKey = pemKey
	raw, err := BuildSignedEnvelope(key, data)
	if err != nil {
		t.Fatal(err)
	}
	var env map[string]any
	if err := json.Unmarshal(raw, &env); err != nil {
		t.Fatal(err)
	}
	// Outer host is not signed, so replacing it must be detected by equality.
	env["host"].(map[string]any)["uuid"] = NewUUID()
	changed, _ := json.Marshal(env)
	if _, apiErr := OpenSignedEnvelope(changed, MethodPost, PathSync, &key.PublicKey); apiErr == nil || apiErr.Code != CodeHostnameMismatch {
		t.Fatalf("host uuid substitution: %+v", apiErr)
	}
	env["host"].(map[string]any)["uuid"] = data.UUID
	env["host"].(map[string]any)["hostname"] = "OTHER-HOST"
	changed, _ = json.Marshal(env)
	if _, apiErr := OpenSignedEnvelope(changed, MethodPost, PathSync, &key.PublicKey); apiErr == nil || apiErr.Code != CodeHostnameMismatch {
		t.Fatalf("host hostname substitution: %+v", apiErr)
	}
	// Tamper with a signed value while keeping the outer host.
	var decoded Envelope
	_ = json.Unmarshal(raw, &decoded)
	var signed map[string]any
	_ = json.Unmarshal(decoded.Data, &signed)
	signed["hostname"] = "OTHER-HOST"
	newData, _ := json.Marshal(signed)
	decoded.Data = newData
	decoded.Host.Hostname = "OTHER-HOST"
	changed, _ = json.Marshal(decoded)
	if _, apiErr := OpenSignedEnvelope(changed, MethodPost, PathSync, &key.PublicKey); apiErr == nil || apiErr.Code != CodeInvalidSignature {
		t.Fatalf("signed hostname tamper: %+v", apiErr)
	}
}

func TestEnvelopeRejectsDuplicateKeys(t *testing.T) {
	key := testKey(t)
	data := baseSignedData(t, OpSync)
	data.Path = PathSync
	raw, err := BuildSignedEnvelope(key, data)
	if err != nil {
		t.Fatal(err)
	}
	var env Envelope
	if err := json.Unmarshal(raw, &env); err != nil {
		t.Fatal(err)
	}
	duplicated := `{"data":` + string(env.Data) + `,"host":{"uuid":"` + env.Host.UUID + `","hostname":"` + env.Host.Hostname + `"},"sign":"` + env.Sign + `","data":{}}`
	if _, apiErr := OpenSignedEnvelope([]byte(duplicated), MethodPost, PathSync, &key.PublicKey); apiErr == nil {
		t.Fatal("duplicate envelope member accepted")
	}
	// Duplicate member inside data must also be rejected.
	bad := strings.Replace(string(env.Data), `"uuid":"`+env.Host.UUID+`"`, `"uuid":"`+env.Host.UUID+`","uuid":"`+env.Host.UUID+`"`, 1)
	full := `{"data":` + bad + `,"host":{"uuid":"` + env.Host.UUID + `","hostname":"` + env.Host.Hostname + `"},"sign":"` + env.Sign + `"}`
	if _, apiErr := OpenSignedEnvelope([]byte(full), MethodPost, PathSync, &key.PublicKey); apiErr == nil {
		t.Fatal("duplicate signed member accepted")
	}
}

func TestReportValidationAndHashes(t *testing.T) {
	der := testCertificateDER(t)
	cert := observedFromDER(t, der)
	now := time.Now().UTC()
	report := &Report{
		ReportID:         NewUUID(),
		ScanSeq:          7,
		CollectedAt:      now.Add(-time.Minute).Format(time.RFC3339Nano),
		StartedAt:        now.Add(-time.Minute).Format(time.RFC3339Nano),
		FinishedAt:       now.Format(time.RFC3339Nano),
		AgentVersion:     "0.1.0",
		Hostname:         "WORKSTATION-1",
		Status:           "complete",
		ProfilesComplete: true,
		Profiles: []ProfileResult{
			{SID: "S-1-5-21-1-2-3-1001", Name: "user1", ProfilePath: `C:\Users\user1`, Loaded: false, StorePresent: true, Complete: true},
		},
		Sources: []SourceResult{
			{
				SourceType: "user_store", SourceKey: "S-1-5-21-1-2-3-1001", UserSID: "S-1-5-21-1-2-3-1001",
				Complete: true, Certificates: []ObservedCertificate{cert},
			},
			{
				SourceType: "folder", SourceKey: `C:\certs`, Path: `C:\certs`, Complete: true,
				Certificates: []ObservedCertificate{cert},
				Files:        []ObservedFile{{Path: `C:\certs\a.cer`, SHA256: cert.SHA256}},
			},
		},
		CSP: CSPResult{
			Scanned: true, Complete: true, Present: true, ProductVersion: "5.0.13003", CoreVersion: "5.0.10013",
			License: LicenseInfo{Kind: "client", KindRaw: "0", KindSource: "CPCSPLicense.GetType", State: "active", TermKind: "time_limited", IsTrial: "unknown", TimeBasis: "system_local_assumed"},
		},
	}
	if apiErr := ValidateReport(report); apiErr != nil {
		t.Fatalf("valid report rejected: %+v", apiErr)
	}
	hash1, err := ReportPayloadHash(mustJSON(t, report))
	if err != nil {
		t.Fatal(err)
	}
	hash2, err := ReportPayloadHash(mustJSON(t, report))
	if err != nil || hash1 != hash2 || len(hash1) != 64 {
		t.Fatalf("report hash is not stable: %s %s %v", hash1, hash2, err)
	}
	badStatus := *report
	badStatus.Status = "partial"
	if apiErr := ValidateReport(&badStatus); apiErr == nil {
		t.Fatal("inconsistent status accepted")
	}
	badHash := *report
	badHash.Sources = append([]SourceResult(nil), report.Sources...)
	badHash.Sources[0].Certificates = append([]ObservedCertificate(nil), report.Sources[0].Certificates...)
	badHash.Sources[0].Certificates[0].SHA256 = strings.Repeat("0", 64)
	if apiErr := ValidateReport(&badHash); apiErr == nil {
		t.Fatal("certificate hash mismatch accepted")
	}
	badFile := *report
	badFile.Sources = append([]SourceResult(nil), report.Sources...)
	badFile.Sources[1].Files = []ObservedFile{{Path: `C:\certs\b.cer`, SHA256: strings.Repeat("1", 64)}}
	if apiErr := ValidateReport(&badFile); apiErr == nil {
		t.Fatal("file referencing unknown certificate accepted")
	}
}

func TestReportEnvelopeBindsReportFields(t *testing.T) {
	key := testKey(t)
	der := testCertificateDER(t)
	cert := observedFromDER(t, der)
	report := &Report{
		ReportID: NewUUID(), ScanSeq: 1,
		CollectedAt: time.Now().UTC().Format(time.RFC3339Nano), StartedAt: time.Now().UTC().Format(time.RFC3339Nano), FinishedAt: time.Now().UTC().Format(time.RFC3339Nano),
		AgentVersion: "0.1.0", Hostname: "WORKSTATION-1", Status: "complete", ProfilesComplete: true,
		Profiles: []ProfileResult{},
		Sources:  []SourceResult{{SourceType: "folder", SourceKey: `C:\certs`, Path: `C:\certs`, Complete: true, Certificates: []ObservedCertificate{cert}}},
		CSP:      CSPResult{Scanned: true, Complete: true, Present: false, License: LicenseInfo{Kind: "unknown", State: "not_installed", TermKind: "unknown", IsTrial: "unknown"}},
	}
	reportRaw := mustJSON(t, report)
	pemKey, _ := MarshalPublicKeyPEM(&key.PublicKey)
	data := baseSignedData(t, OpReport)
	data.Path = PathReport
	data.PublicKey = pemKey
	data.ReportID = report.ReportID
	seq := report.ScanSeq
	data.ScanSeq = &seq
	data.CollectedAt = report.CollectedAt
	data.Report = reportRaw
	raw, err := BuildSignedEnvelope(key, data)
	if err != nil {
		t.Fatal(err)
	}
	req, apiErr := OpenSignedEnvelope(raw, MethodPost, PathReport, &key.PublicKey)
	if apiErr != nil {
		t.Fatalf("report envelope: %+v", apiErr)
	}
	var decoded Report
	if err := json.Unmarshal(req.Data.Report, &decoded); err != nil {
		t.Fatal(err)
	}
	if err := ValidateReport(&decoded); err != nil {
		t.Fatalf("decoded report invalid: %+v", err)
	}
	if decoded.ReportID != req.Data.ReportID || decoded.ScanSeq != *req.Data.ScanSeq || decoded.CollectedAt != req.Data.CollectedAt {
		t.Fatal("report fields do not match signed data")
	}
}

func mustJSON(t *testing.T, value any) []byte {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestConfigHashIsCanonical(t *testing.T) {
	cfg := DefaultAgentConfig()
	cfg.CertDirectories = []string{`C:\certs`, `D:\more`}
	hash1, err := ConfigHash(cfg)
	if err != nil {
		t.Fatal(err)
	}
	reordered := []byte(`{"max_file_bytes":10485760,"max_files":2000,"recursive":true,"cert_directories":["C:\\certs","D:\\more"],"scan_interval_days":1,"version":1}`)
	decoded, err := DecodeConfig(reordered)
	if err != nil {
		t.Fatalf("decode reordered config: %v", err)
	}
	hash2, err := ConfigHash(decoded)
	if err != nil {
		t.Fatal(err)
	}
	if hash1 != hash2 {
		t.Fatalf("config hash depends on member order: %s %s", hash1, hash2)
	}
	bad := cfg
	bad.ScanIntervalDays = 0
	if _, err := ConfigHash(bad); err == nil {
		t.Fatal("invalid interval accepted")
	}
	bad = cfg
	bad.CertDirectories = []string{"C:\\a", "c:\\A\\"}
	if err := ValidateConfig(&bad); err != nil {
		t.Fatal(err)
	}
	if len(bad.CertDirectories) != 1 {
		t.Fatalf("case-insensitive duplicate directories not collapsed: %v", bad.CertDirectories)
	}
}
