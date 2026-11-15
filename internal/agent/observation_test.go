package agent

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"telehack2026/internal/certparse"
	"telehack2026/internal/protocol"
)

func TestStripWhitespaceKeepsDERControlBytes(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "test-data", "certificates-2026-11-14", "certificates", "01-individual-valid.cer"))
	if err != nil {
		t.Fatal(err)
	}
	trimmed := stripWhitespace(raw)
	if len(trimmed) != len(raw) {
		t.Fatalf("DER length changed from %d to %d", len(raw), len(trimmed))
	}
	if _, err := certparse.Parse(trimmed); err != nil {
		t.Fatalf("trimmed DER no longer parses: %v", err)
	}
}

func testDERWith(t *testing.T, cn string, notBefore, notAfter time.Time) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(7),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func TestObserveDERKeepsOutOfRangeValidityAsParseError(t *testing.T) {
	der := testDERWith(t, "range-test", time.Now().Add(-time.Hour), time.Date(9999, 1, 1, 0, 0, 0, 0, time.UTC))
	observation, include, err := observeDER(der)
	if !include || err != nil {
		t.Fatalf("include=%v err=%v", include, err)
	}
	if observation.ParseError == "" {
		t.Fatal("out-of-range validity must be reported as parse_error")
	}
	report := protocol.Report{
		ReportID: protocol.NewUUID(), ScanSeq: 1,
		CollectedAt: time.Now().UTC().Format(time.RFC3339Nano), StartedAt: time.Now().UTC().Format(time.RFC3339Nano), FinishedAt: time.Now().UTC().Format(time.RFC3339Nano),
		AgentVersion: "0.5.0", Hostname: "TEST-01", Status: "partial", ProfilesComplete: true,
		Profiles: []protocol.ProfileResult{},
		Sources: []protocol.SourceResult{{SourceType: "folder", SourceKey: `C:\certs`, Path: `C:\certs`, Complete: false,
			Certificates: []protocol.ObservedCertificate{observation}}},
		CSP: protocol.CSPResult{Scanned: true, Complete: true, Present: false, License: protocol.LicenseInfo{Kind: "unknown", State: "not_installed", TermKind: "unknown", IsTrial: "unknown"}, Licenses: []protocol.LicenseInfo{}},
	}
	if apiErr := protocol.ValidateReport(&report); apiErr != nil {
		t.Fatalf("report with out-of-range validity rejected: %+v", apiErr)
	}
}

func TestObserveDERTruncatesLongSubject(t *testing.T) {
	der := testDERWith(t, strings.Repeat("Я", 9000), time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	observation, include, err := observeDER(der)
	if !include || err != nil {
		t.Fatalf("include=%v err=%v", include, err)
	}
	if len(observation.Subject) > protocol.MaxCertificateSubject {
		t.Fatalf("subject length %d exceeds limit", len(observation.Subject))
	}
	if !utf8.ValidString(observation.Subject) {
		t.Fatal("truncated subject is not valid UTF-8")
	}
}

func TestObserveDERSkipsUnrepresentableDER(t *testing.T) {
	der := make([]byte, protocol.MaxDERBytes+1)
	if _, include, _ := observeDER(der); include {
		t.Fatal("oversized DER must be skipped, not included in a report")
	}
}
