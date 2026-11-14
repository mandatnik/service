package agent

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"telehack2026/internal/protocol"
)

func copyFixture(t *testing.T, source, destination string) {
	t.Helper()
	data, err := os.ReadFile(source)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(destination, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

func fixturePath(name string) string {
	return filepath.Join("..", "..", "test-data", "certificates-2026-11-14", name)
}

func TestScanFoldersDERPEMDuplicatesAndCorruption(t *testing.T) {
	dir := t.TempDir()
	copyFixture(t, fixturePath("certificates/01-individual-valid.cer"), filepath.Join(dir, "01.cer"))
	copyFixture(t, fixturePath("certificates/02-individual-expired.cer"), filepath.Join(dir, "02.cer"))
	copyFixture(t, fixturePath("certificates/03-individual-future.cer"), filepath.Join(dir, "03.cer"))
	copyFixture(t, fixturePath("pem/09-ip-valid.pem"), filepath.Join(dir, "09.pem"))
	copyFixture(t, fixturePath("certificates/01-individual-valid.cer"), filepath.Join(dir, "01-duplicate.cer"))
	if err := os.Mkdir(filepath.Join(dir, "nested"), 0o700); err != nil {
		t.Fatal(err)
	}
	copyFixture(t, fixturePath("certificates/04-individual-expires-soon.cer"), filepath.Join(dir, "nested", "04.cer"))

	cfg := protocol.DefaultAgentConfig()
	cfg.CertDirectories = []string{dir}
	sources := ScanFolders(context.Background(), cfg, nil)
	if len(sources) != 1 {
		t.Fatalf("sources = %d", len(sources))
	}
	source := sources[0]
	if !source.Complete {
		t.Fatalf("source unexpectedly partial: %s", source.Error)
	}
	if len(source.Certificates) != 5 {
		t.Fatalf("certificates = %d, want 5", len(source.Certificates))
	}
	if len(source.Files) != 6 {
		t.Fatalf("files = %d, want 6 (duplicate included)", len(source.Files))
	}
	seen := map[string]bool{}
	for _, cert := range source.Certificates {
		seen[cert.SHA256] = true
		if cert.SHA256 == "" || cert.DERBase64 == "" {
			t.Fatal("empty hash/DER")
		}
	}
	for _, want := range []string{
		"686e89cb4235914d9e48c68fc1dca73b248e349493df781c3b8de3510ac6868d",
		"88f4d4178d3304170c59cf9a17dc2f11447b3ea1dee52a081dd5d10a32f010a6",
		"dc7667ab2db38b2e2150753f1dd686b74ea4922807706c9e65c79b842a090de9",
		"6a9c17b4934aaea8214360f75fda8b97542d5b194558f3fc8c557451a70270e1",
		"a3a1624b9caa518b1ebebf003fcfb6d125bb1d3ce5728957e9aa2cd6a430b2c8",
	} {
		if !seen[want] {
			t.Errorf("missing certificate %s", want)
		}
	}

	// A corrupt file makes the source partial but must not remove the valid
	// certificates from the same scan.
	if err := os.WriteFile(filepath.Join(dir, "corrupt.cer"), []byte{1, 2, 3, 4}, 0o600); err != nil {
		t.Fatal(err)
	}
	source = ScanFolders(context.Background(), cfg, nil)[0]
	if source.Complete {
		t.Fatal("corrupt file did not make the source partial")
	}
	if len(source.Certificates) != 5 {
		t.Fatalf("valid certificates lost with corrupt file: %d", len(source.Certificates))
	}
	foundError := false
	for _, file := range source.Files {
		if file.Error != "" {
			foundError = true
		}
	}
	if !foundError {
		t.Fatal("corrupt file error not recorded")
	}

	// Missing directory is partial, not a successful empty result.
	cfg.CertDirectories = []string{filepath.Join(dir, "does-not-exist")}
	source = ScanFolders(context.Background(), cfg, nil)[0]
	if source.Complete {
		t.Fatal("missing directory reported complete")
	}
	if source.Error == "" {
		t.Fatal("missing directory has no error")
	}
}

func TestScanFoldersFileLimit(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"01-individual-valid.cer", "02-individual-expired.cer", "03-individual-future.cer"} {
		copyFixture(t, fixturePath("certificates/"+name), filepath.Join(dir, name))
	}
	cfg := protocol.DefaultAgentConfig()
	cfg.CertDirectories = []string{dir}
	cfg.MaxFiles = 2
	source := ScanFolders(context.Background(), cfg, nil)[0]
	if source.Complete {
		t.Fatal("file limit did not mark source partial")
	}
	if len(source.Certificates) > 2 {
		t.Fatalf("file limit exceeded: %d certificates", len(source.Certificates))
	}
}

func TestBuildReportStatus(t *testing.T) {
	now := mustTime(t)
	complete := Collection{
		StartedAt: now, FinishedAt: now, Hostname: "WORKSTATION-1", ProfilesComplete: true,
		Sources: []protocol.SourceResult{{SourceType: "folder", SourceKey: `C:\certs`, Path: `C:\certs`, Complete: true}},
		CSP:     protocol.CSPResult{Scanned: true, Complete: true, Present: false, License: protocol.LicenseInfo{Kind: "unknown", State: "not_installed", TermKind: "unknown", IsTrial: "unknown"}},
	}
	report := BuildReport(complete, protocol.NewUUID(), 1, "0.1.0")
	if report.Status != "complete" {
		t.Fatalf("complete collection status = %q", report.Status)
	}
	partial := complete
	partial.Sources = []protocol.SourceResult{{SourceType: "folder", SourceKey: `C:\certs`, Path: `C:\certs`, Complete: false, Error: "denied"}}
	report = BuildReport(partial, protocol.NewUUID(), 2, "0.1.0")
	if report.Status != "partial" {
		t.Fatalf("partial collection status = %q", report.Status)
	}
	if err := protocol.ValidateReport(&report); err != nil {
		t.Fatalf("partial report invalid: %v", err)
	}
}

func mustTime(t *testing.T) (value time.Time) {
	t.Helper()
	value, err := time.Parse(time.RFC3339, "2026-11-14T02:00:00Z")
	if err != nil {
		t.Fatal(err)
	}
	return value
}
