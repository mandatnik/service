package agent

import (
	"context"
	"os"
	"path/filepath"
	"telehack2026/internal/protocol"
	"testing"
)

func TestFolderPoliciesPriorityAndOnlyCER(t *testing.T) {
	dir := t.TempDir()
	for _, sub := range []string{"keep", "trash", "other"} {
		if err := os.Mkdir(filepath.Join(dir, sub), 0700); err != nil {
			t.Fatal(err)
		}
	}
	for _, file := range []string{"keep/a.cer", "trash/b.CER", "other/c.cer", "keep/ignored.crt", "keep/ignored.pem"} {
		copyFixture(t, fixturePath("certificates/01-individual-valid.cer"), filepath.Join(dir, file))
	}
	root := filepath.ToSlash(dir)
	cfg := protocol.DefaultAgentConfig()
	policy := func(id, level, rules string) protocol.FolderPolicy {
		return protocol.FolderPolicy{ID: id, Name: id, Level: level, Rules: rules}
	}
	cfg.FolderPolicies = []protocol.FolderPolicy{policy("group-a", "group", root+"/\n!"+root+"/trash"), policy("group-b", "group", root+"/trash")}
	scan := func(want int) {
		t.Helper()
		s := ScanFolders(context.Background(), cfg, nil)[0]
		if !s.Complete || len(s.Files) != want {
			t.Fatalf("want %d: complete=%v files=%d error=%s", want, s.Complete, len(s.Files), s.Error)
		}
	}
	scan(3) // same-level exclusion does not veto another policy
	cfg.FolderPolicies = append(cfg.FolderPolicies, policy("direct-exclusion", "machine", "!"+root+"/trash"))
	scan(2)
	cfg.FolderPolicies = append(cfg.FolderPolicies, policy("direct-inclusion", "machine", root+"/trash"))
	scan(3) // another direct policy remains independent
	cfg.FolderPolicies = nil
	cfg.CertDirectories = []string{dir}
	scan(0) // no fallback to legacy/global paths
}
func TestWildcardFoldersAndNoLinks(t *testing.T) {
	root := t.TempDir()
	for _, user := range []string{"Иван", "agent"} {
		d := filepath.Join(root, user, "AppData", "testDir")
		if err := os.MkdirAll(d, 0700); err != nil {
			t.Fatal(err)
		}
		copyFixture(t, fixturePath("certificates/01-individual-valid.cer"), filepath.Join(d, "test.cer"))
	}
	cfg := protocol.DefaultAgentConfig()
	cfg.FolderPolicies = []protocol.FolderPolicy{{ID: "wild", Name: "wild", Level: "machine", Rules: filepath.ToSlash(root) + "/*/AppData/testDir/"}}
	s := ScanFolders(context.Background(), cfg, nil)[0]
	if !s.Complete || len(s.Files) != 2 {
		t.Fatalf("wildcards: %+v", s)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	s = ScanFolders(ctx, cfg, nil)[0]
	if s.Complete {
		t.Fatal("cancelled scan is complete")
	}
}
