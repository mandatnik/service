package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCleanCannotDeleteRepository(t *testing.T) {
	for _, path := range []string{".", "..", "/", "internal", "artifacts", "build"} {
		if err := clean(path); err == nil {
			t.Errorf("unsafe clean accepted %s", path)
		}
	}
}
func TestProductCodeVersionIdentity(t *testing.T) {
	if productCode("0.4.0") != "{35F44613-8F88-4599-8D86-C901BB368F47}" {
		t.Fatal("breaks installed MSI identity")
	}
	if productCode("0.5.0") == productCode("0.4.0") || productCode("0.5.0") != productCode("0.5.0") {
		t.Fatal("version identity is unstable")
	}
}
func TestE2ERequiresExplicitHTTPSConfig(t *testing.T) {
	if validateConfig("") == nil {
		t.Fatal("missing config accepted")
	}
	file := filepath.Join(t.TempDir(), "config.json")
	os.WriteFile(file, []byte(`{"server_url":"http://localhost","db":{"database":"test"}}`), 0600)
	if validateConfig(file) == nil {
		t.Fatal("HTTP config accepted")
	}
}
