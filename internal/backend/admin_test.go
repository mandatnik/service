package backend

import (
	"strings"
	"testing"

	"golang.org/x/crypto/bcrypt"
	"mandatnik/internal/backend/store"
)

func TestHashAdminPassword(t *testing.T) {
	hash, err := HashAdminPassword("a-long-test-password")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(hash, "$2") {
		t.Fatalf("expected bcrypt hash, got %q", hash)
	}
	if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte("a-long-test-password")); err != nil {
		t.Fatalf("hash does not verify: %v", err)
	}
	if _, err := HashAdminPassword("short"); err == nil {
		t.Fatal("short password must be rejected")
	}
}

func TestTokenHashIsStableAndOpaque(t *testing.T) {
	a := store.TokenHash("session-token")
	b := store.TokenHash("session-token")
	if a != b || len(a) != 64 {
		t.Fatalf("token hash not stable/sha256: %q %q", a, b)
	}
	if a == "session-token" {
		t.Fatal("token hash must not equal the token")
	}
}
