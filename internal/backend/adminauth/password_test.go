package adminauth

import (
	"strings"
	"testing"

	"golang.org/x/crypto/bcrypt"
)

func TestHashAdministratorPassword(t *testing.T) {
	hash, err := Hash("a-long-test-password")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(hash, "$2") {
		t.Fatalf("expected bcrypt hash, got %q", hash)
	}
	if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte("a-long-test-password")); err != nil {
		t.Fatalf("hash does not verify: %v", err)
	}
}

func TestHashRejectsShortPassword(t *testing.T) {
	if _, err := Hash(strings.Repeat("x", MinPasswordLength-1)); err == nil {
		t.Fatal("short password must be rejected")
	}
	if _, err := Hash(strings.Repeat("x", MinPasswordLength)); err != nil {
		t.Fatalf("minimum-length password rejected: %v", err)
	}
}
