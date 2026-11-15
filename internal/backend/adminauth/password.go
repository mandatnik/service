// Package adminauth contains the password rules shared by the bootstrap CLI
// and the administrator-management API.
package adminauth

import (
	"fmt"

	"golang.org/x/crypto/bcrypt"
)

// MinPasswordLength matches the documented local-administrator requirement.
const MinPasswordLength = 12

// ValidatePassword rejects short passwords. The password is not trimmed or
// otherwise normalized: the exact value entered by the administrator is used.
func ValidatePassword(password string) error {
	if len(password) < MinPasswordLength {
		return fmt.Errorf("administrator password must contain at least %d characters", MinPasswordLength)
	}
	return nil
}

// Hash produces the bcrypt cost-12 hash stored in dbo.administrators.
func Hash(password string) (string, error) {
	if err := ValidatePassword(password); err != nil {
		return "", err
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), 12)
	if err != nil {
		return "", fmt.Errorf("hash administrator password: %w", err)
	}
	return string(hash), nil
}
