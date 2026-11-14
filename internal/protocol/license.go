package protocol

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
)

// NormalizeLicenseSerial is an alias for the protocol serial normalizer. It
// keeps the inventory code readable while sharing the exact validation used by
// activation tasks.
func NormalizeLicenseSerial(serial string) string {
	return NormalizeSerial(serial)
}

// MaskLicenseSerial returns the normalized serial with the last five symbols
// replaced by stars. The integration API intentionally uses this inventory
// mask, which differs from the task UI's last-four mask.
func MaskLicenseSerial(serial string) (string, error) {
	normalized := NormalizeSerial(serial)
	if err := ValidateSerialFormat(normalized); err != nil {
		return "", err
	}
	return normalized[:len(normalized)-5] + "*****", nil
}

// LicenseIDFromMaskedSerial computes the stable identifier used by the
// integration API. The input must already be masked.
func LicenseIDFromMaskedSerial(masked string) string {
	sum := sha256.Sum256([]byte(masked))
	return hex.EncodeToString(sum[:])
}

// LicenseIDFromSerial normalizes, masks and hashes a raw license serial.
func LicenseIDFromSerial(serial string) (string, error) {
	masked, err := MaskLicenseSerial(serial)
	if err != nil {
		return "", err
	}
	return LicenseIDFromMaskedSerial(masked), nil
}

// ValidateLicenseID checks the canonical lowercase SHA-256 form.
func ValidateLicenseID(value string) error {
	if len(value) != 64 {
		return fmt.Errorf("license_id must contain 64 lowercase hex characters")
	}
	if strings.ToLower(value) != value {
		return fmt.Errorf("license_id must be lowercase")
	}
	if _, err := hex.DecodeString(value); err != nil {
		return fmt.Errorf("license_id must be hexadecimal")
	}
	return nil
}

// ValidateMaskedSerial checks the masked serial form and its hash.
func ValidateMaskedSerial(masked, licenseID string) error {
	if !strings.HasSuffix(masked, "*****") {
		return fmt.Errorf("serial_masked must end with five stars")
	}
	if len([]rune(masked)) < 5 {
		return fmt.Errorf("serial_masked is too short")
	}
	if LicenseIDFromMaskedSerial(masked) != strings.ToLower(licenseID) {
		return fmt.Errorf("license_id does not match serial_masked")
	}
	return nil
}
