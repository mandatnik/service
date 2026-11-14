package protocol

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"unicode"
)

// NormalizeLicenseSerial removes separators and upper-cases a CryptoPro
// license serial. The documented paper form contains hyphens; the MSI
// ProductID value is usually already without them.
func NormalizeLicenseSerial(serial string) string {
	var builder strings.Builder
	for _, symbol := range serial {
		if symbol == '-' || unicode.IsSpace(symbol) {
			continue
		}
		builder.WriteRune(unicode.ToUpper(symbol))
	}
	return builder.String()
}

// MaskLicenseSerial returns the normalized serial with the last five symbols
// replaced by stars. A serial shorter than five symbols cannot produce the
// agreed license_id and is rejected explicitly.
func MaskLicenseSerial(serial string) (string, error) {
	normalized := NormalizeLicenseSerial(serial)
	if len([]rune(normalized)) < 5 {
		return "", fmt.Errorf("license serial must contain at least 5 symbols")
	}
	runes := []rune(normalized)
	return string(runes[:len(runes)-5]) + "*****", nil
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
