package protocol

import (
	"encoding/json"
	"strings"
	"testing"
)

// These values are synthetic. A real workstation serial must never be
// committed; the full serial must never appear in any API response. These
// helpers are the only place it is converted.
func TestLicenseIDFromRealSerial(t *testing.T) {
	const serial = "99999X00000999ZZZZZ000000"
	masked, err := MaskLicenseSerial(serial)
	if err != nil {
		t.Fatal(err)
	}
	if masked != "99999X00000999ZZZZZ0*****" {
		t.Fatalf("masked serial = %q", masked)
	}
	id, err := LicenseIDFromSerial(serial)
	if err != nil {
		t.Fatal(err)
	}
	const expected = "cc4036b72546fa95edf6de0c9196e60153f72212a1eae180aaef208fb8b06e0d"
	if id != expected {
		t.Fatalf("license id = %q", id)
	}
	if err := ValidateMaskedSerial(masked, id); err != nil {
		t.Fatal(err)
	}
}

func TestLicenseSerialNormalization(t *testing.T) {
	cases := map[string]string{
		"99999X00000999ZZZZZ000000":        "99999X00000999ZZZZZ000000",
		"99999X-00000999-ZZZZ-Z000000":     "99999X00000999ZZZZZ000000",
		"  99999x 00000999 zzzz z000000  ": "99999X00000999ZZZZZ000000",
	}
	for input, expected := range cases {
		if got := NormalizeLicenseSerial(input); got != expected {
			t.Errorf("NormalizeLicenseSerial(%q) = %q, want %q", input, got, expected)
		}
	}
}

func TestLicenseSerialRejectsShortValue(t *testing.T) {
	if _, err := MaskLicenseSerial("1234"); err == nil {
		t.Fatal("short serial accepted")
	}
	if _, err := LicenseIDFromSerial(""); err == nil {
		t.Fatal("empty serial accepted")
	}
}

func TestValidateLicenseIDCanonicalForm(t *testing.T) {
	if err := ValidateLicenseID("A5DC754D2FF42421CCBFAA9B91F1CB0BBB980B7534A8EC42B32E6FCE31AE3FC6"); err == nil {
		t.Fatal("uppercase license id accepted")
	}
	if err := ValidateLicenseID("a5dc"); err == nil {
		t.Fatal("short license id accepted")
	}
	if err := ValidateLicenseID("zzdc754d2ff42421ccbfaa9b91f1cb0bbb980b7534a8ec42b32e6fce31ae3fc6"); err == nil {
		t.Fatal("non-hex license id accepted")
	}
}

func TestValidateMaskedSerialMismatch(t *testing.T) {
	const masked = "99999X00000999ZZZZZ0*****"
	if err := ValidateMaskedSerial(masked, "cc4036b72546fa95edf6de0c9196e60153f72212a1eae180aaef208fb8b06e0d"); err != nil {
		t.Fatal(err)
	}
	if err := ValidateMaskedSerial(masked, "0000000000000000000000000000000000000000000000000000000000000000"); err == nil {
		t.Fatal("mismatched license id accepted")
	}
}

func TestValidateLicenseRecord(t *testing.T) {
	valid := LicenseInfo{
		LicenseID:    "cc4036b72546fa95edf6de0c9196e60153f72212a1eae180aaef208fb8b06e0d",
		SerialMasked: "99999X00000999ZZZZZ0*****",
		Product:      "csp",
		ProductCode:  0,
		ProductName:  "CryptoPro CSP",
		Complete:     true,
		Kind:         "client",
		State:        "active",
		TermKind:     "perpetual",
		Source:       "CPCSPLicense",
	}
	if err := validateLicenseRecord(valid); err != nil {
		t.Fatal(err)
	}
	cases := map[string]func(*LicenseInfo){
		"bad id":          func(v *LicenseInfo) { v.LicenseID = "short" },
		"bad mask":        func(v *LicenseInfo) { v.SerialMasked = "99999X00000999ZZZZZ0" },
		"unknown product": func(v *LicenseInfo) { v.Product = "other" },
		"wrong code":      func(v *LicenseInfo) { v.ProductCode = 2 },
		"bad state":       func(v *LicenseInfo) { v.State = "broken" },
		"bad term":        func(v *LicenseInfo) { v.TermKind = "forever" },
		"bad trial":       func(v *LicenseInfo) { v.IsTrial = "maybe" },
		"bad date":        func(v *LicenseInfo) { v.ValidToUTC = "tomorrow" },
	}
	for name, mutate := range cases {
		item := valid
		mutate(&item)
		if err := validateLicenseRecord(item); err == nil {
			t.Fatalf("%s: invalid license record accepted", name)
		}
	}
}

func TestEmptyLicensesMarshalAsExplicitArray(t *testing.T) {
	raw, err := json.Marshal(CSPResult{Licenses: []LicenseInfo{}})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), `"licenses":[]`) {
		t.Fatalf("empty license list was omitted: %s", raw)
	}
}
