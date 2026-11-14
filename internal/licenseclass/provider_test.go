package licenseclass

import (
	"testing"
	"time"
)

func TestProviderAttribution(t *testing.T) {
	cases := []struct {
		name  string
		bind  string
		owner string
	}{
		{"Crypto-Pro GOST R 34.10-2012 Cryptographic Service Provider", "present", ProviderOwnerCryptoPro},
		{"КриптоПро GOST R 34.10-2012", "present", ProviderOwnerCryptoPro},
		{"Crypto-Pro RSA Cryptographic Service Provider", "present", ProviderOwnerCryptoPro},
		{"Microsoft Enhanced RSA and AES Cryptographic Provider", "present", ProviderOwnerOther},
		{"Microsoft Software Key Storage Provider", "present", ProviderOwnerOther},
		{"Some RSA Cryptographic Provider", "present", ProviderOwnerUnknown},
		{"Crypto-Pro GOST", "absent", ProviderOwnerUnknown},
		{"", "present", ProviderOwnerUnknown},
	}
	for _, test := range cases {
		owner, _, _ := AttributeProvider(test.name, "capi", test.bind)
		if owner != test.owner {
			t.Errorf("%q: owner=%s want %s", test.name, owner, test.owner)
		}
	}
}

func TestOLEZeroPerpetual(t *testing.T) {
	zero := time.Date(1899, 12, 30, 0, 0, 0, 0, time.UTC)
	if !IsOLEZeroDate(zero) {
		t.Fatal("OLE zero date not recognized")
	}
	if IsOLEZeroDate(time.Date(2027, 2, 14, 0, 0, 0, 0, time.UTC)) {
		t.Fatal("real date misclassified as OLE zero")
	}
}
