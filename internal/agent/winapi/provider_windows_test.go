//go:build windows

package winapi

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"mandatnik/internal/licenseclass"
)

var procCertSetCertificateContextProperty = crypt32.NewProc("CertSetCertificateContextProperty")

func TestProviderBindingsFromRealCertificateContext(t *testing.T) {
	store, err := windows.CertOpenStore(windows.CERT_STORE_PROV_MEMORY, 0, 0, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer windows.CertCloseStore(store, 0)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	template := x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "provider test"}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	ctx, err := windows.CertCreateCertificateContext(windows.X509_ASN_ENCODING, &der[0], uint32(len(der)))
	if err != nil {
		t.Fatal(err)
	}
	defer windows.CertFreeCertificateContext(ctx)

	absent := readProviderBindings(ctx)
	if absent.BindingState != "absent" || absent.ProviderOwner != licenseclass.ProviderOwnerUnknown {
		t.Fatalf("absent property: %+v", absent)
	}
	cases := []struct {
		name  string
		owner string
	}{
		{"Crypto-Pro GOST R 34.10-2012 Cryptographic Service Provider", licenseclass.ProviderOwnerCryptoPro},
		{"Microsoft Enhanced RSA and AES Cryptographic Provider", licenseclass.ProviderOwnerOther},
		{"Unknown RSA Provider", licenseclass.ProviderOwnerUnknown},
	}
	for _, test := range cases {
		name, _ := windows.UTF16PtrFromString(test.name)
		info := cryptKeyProvInfo{ProvName: name, ProvType: 80, KeySpec: 1}
		ok, _, lastErr := procCertSetCertificateContextProperty.Call(
			uintptr(unsafe.Pointer(ctx)), certKeyProvInfoPropID, 0, uintptr(unsafe.Pointer(&info)))
		if ok == 0 {
			t.Fatalf("set provider property: %v", lastErr)
		}
		binding := readProviderBindings(ctx)
		if binding.BindingState != "present" || binding.ProviderOwner != test.owner {
			t.Fatalf("%s: %+v", test.name, binding)
		}
		if binding.PrivateKeyState != "not_checked" {
			t.Fatalf("private key state must stay not_checked: %+v", binding)
		}
		if binding.ProviderAPI != "capi" && binding.ProviderAPI != "cng" {
			t.Fatalf("provider API: %+v", binding)
		}
	}
}
