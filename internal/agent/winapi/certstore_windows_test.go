//go:build windows

package winapi

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

// Exercise the real CryptoAPI pointer boundary on every Windows CI run without
// installing certificates, touching user profiles or requiring an administrator.
func TestEnumerateMemoryCertificateStore(t *testing.T) {
	store, err := windows.CertOpenStore(windows.CERT_STORE_PROV_MEMORY, 0, 0, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer windows.CertCloseStore(store, 0)
	if certs, err := enumerateCertificates(uintptr(store)); err != nil || len(certs) != 0 {
		t.Fatalf("empty store: %d, %v", len(certs), err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	template := x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "CI ephemeral memory store"}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	ctx, err := windows.CertCreateCertificateContext(windows.X509_ASN_ENCODING, &der[0], uint32(len(der)))
	if err != nil {
		t.Fatal(err)
	}
	defer windows.CertFreeCertificateContext(ctx)
	if err = windows.CertAddCertificateContextToStore(store, ctx, windows.CERT_STORE_ADD_ALWAYS, nil); err != nil {
		t.Fatal(err)
	}
	certs, err := enumerateCertificates(uintptr(store))
	if err != nil || len(certs) != 1 || !bytes.Equal(certs[0], der) {
		t.Fatalf("enumeration mismatch: count=%d error=%v", len(certs), err)
	}
	if certs, err = enumerateCertificates(uintptr(store)); err != nil || len(certs) != 1 {
		t.Fatalf("repeat enumeration: %d, %v", len(certs), err)
	}
}
