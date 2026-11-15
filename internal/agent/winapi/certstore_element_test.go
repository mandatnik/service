package winapi

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/hex"
	"math/big"
	"strings"
	"testing"
	"time"
)

func testDER(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(42),
		Subject:      pkix.Name{CommonName: "file-store-test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func TestDecodeFileStoreElementV3(t *testing.T) {
	der := testDER(t)
	element := make([]byte, 44+len(der))
	binary.LittleEndian.PutUint32(element[0:4], 3)
	sum := sha1.Sum(der)
	copy(element[12:32], sum[:])
	binary.LittleEndian.PutUint32(element[40:44], uint32(len(der)))
	copy(element[44:], der)

	got, err := decodeFileStoreElement(element, strings.ToLower(hex.EncodeToString(sum[:])))
	if err != nil {
		t.Fatalf("v3 element: %v", err)
	}
	if string(got) != string(der) {
		t.Fatal("v3 element returned different DER")
	}
}

func TestDecodeFileStoreElementCryptoProWrapper(t *testing.T) {
	der := testDER(t)
	sum := sha1.Sum(der)
	name := strings.ToLower(hex.EncodeToString(sum[:]))

	// The real container element starts with a length/type/value record for
	// the container name and keeps more key records before the DER. The exact
	// header layout is irrelevant: the SHA-1 of the file name identifies the
	// embedded certificate.
	header := make([]byte, 300)
	binary.LittleEndian.PutUint32(header[0:4], 0x4B)
	binary.LittleEndian.PutUint32(header[4:8], 1)
	binary.LittleEndian.PutUint32(header[8:12], 68)
	copy(header[12:12+34], []byte("E98D47CA6066D5638506AFC181BDD319_"))
	for i := 60; i < len(header); i++ {
		header[i] = byte(i)
	}
	element := append(append([]byte(nil), header...), der...)

	got, err := decodeFileStoreElement(element, name)
	if err != nil {
		t.Fatalf("CryptoPro element: %v", err)
	}
	if string(got) != string(der) {
		t.Fatal("CryptoPro element returned different DER")
	}
}

func TestDecodeFileStoreElementRawDER(t *testing.T) {
	der := testDER(t)
	got, err := decodeFileStoreElement(der, "not-a-sha1-name")
	if err != nil {
		t.Fatalf("raw DER: %v", err)
	}
	if string(got) != string(der) {
		t.Fatal("raw DER returned different bytes")
	}
}

func TestDecodeFileStoreElementRejectsMismatchedName(t *testing.T) {
	der := testDER(t)
	element := append(make([]byte, 300), der...)
	if _, err := decodeFileStoreElement(element, strings.Repeat("0", 40)); err == nil {
		t.Fatal("mismatched SHA-1 file name was accepted")
	}
}

func TestDecodeFileStoreElementRejectsTruncatedDER(t *testing.T) {
	der := testDER(t)
	sum := sha1.Sum(der)
	name := strings.ToLower(hex.EncodeToString(sum[:]))
	element := append(make([]byte, 300), der[:len(der)-8]...)
	if _, err := decodeFileStoreElement(element, name); err == nil {
		t.Fatal("truncated DER was accepted")
	}
}
