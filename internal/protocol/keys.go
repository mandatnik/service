package protocol

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
)

// GenerateKey creates the agent's ECDSA P-256 identity key.
func GenerateKey() (*ecdsa.PrivateKey, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate ECDSA P-256 key: %w", err)
	}
	return key, nil
}

// MarshalPublicKeyPEM encodes the public key as PEM "PUBLIC KEY" with an SPKI
// DER body. This is the only accepted registration key format.
func MarshalPublicKeyPEM(pub *ecdsa.PublicKey) (string, error) {
	if pub == nil || pub.Curve != elliptic.P256() {
		return "", errors.New("public key must be ECDSA P-256")
	}
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "", fmt.Errorf("marshal public key: %w", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})), nil
}

// ParsePublicKeyPEM parses a PEM "PUBLIC KEY", requires ECDSA P-256, and
// rejects trailing PEM blocks or non-SPKI data.
func ParsePublicKeyPEM(encoded string) (*ecdsa.PublicKey, error) {
	if len(encoded) == 0 || len(encoded) > MaxPublicKeyPEMBytes {
		return nil, fmt.Errorf("public key PEM length out of range")
	}
	block, rest := pem.Decode([]byte(encoded))
	if block == nil {
		return nil, errors.New("public key is not PEM")
	}
	if len(rest) != 0 {
		return nil, errors.New("trailing data after public key PEM block")
	}
	if block.Type != "PUBLIC KEY" {
		return nil, fmt.Errorf("unsupported PEM block %q, want PUBLIC KEY", block.Type)
	}
	if len(block.Headers) != 0 {
		return nil, errors.New("public key PEM must not have headers")
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse SPKI public key: %w", err)
	}
	pub, ok := parsed.(*ecdsa.PublicKey)
	if !ok {
		return nil, errors.New("public key is not ECDSA")
	}
	if pub.Curve != elliptic.P256() {
		return nil, fmt.Errorf("%w: only P-256 is supported", ErrWrongCurve)
	}
	if pub.X == nil || pub.Y == nil || !pub.Curve.IsOnCurve(pub.X, pub.Y) {
		return nil, errors.New("public key point is invalid")
	}
	return pub, nil
}

// ErrWrongCurve distinguishes an otherwise valid ECDSA key on another curve.
var ErrWrongCurve = errors.New("unsupported elliptic curve")

// PublicKeyFingerprint is the SHA-256 of the canonical SPKI DER, lower-case
// hex. It is a key identity, not a certificate fingerprint.
func PublicKeyFingerprint(pub *ecdsa.PublicKey) (string, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "", fmt.Errorf("marshal public key: %w", err)
	}
	sum := sha256.Sum256(der)
	return hex.EncodeToString(sum[:]), nil
}

// MarshalPrivateKeyPKCS8 serializes the private key for DPAPI protection.
func MarshalPrivateKeyPKCS8(key *ecdsa.PrivateKey) ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("marshal private key: %w", err)
	}
	return der, nil
}

// ParsePrivateKeyPKCS8 parses a PKCS#8 ECDSA P-256 private key.
func ParsePrivateKeyPKCS8(der []byte) (*ecdsa.PrivateKey, error) {
	parsed, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil, fmt.Errorf("parse PKCS#8 private key: %w", err)
	}
	key, ok := parsed.(*ecdsa.PrivateKey)
	if !ok {
		return nil, errors.New("private key is not ECDSA")
	}
	if key.Curve != elliptic.P256() {
		return nil, fmt.Errorf("%w: only P-256 is supported", ErrWrongCurve)
	}
	if key.D == nil || key.X == nil || key.Y == nil || !key.Curve.IsOnCurve(key.X, key.Y) {
		return nil, errors.New("private key is invalid")
	}
	return key, nil
}

// SignCanonical signs SHA-256(canonical) and returns ASN.1 DER bytes.
func SignCanonical(key *ecdsa.PrivateKey, canonical []byte) ([]byte, error) {
	digest := sha256.Sum256(canonical)
	sig, err := ecdsa.SignASN1(rand.Reader, key, digest[:])
	if err != nil {
		return nil, fmt.Errorf("ECDSA sign: %w", err)
	}
	return sig, nil
}

// VerifyCanonical verifies an ASN.1 DER ECDSA signature over SHA-256 of the
// canonical bytes.
func VerifyCanonical(pub *ecdsa.PublicKey, canonical, signature []byte) error {
	if pub == nil {
		return errors.New("nil public key")
	}
	if pub.Curve != elliptic.P256() {
		return ErrWrongCurve
	}
	if len(signature) == 0 {
		return errors.New("empty signature")
	}
	digest := sha256.Sum256(canonical)
	if !ecdsa.VerifyASN1(pub, digest[:], signature) {
		return errors.New("ECDSA signature verification failed")
	}
	return nil
}

// EncodeSignatureBase64 uses standard padded Base64 for the DER signature.
func EncodeSignatureBase64(sig []byte) string {
	return base64.StdEncoding.EncodeToString(sig)
}

// DecodeSignatureBase64 strictly decodes standard padded Base64.
func DecodeSignatureBase64(encoded string) ([]byte, error) {
	if encoded == "" {
		return nil, errors.New("empty signature")
	}
	sig, err := base64.StdEncoding.Strict().DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("decode signature Base64: %w", err)
	}
	return sig, nil
}
