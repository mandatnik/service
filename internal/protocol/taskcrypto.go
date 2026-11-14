package protocol

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
)

const (
	RSAEncryptionBits = 3072
	maxTaskParameters = 1 << 20
)

// GenerateTaskEncryptionKey creates the dedicated RSA-3072 key used only for
// task parameter envelopes. It is never the ECDSA transport/signing identity.
func GenerateTaskEncryptionKey() (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(rand.Reader, RSAEncryptionBits)
}

func MarshalTaskPublicKeyPEM(pub *rsa.PublicKey) (string, error) {
	if pub == nil || pub.N.BitLen() != RSAEncryptionBits {
		return "", fmt.Errorf("task encryption key must be RSA-%d", RSAEncryptionBits)
	}
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "", fmt.Errorf("marshal task public key: %w", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})), nil
}

func ParseTaskPublicKeyPEM(encoded string) (*rsa.PublicKey, error) {
	if len(encoded) == 0 || len(encoded) > 16*1024 {
		return nil, errors.New("task public key PEM length out of range")
	}
	block, rest := pem.Decode([]byte(encoded))
	if block == nil || len(rest) != 0 || block.Type != "PUBLIC KEY" || len(block.Headers) != 0 {
		return nil, errors.New("task public key must be a single PUBLIC KEY PEM block")
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse task public key: %w", err)
	}
	pub, ok := parsed.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("task public key is not RSA")
	}
	if pub.N == nil || pub.N.BitLen() != RSAEncryptionBits {
		return nil, fmt.Errorf("task public key must be RSA-%d", RSAEncryptionBits)
	}
	if pub.E != 65537 {
		return nil, errors.New("task public key exponent must be 65537")
	}
	return pub, nil
}

func TaskPublicKeyID(pub *rsa.PublicKey) (string, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(der)
	return hex.EncodeToString(sum[:]), nil
}

// SealTaskParameters builds the versioned RSA-OAEP-SHA256 + AES-256-GCM
// envelope. The same canonical binding is the OAEP label and the AEAD AAD.
func SealTaskParameters(pub *rsa.PublicKey, binding TaskBinding, plaintext []byte) (EncryptedParameters, error) {
	var empty EncryptedParameters
	if pub == nil {
		return empty, errors.New("nil task encryption key")
	}
	if len(plaintext) == 0 || len(plaintext) > maxTaskParameters {
		return empty, fmt.Errorf("task parameters length out of range")
	}
	if err := validateTaskBinding(binding); err != nil {
		return empty, err
	}
	keyID, err := TaskPublicKeyID(pub)
	if err != nil {
		return empty, err
	}
	if binding.RecipientKeyID != keyID {
		return empty, errors.New("binding recipient key does not match the public key")
	}
	aad, err := TaskBindingAAD(binding)
	if err != nil {
		return empty, err
	}
	contentKey := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, contentKey); err != nil {
		return empty, fmt.Errorf("generate content key: %w", err)
	}
	nonce := make([]byte, 12)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return empty, fmt.Errorf("generate nonce: %w", err)
	}
	block, err := aes.NewCipher(contentKey)
	if err != nil {
		return empty, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return empty, err
	}
	ciphertext := gcm.Seal(nil, nonce, plaintext, aad)
	wrapped, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, pub, contentKey, aad)
	if err != nil {
		return empty, fmt.Errorf("wrap content key: %w", err)
	}
	return EncryptedParameters{
		Version:        ParametersVersionV1,
		Algorithm:      EncryptionAlgorithmV1,
		RecipientKeyID: keyID,
		WrappedKey:     base64.StdEncoding.EncodeToString(wrapped),
		Nonce:          base64.StdEncoding.EncodeToString(nonce),
		Ciphertext:     base64.StdEncoding.EncodeToString(ciphertext),
	}, nil
}

// OpenTaskParameters verifies the public binding and decrypts the envelope. It
// rejects any ciphertext moved between tasks, items, machines, registrations,
// kinds, key ids or expiry values.
func OpenTaskParameters(key *rsa.PrivateKey, binding TaskBinding, envelope EncryptedParameters) ([]byte, error) {
	if key == nil {
		return nil, errors.New("nil task decryption key")
	}
	if err := validateTaskBinding(binding); err != nil {
		return nil, err
	}
	keyID, err := TaskPublicKeyID(&key.PublicKey)
	if err != nil {
		return nil, err
	}
	if envelope.Version != ParametersVersionV1 || envelope.Algorithm != EncryptionAlgorithmV1 {
		return nil, errors.New("unsupported parameters envelope version or algorithm")
	}
	if envelope.RecipientKeyID != keyID || binding.RecipientKeyID != keyID {
		return nil, errors.New("parameters envelope recipient key mismatch")
	}
	aad, err := TaskBindingAAD(binding)
	if err != nil {
		return nil, err
	}
	wrapped, err := base64.StdEncoding.Strict().DecodeString(envelope.WrappedKey)
	if err != nil {
		return nil, fmt.Errorf("decode wrapped key: %w", err)
	}
	nonce, err := base64.StdEncoding.Strict().DecodeString(envelope.Nonce)
	if err != nil {
		return nil, fmt.Errorf("decode nonce: %w", err)
	}
	ciphertext, err := base64.StdEncoding.Strict().DecodeString(envelope.Ciphertext)
	if err != nil {
		return nil, fmt.Errorf("decode ciphertext: %w", err)
	}
	contentKey, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, key, wrapped, aad)
	if err != nil {
		return nil, fmt.Errorf("unwrap content key: %w", err)
	}
	if len(contentKey) != 32 {
		return nil, errors.New("unwrapped content key has an invalid length")
	}
	if len(nonce) != 12 {
		return nil, errors.New("nonce has an invalid length")
	}
	block, err := aes.NewCipher(contentKey)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	plaintext, err := gcm.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		return nil, errors.New("parameters authentication failed")
	}
	if len(plaintext) == 0 || len(plaintext) > maxTaskParameters {
		return nil, errors.New("decrypted parameters length out of range")
	}
	return plaintext, nil
}

func validateTaskBinding(binding TaskBinding) error {
	if binding.Protocol != TaskBindingProtocol || binding.Purpose != "task_item_parameters" {
		return errors.New("invalid task binding protocol or purpose")
	}
	for name, value := range map[string]string{
		"task_id": binding.TaskID, "item_id": binding.ItemID, "machine_id": binding.MachineID,
	} {
		if _, err := NormalizeUUID(value); err != nil {
			return fmt.Errorf("task binding %s: %w", name, err)
		}
	}
	if binding.RegistrationID <= 0 {
		return errors.New("task binding registration is missing")
	}
	if binding.Kind != TaskKindScan && binding.Kind != TaskKindInstallLicense {
		return errors.New("task binding kind is invalid")
	}
	if binding.ParametersVersion != ParametersVersionV1 {
		return errors.New("task binding parameters version is invalid")
	}
	if len(binding.RecipientKeyID) != 64 {
		return errors.New("task binding recipient key id is invalid")
	}
	if _, err := ValidateTimestamp(binding.ExpiresAt); err != nil {
		return fmt.Errorf("task binding expires_at: %w", err)
	}
	return nil
}
