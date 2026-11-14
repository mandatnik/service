// Package licensecrypto protects license serial numbers at rest and provides
// a stable, keyed deduplication fingerprint. The keyring and the HMAC key are
// separate files outside the database; losing either is an explicit
// unavailability, never a silent plaintext fallback.
package licensecrypto

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"telehack2026/internal/protocol"
)

const (
	keyringVersion = 1
	keyBytes       = 32
)

type permissionError struct{ path string }

func (e *permissionError) Error() string {
	return "license key material " + e.path + " must not be accessible by group/others"
}

type keyEntry struct {
	KeyID     string `json:"key_id"`
	Key       string `json:"key"`
	CreatedAt string `json:"created_at"`
}

type keyringFile struct {
	Version     int        `json:"version"`
	ActiveKeyID string     `json:"active_key_id"`
	Keys        []keyEntry `json:"keys"`
}

// Keyring is an immutable snapshot of the protected license keyring.
type Keyring struct {
	active string
	keys   map[string][]byte
	path   string
}

type sealedSerial struct {
	Version    int    `json:"v"`
	KeyID      string `json:"key_id"`
	Nonce      string `json:"nonce"`
	Ciphertext string `json:"ciphertext"`
}

// LicenseBinding is the AAD for a stored serial. It binds the serial to its
// immutable row identity and pool characteristics, so a ciphertext cannot be
// moved to another license row or silently reinterpreted as another pool.
type LicenseBinding struct {
	LicenseID       string `json:"license_id"`
	PoolID          string `json:"pool_id"`
	CSPMajorVersion int    `json:"csp_major_version"`
	LicenseKind     string `json:"license_kind"`
	Term            string `json:"term"`
}

func LicenseAAD(binding LicenseBinding) ([]byte, error) {
	raw, err := json.Marshal(binding)
	if err != nil {
		return nil, err
	}
	return protocol.Canonicalize(raw)
}

// InitKeyring creates a new keyring atomically. It never overwrites an
// existing file: backup/restore mistakes must be explicit.
func InitKeyring(path string) (string, error) {
	if path == "" {
		return "", errors.New("license keyring path is empty")
	}
	if _, err := os.Stat(path); err == nil {
		return "", fmt.Errorf("keyring already exists at %s", path)
	} else if !os.IsNotExist(err) {
		return "", err
	}
	key := make([]byte, keyBytes)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return "", err
	}
	keyID, err := randomKeyID()
	if err != nil {
		return "", err
	}
	content := keyringFile{
		Version:     keyringVersion,
		ActiveKeyID: keyID,
		Keys:        []keyEntry{{KeyID: keyID, Key: base64.StdEncoding.EncodeToString(key), CreatedAt: time.Now().UTC().Format(time.RFC3339Nano)}},
	}
	if err := writeProtectedJSON(path, content); err != nil {
		return "", err
	}
	return keyID, nil
}

// InitFingerprintKey creates the separate HMAC key. Existing keys are never
// overwritten.
func InitFingerprintKey(path string) error {
	if path == "" {
		return errors.New("fingerprint key path is empty")
	}
	if _, err := os.Stat(path); err == nil {
		return fmt.Errorf("fingerprint key already exists at %s", path)
	} else if !os.IsNotExist(err) {
		return err
	}
	key := make([]byte, keyBytes)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return err
	}
	return writeProtectedJSON(path, map[string]any{
		"version":    keyringVersion,
		"key":        base64.StdEncoding.EncodeToString(key),
		"created_at": time.Now().UTC().Format(time.RFC3339Nano),
	})
}

func randomKeyID() (string, error) {
	random := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, random); err != nil {
		return "", err
	}
	return hex.EncodeToString(random), nil
}

func writeProtectedJSON(path string, value any) error {
	raw, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return err
	}
	temp, err := os.CreateTemp(filepath.Dir(path), ".keyring-*")
	if err != nil {
		return err
	}
	name := temp.Name()
	defer os.Remove(name)
	if err := temp.Chmod(0o600); err != nil {
		temp.Close()
		return err
	}
	if _, err := temp.Write(raw); err != nil {
		temp.Close()
		return err
	}
	if err := temp.Sync(); err != nil {
		temp.Close()
		return err
	}
	if err := temp.Close(); err != nil {
		return err
	}
	if err := os.Rename(name, path); err != nil {
		return err
	}
	return securePrivateFile(path)
}

// LoadKeyring reads and validates the protected keyring. Group/world-readable
// files are rejected on platforms where POSIX mode bits are meaningful.
func LoadKeyring(path string) (*Keyring, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read license keyring: %w", err)
	}
	if err := checkPrivateFile(path); err != nil {
		return nil, err
	}
	var file keyringFile
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&file); err != nil {
		return nil, fmt.Errorf("decode license keyring: %w", err)
	}
	if file.Version != keyringVersion || file.ActiveKeyID == "" || len(file.Keys) == 0 {
		return nil, errors.New("license keyring is incomplete")
	}
	ring := &Keyring{active: file.ActiveKeyID, keys: map[string][]byte{}, path: path}
	for _, entry := range file.Keys {
		if entry.KeyID == "" || entry.KeyID == file.ActiveKeyID && entry.Key == "" {
			return nil, errors.New("license keyring entry is incomplete")
		}
		key, err := base64.StdEncoding.Strict().DecodeString(entry.Key)
		if err != nil || len(key) != keyBytes {
			return nil, fmt.Errorf("license key %s is invalid", entry.KeyID)
		}
		ring.keys[entry.KeyID] = key
	}
	if _, ok := ring.keys[file.ActiveKeyID]; !ok {
		return nil, errors.New("active license key is missing from keyring")
	}
	return ring, nil
}

func (k *Keyring) ActiveKeyID() string {
	if k == nil {
		return ""
	}
	return k.active
}

// Rotate creates a new active key and rewrites the keyring while retaining all
// older keys for decrypting historical rows. Only after every row is
// re-encrypted may an old key be removed by a separate, explicit operation.
func (k *Keyring) Rotate() (string, error) {
	if k == nil || k.path == "" {
		return "", errors.New("license keyring is unavailable")
	}
	key := make([]byte, keyBytes)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return "", err
	}
	keyID, err := randomKeyID()
	if err != nil {
		return "", err
	}
	k.keys[keyID] = key
	k.active = keyID
	if err := k.write(); err != nil {
		return "", err
	}
	return keyID, nil
}

func (k *Keyring) write() error {
	file := keyringFile{Version: keyringVersion, ActiveKeyID: k.active}
	ids := make([]string, 0, len(k.keys))
	for id := range k.keys {
		ids = append(ids, id)
	}
	sortStrings(ids)
	for _, id := range ids {
		file.Keys = append(file.Keys, keyEntry{KeyID: id, Key: base64.StdEncoding.EncodeToString(k.keys[id]), CreatedAt: time.Now().UTC().Format(time.RFC3339Nano)})
	}
	return writeProtectedJSON(k.path, file)
}

func sortStrings(values []string) {
	for i := 1; i < len(values); i++ {
		for j := i; j > 0 && values[j] < values[j-1]; j-- {
			values[j], values[j-1] = values[j-1], values[j]
		}
	}
}

// Encrypt seals one serial with AES-256-GCM and a fresh nonce.
func (k *Keyring) Encrypt(serial string, aad []byte) ([]byte, error) {
	if k == nil {
		return nil, errors.New("license keyring is unavailable")
	}
	key := k.keys[k.active]
	if len(key) != keyBytes {
		return nil, errors.New("active license key is invalid")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	ciphertext := gcm.Seal(nil, nonce, []byte(serial), aad)
	return json.Marshal(sealedSerial{
		Version:    1,
		KeyID:      k.active,
		Nonce:      base64.StdEncoding.EncodeToString(nonce),
		Ciphertext: base64.StdEncoding.EncodeToString(ciphertext),
	})
}

// Decrypt opens a serial sealed with this keyring. Old key ids remain readable
// after rotation.
func (k *Keyring) Decrypt(blob, aad []byte) (string, error) {
	if k == nil {
		return "", errors.New("license keyring is unavailable")
	}
	var sealed sealedSerial
	decoder := json.NewDecoder(bytes.NewReader(blob))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&sealed); err != nil {
		return "", fmt.Errorf("decode sealed serial: %w", err)
	}
	if sealed.Version != 1 {
		return "", errors.New("unsupported sealed serial version")
	}
	key, ok := k.keys[sealed.KeyID]
	if !ok {
		return "", fmt.Errorf("license key %s is not in the keyring", sealed.KeyID)
	}
	nonce, err := base64.StdEncoding.Strict().DecodeString(sealed.Nonce)
	if err != nil {
		return "", errors.New("invalid sealed serial nonce")
	}
	ciphertext, err := base64.StdEncoding.Strict().DecodeString(sealed.Ciphertext)
	if err != nil {
		return "", errors.New("invalid sealed serial ciphertext")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	plaintext, err := gcm.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		return "", errors.New("sealed serial authentication failed")
	}
	return string(plaintext), nil
}

// FingerprintKey is the stable HMAC key used for global deduplication.
type FingerprintKey struct {
	key []byte
}

func LoadFingerprintKey(path string) (*FingerprintKey, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read fingerprint key: %w", err)
	}
	if err := checkPrivateFile(path); err != nil {
		return nil, err
	}
	var file struct {
		Version   int    `json:"version"`
		Key       string `json:"key"`
		CreatedAt string `json:"created_at,omitempty"`
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&file); err != nil {
		return nil, fmt.Errorf("decode fingerprint key: %w", err)
	}
	key, err := base64.StdEncoding.Strict().DecodeString(file.Key)
	if err != nil || file.Version != keyringVersion || len(key) != keyBytes {
		return nil, errors.New("fingerprint key is invalid")
	}
	return &FingerprintKey{key: key}, nil
}

// Fingerprint returns HMAC-SHA-256 over the normalized serial. Rotation of the
// encryption key does not change this value.
func (k *FingerprintKey) Fingerprint(normalizedSerial string) []byte {
	mac := hmac.New(sha256.New, k.key)
	mac.Write([]byte(strings.ToUpper(normalizedSerial)))
	return mac.Sum(nil)
}
