// Recovery bundle: a passphrase-protected container with the keys and settings
// needed to restore data (license keyring, HMAC fingerprint key, TLS material,
// backend configuration, the CA private key when applicable). Standard
// primitives only: scrypt KDF + AES-256-GCM envelope.
package setup

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"golang.org/x/crypto/scrypt"
)

// Bundle magic and version.
const (
	BundleMagic   = "MNDKBUNDL"
	BundleVersion = 1
)

// BundleFile is one entry of the container.
type BundleFile struct {
	Name   string `json:"name"`
	Role   string `json:"role"` // settings|key|certificate|ca
	Size   int    `json:"size"`
	SHA256 string `json:"sha256"`
	Data   []byte `json:"data"`
}

// BundleManifest documents the exact content of a bundle.
type BundleManifest struct {
	CreatedAt               string       `json:"created_at"`
	BackendExe              string       `json:"backend_exe,omitempty"`
	ContainsCAKey           bool         `json:"contains_ca_key"`
	ContainsServicePassword bool         `json:"contains_service_password"`
	Files                   []BundleFile `json:"files"`
}

type bundleEnvelope struct {
	Magic      string `json:"magic"`
	Version    int    `json:"version"`
	KDF        string `json:"kdf"`
	N          int    `json:"n"`
	R          int    `json:"r"`
	P          int    `json:"p"`
	Salt       string `json:"salt"`
	Nonce      string `json:"nonce"`
	Ciphertext string `json:"ciphertext"`
}

// BuildBundle collects the given files into a passphrase-protected bundle.
func BuildBundle(path string, manifest *BundleManifest, files []BundleFile, passphrase string) error {
	if len(passphrase) < 8 {
		return errors.New("пароль комплекта восстановления должен содержать не менее 8 символов")
	}
	manifest.Files = files
	manifest.CreatedAt = time.Now().UTC().Format(time.RFC3339)
	for i := range manifest.Files {
		manifest.Files[i].SHA256 = fmt.Sprintf("%x", sha256.Sum256(manifest.Files[i].Data))
	}
	plain, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return err
	}
	salt := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return err
	}
	derived, err := scrypt.Key([]byte(passphrase), salt, scryptN, scryptR, scryptP, 32)
	if err != nil {
		return err
	}
	block, err := aes.NewCipher(derived)
	if err != nil {
		return err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return err
	}
	envelope := bundleEnvelope{
		Magic: BundleMagic, Version: BundleVersion,
		KDF: "scrypt", N: scryptN, R: scryptR, P: scryptP,
		Salt: hex.EncodeToString(salt), Nonce: hex.EncodeToString(nonce),
		Ciphertext: hex.EncodeToString(gcm.Seal(nil, nonce, plain, salt)),
	}
	raw, err := json.MarshalIndent(envelope, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return fmt.Errorf("пишу комплект восстановления: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if err := secureFile(path); err != nil {
		return err
	}
	// Read-back verification: only a bundle that opens with the passphrase and
	// matches the manifest counts as an exported bundle.
	if _, _, err := OpenBundle(path, passphrase); err != nil {
		_ = os.Remove(path)
		return fmt.Errorf("комплект не прошёл проверку после записи: %w", err)
	}
	return nil
}

// OpenBundle decrypts and verifies the integrity of a recovery bundle.
func OpenBundle(path, passphrase string) (*BundleManifest, []BundleFile, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, fmt.Errorf("читаю комплект %s: %w", path, err)
	}
	var envelope bundleEnvelope
	if err := json.Unmarshal(raw, &envelope); err != nil {
		return nil, nil, fmt.Errorf("комплект %s повреждён: %w", path, err)
	}
	if envelope.Magic != BundleMagic || envelope.Version != BundleVersion || envelope.KDF != "scrypt" {
		return nil, nil, errors.New("комплект имеет неизвестный формат")
	}
	salt, err := hex.DecodeString(envelope.Salt)
	if err != nil || len(salt) != 16 {
		return nil, nil, errors.New("комплект повреждён (соль)")
	}
	nonce, err := hex.DecodeString(envelope.Nonce)
	if err != nil {
		return nil, nil, errors.New("комплект повреждён (nonce)")
	}
	ciphertext, err := hex.DecodeString(envelope.Ciphertext)
	if err != nil {
		return nil, nil, errors.New("комплект повреждён (данные)")
	}
	derived, err := scrypt.Key([]byte(passphrase), salt, envelope.N, envelope.R, envelope.P, 32)
	if err != nil {
		return nil, nil, err
	}
	block, err := aes.NewCipher(derived)
	if err != nil {
		return nil, nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, err
	}
	plain, err := gcm.Open(nil, nonce, ciphertext, salt)
	if err != nil {
		return nil, nil, errors.New("пароль комплекта неверен или комплект повреждён")
	}
	var manifest BundleManifest
	if err := json.Unmarshal(plain, &manifest); err != nil {
		return nil, nil, fmt.Errorf("манифест комплекта повреждён: %w", err)
	}
	for i := range manifest.Files {
		sum := fmt.Sprintf("%x", sha256.Sum256(manifest.Files[i].Data))
		if sum != manifest.Files[i].SHA256 {
			return nil, nil, fmt.Errorf("файл %q внутри комплекта не совпадает с контрольной суммой", manifest.Files[i].Name)
		}
	}
	return &manifest, manifest.Files, nil
}
