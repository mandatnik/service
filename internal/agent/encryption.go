package agent

import (
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"

	"mandatnik/internal/platform"
	"mandatnik/internal/protocol"
)

const encryptionMagic = "THK2"

type encryptionKeyBundle struct {
	KeyID      string `json:"key_id"`
	PublicPEM  string `json:"public_key_pem"`
	PrivatePK8 string `json:"private_key_pkcs8"`
	CreatedAt  string `json:"created_at"`
}

type encryptionBundle struct {
	InstallationID string                `json:"installation_id"`
	ActiveKeyID    string                `json:"active_key_id"`
	Keys           []encryptionKeyBundle `json:"keys"`
}

// EncryptionIdentity is the agent's dedicated task-parameter decryption ring.
// It is deliberately separate from the ECDSA signing identity.
type EncryptionIdentity struct {
	InstallationID string
	ActiveKeyID    string
	Keys           map[string]*rsa.PrivateKey
	PublicPEM      map[string]string
	path           string
	rotated        bool
}

func encryptionPath() string { return filepath.Join(platform.AgentDir(), "encryption.dpapi") }

// LoadOrCreateEncryptionIdentity loads the RSA ring. A ring belonging to a
// different installation is archived, never silently reused across a
// reinstall. A corrupt ring is an error, not a reason to overwrite keys.
func LoadOrCreateEncryptionIdentity(identity *Identity) (*EncryptionIdentity, error) {
	return loadOrCreateEncryptionIdentity(identity, encryptionPath())
}

func loadOrCreateEncryptionIdentity(identity *Identity, path string) (*EncryptionIdentity, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		if !os.IsNotExist(err) {
			return nil, err
		}
		return generateEncryptionIdentity(identity, path)
	}
	ring, err := readEncryptionBundle(raw, path)
	if err != nil {
		return nil, err
	}
	if ring.InstallationID != identity.InstallationID {
		archive := filepath.Join(filepath.Dir(path), "encryption.previous-"+time.Now().UTC().Format("20060102T150405")+".dpapi")
		if renameErr := os.Rename(path, archive); renameErr != nil {
			return nil, fmt.Errorf("archive encryption ring from another installation: %w", renameErr)
		}
		return generateEncryptionIdentity(identity, path)
	}
	return ring, nil
}

func generateEncryptionIdentity(identity *Identity, path string) (*EncryptionIdentity, error) {
	key, err := protocol.GenerateTaskEncryptionKey()
	if err != nil {
		return nil, err
	}
	publicPEM, err := protocol.MarshalTaskPublicKeyPEM(&key.PublicKey)
	if err != nil {
		return nil, err
	}
	keyID, err := protocol.TaskPublicKeyID(&key.PublicKey)
	if err != nil {
		return nil, err
	}
	ring := &EncryptionIdentity{
		InstallationID: identity.InstallationID, ActiveKeyID: keyID,
		Keys: map[string]*rsa.PrivateKey{keyID: key}, PublicPEM: map[string]string{keyID: publicPEM}, path: path,
	}
	if err := ring.save(); err != nil {
		return nil, err
	}
	return ring, nil
}

func readEncryptionBundle(raw []byte, path string) (*EncryptionIdentity, error) {
	if !bytes.HasPrefix(raw, []byte(encryptionMagic)) {
		return nil, fmt.Errorf("encryption key bundle has an unknown format")
	}
	plain, err := unprotectSecret(raw[len(encryptionMagic):])
	if err != nil {
		return nil, fmt.Errorf("decrypt encryption key bundle: %w", err)
	}
	var bundle encryptionBundle
	if err := json.Unmarshal(plain, &bundle); err != nil {
		return nil, fmt.Errorf("decode encryption key bundle: %w", err)
	}
	if bundle.InstallationID == "" || bundle.ActiveKeyID == "" || len(bundle.Keys) == 0 {
		return nil, fmt.Errorf("encryption key bundle is incomplete")
	}
	ring := &EncryptionIdentity{InstallationID: bundle.InstallationID, ActiveKeyID: bundle.ActiveKeyID,
		Keys: map[string]*rsa.PrivateKey{}, PublicPEM: map[string]string{}, path: path}
	for _, entry := range bundle.Keys {
		der, err := base64.StdEncoding.Strict().DecodeString(entry.PrivatePK8)
		if err != nil {
			return nil, fmt.Errorf("decode encryption private key: %w", err)
		}
		parsed, err := x509.ParsePKCS8PrivateKey(der)
		if err != nil {
			return nil, fmt.Errorf("parse encryption private key: %w", err)
		}
		key, ok := parsed.(*rsa.PrivateKey)
		if !ok || key.N.BitLen() != protocol.RSAEncryptionBits {
			return nil, fmt.Errorf("encryption key is not RSA-3072")
		}
		keyID, err := protocol.TaskPublicKeyID(&key.PublicKey)
		if err != nil || keyID != entry.KeyID {
			return nil, fmt.Errorf("encryption key id does not match the private key")
		}
		publicPEM, err := protocol.MarshalTaskPublicKeyPEM(&key.PublicKey)
		if err != nil || publicPEM != entry.PublicPEM {
			return nil, fmt.Errorf("encryption public key does not match the private key")
		}
		ring.Keys[entry.KeyID] = key
		ring.PublicPEM[entry.KeyID] = publicPEM
	}
	if ring.Keys[bundle.ActiveKeyID] == nil {
		return nil, fmt.Errorf("active encryption key is missing")
	}
	return ring, nil
}

func (e *EncryptionIdentity) save() error {
	bundle := encryptionBundle{InstallationID: e.InstallationID, ActiveKeyID: e.ActiveKeyID}
	ids := make([]string, 0, len(e.Keys))
	for id := range e.Keys {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	existingCreated := time.Now().UTC().Format(time.RFC3339Nano)
	for _, id := range ids {
		der, err := x509.MarshalPKCS8PrivateKey(e.Keys[id])
		if err != nil {
			return err
		}
		bundle.Keys = append(bundle.Keys, encryptionKeyBundle{
			KeyID: id, PublicPEM: e.PublicPEM[id], PrivatePK8: base64.StdEncoding.EncodeToString(der),
			CreatedAt: existingCreated,
		})
	}
	plain, err := json.Marshal(bundle)
	if err != nil {
		return err
	}
	protected, err := protectSecret(plain)
	if err != nil {
		return err
	}
	data := append([]byte(encryptionMagic), protected...)
	if err := writeFileAtomic(e.path, data, 0o600); err != nil {
		return err
	}
	return securePath(e.path)
}

// Rotate creates a new active RSA key and retains older keys so unfinished
// envelopes can still be opened.
func (e *EncryptionIdentity) Rotate() (string, error) {
	key, err := protocol.GenerateTaskEncryptionKey()
	if err != nil {
		return "", err
	}
	publicPEM, err := protocol.MarshalTaskPublicKeyPEM(&key.PublicKey)
	if err != nil {
		return "", err
	}
	keyID, err := protocol.TaskPublicKeyID(&key.PublicKey)
	if err != nil {
		return "", err
	}
	e.Keys[keyID] = key
	e.PublicPEM[keyID] = publicPEM
	e.ActiveKeyID = keyID
	if err := e.save(); err != nil {
		return "", err
	}
	return keyID, nil
}

func (e *EncryptionIdentity) PublicKey() (string, error) {
	if e == nil {
		return "", fmt.Errorf("encryption identity is missing")
	}
	publicPEM, ok := e.PublicPEM[e.ActiveKeyID]
	if !ok {
		return "", fmt.Errorf("active encryption public key is missing")
	}
	return publicPEM, nil
}

func (e *EncryptionIdentity) Key(keyID string) *rsa.PrivateKey {
	if e == nil {
		return nil
	}
	return e.Keys[keyID]
}

func (e *EncryptionIdentity) ActiveID() string {
	if e == nil {
		return ""
	}
	return e.ActiveKeyID
}

// RotateEncryptionKey is the explicit maintenance entry point. The service
// must be restarted after rotation so it registers the new key; old keys stay
// in the DPAPI ring for unfinished envelopes.
func RotateEncryptionKey() (string, error) {
	identity, _, err := LoadOrCreateIdentity()
	if err != nil {
		return "", err
	}
	ring, err := LoadOrCreateEncryptionIdentity(identity)
	if err != nil {
		return "", err
	}
	return ring.Rotate()
}
