package agent

import (
	"bytes"
	"crypto/ecdsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"telehack2026/internal/platform"
	"telehack2026/internal/protocol"
)

const identityMagic = "THK1"

// Identity is the agent's transport identity. The private key is never
// written outside the DPAPI-protected bundle.
type Identity struct {
	UUID         string
	Hostname     string
	CreatedAt    time.Time
	PublicKeyPEM string
	Key          *ecdsa.PrivateKey
}

type identityBundle struct {
	UUID            string `json:"uuid"`
	Hostname        string `json:"hostname"`
	CreatedAt       string `json:"created_at"`
	PublicKeyPEM    string `json:"public_key_pem"`
	PrivateKeyPKCS8 string `json:"private_key_pkcs8"`
}

type publicIdentity struct {
	UUID         string `json:"uuid"`
	Hostname     string `json:"hostname"`
	CreatedAt    string `json:"created_at"`
	PublicKeyPEM string `json:"public_key_pem"`
}

// LoadOrCreateIdentity loads the active identity and, if the operating system
// hostname differs, prepares a signed rename transition. It never silently
// replaces an unreadable identity or key.
func LoadOrCreateIdentity() (*Identity, *Identity, error) {
	if err := os.MkdirAll(platform.AgentDir(), 0o755); err != nil {
		return nil, nil, fmt.Errorf("create agent directory: %w", err)
	}
	hostname, err := os.Hostname()
	if err != nil {
		return nil, nil, fmt.Errorf("read hostname: %w", err)
	}
	hostname, err = protocol.NormalizeHostname(hostname)
	if err != nil {
		return nil, nil, fmt.Errorf("normalize hostname: %w", err)
	}
	activePath := platform.AgentIdentityPath()
	pendingPath := platform.AgentPendingRenamePath()
	active, err := readIdentityFile(activePath)
	if err != nil {
		if !os.IsNotExist(err) {
			return nil, nil, fmt.Errorf("load identity: %w", err)
		}
		if _, pendingErr := os.Stat(pendingPath); pendingErr == nil {
			return nil, nil, fmt.Errorf("pending rename exists without an active identity; administrator reset required")
		}
		active, err = newIdentity(hostname)
		if err != nil {
			return nil, nil, err
		}
		if err := saveIdentity(activePath, active); err != nil {
			return nil, nil, err
		}
		if err := writePublicIdentity(active); err != nil {
			return nil, nil, err
		}
		return active, nil, nil
	}
	if active.Hostname == hostname {
		// A matching active hostname makes any leftover transition stale.
		if _, err := os.Stat(pendingPath); err == nil {
			_ = os.Remove(pendingPath)
		}
		_ = writePublicIdentity(active)
		return active, nil, nil
	}
	pending, err := readIdentityFile(pendingPath)
	if err == nil {
		if pending.Hostname == hostname {
			return active, pending, nil
		}
		// The machine was renamed again before the previous transition was
		// delivered. The old target was never confirmed; prepare a new one.
		pending = nil
	} else if !os.IsNotExist(err) {
		return nil, nil, fmt.Errorf("load pending rename: %w", err)
	}
	pending, err = newIdentity(hostname)
	if err != nil {
		return nil, nil, err
	}
	if err := saveIdentity(pendingPath, pending); err != nil {
		return nil, nil, err
	}
	return active, pending, nil
}

func newIdentity(hostname string) (*Identity, error) {
	key, err := protocol.GenerateKey()
	if err != nil {
		return nil, err
	}
	publicPEM, err := protocol.MarshalPublicKeyPEM(&key.PublicKey)
	if err != nil {
		return nil, err
	}
	return &Identity{
		UUID:         protocol.NewUUID(),
		Hostname:     hostname,
		CreatedAt:    time.Now().UTC(),
		PublicKeyPEM: publicPEM,
		Key:          key,
	}, nil
}

func readIdentityFile(path string) (*Identity, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if !bytes.HasPrefix(raw, []byte(identityMagic)) {
		return nil, fmt.Errorf("identity file has an unknown format")
	}
	plain, err := unprotectIdentity(raw[len(identityMagic):])
	if err != nil {
		return nil, err
	}
	var bundle identityBundle
	if err := json.Unmarshal(plain, &bundle); err != nil {
		return nil, fmt.Errorf("decode identity bundle: %w", err)
	}
	privateDER, err := base64.StdEncoding.Strict().DecodeString(bundle.PrivateKeyPKCS8)
	if err != nil {
		return nil, fmt.Errorf("decode private key: %w", err)
	}
	key, err := protocol.ParsePrivateKeyPKCS8(privateDER)
	if err != nil {
		return nil, err
	}
	pub, err := protocol.ParsePublicKeyPEM(bundle.PublicKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("identity public key: %w", err)
	}
	derivedPEM, err := protocol.MarshalPublicKeyPEM(&key.PublicKey)
	if err != nil {
		return nil, err
	}
	if derivedPEM != bundle.PublicKeyPEM {
		return nil, fmt.Errorf("identity public key does not match the private key")
	}
	if pub.X.Cmp(key.PublicKey.X) != 0 || pub.Y.Cmp(key.PublicKey.Y) != 0 {
		return nil, fmt.Errorf("identity public key mismatch")
	}
	if _, err := protocol.NormalizeUUID(bundle.UUID); err != nil {
		return nil, fmt.Errorf("identity UUID: %w", err)
	}
	if _, err := protocol.NormalizeHostname(bundle.Hostname); err != nil {
		return nil, fmt.Errorf("identity hostname: %w", err)
	}
	created, err := time.Parse(time.RFC3339Nano, bundle.CreatedAt)
	if err != nil {
		return nil, fmt.Errorf("identity created_at: %w", err)
	}
	return &Identity{UUID: strings.ToLower(bundle.UUID), Hostname: bundle.Hostname, CreatedAt: created.UTC(), PublicKeyPEM: bundle.PublicKeyPEM, Key: key}, nil
}

func saveIdentity(path string, identity *Identity) error {
	if identity == nil || identity.Key == nil {
		return fmt.Errorf("nil identity")
	}
	privateDER, err := protocol.MarshalPrivateKeyPKCS8(identity.Key)
	if err != nil {
		return err
	}
	bundle := identityBundle{
		UUID:            identity.UUID,
		Hostname:        identity.Hostname,
		CreatedAt:       identity.CreatedAt.UTC().Format(time.RFC3339Nano),
		PublicKeyPEM:    identity.PublicKeyPEM,
		PrivateKeyPKCS8: base64.StdEncoding.EncodeToString(privateDER),
	}
	plain, err := json.Marshal(bundle)
	if err != nil {
		return err
	}
	protected, err := protectIdentity(plain)
	if err != nil {
		return err
	}
	data := append([]byte(identityMagic), protected...)
	if err := writeFileAtomic(path, data, 0o600); err != nil {
		return err
	}
	return securePath(path)
}

func promotePendingIdentity() (*Identity, error) {
	pendingPath := platform.AgentPendingRenamePath()
	identityPath := platform.AgentIdentityPath()
	next, err := readIdentityFile(pendingPath)
	if err != nil {
		return nil, err
	}
	if err := os.Rename(pendingPath, identityPath); err != nil {
		return nil, fmt.Errorf("promote pending identity: %w", err)
	}
	if err := securePath(identityPath); err != nil {
		return nil, err
	}
	if err := writePublicIdentity(next); err != nil {
		return nil, err
	}
	return next, nil
}

func writePublicIdentity(identity *Identity) error {
	summary := publicIdentity{
		UUID:         identity.UUID,
		Hostname:     identity.Hostname,
		CreatedAt:    identity.CreatedAt.UTC().Format(time.RFC3339Nano),
		PublicKeyPEM: identity.PublicKeyPEM,
	}
	raw, err := json.MarshalIndent(summary, "", "  ")
	if err != nil {
		return err
	}
	if err := writeFileAtomic(platform.AgentPublicIdentityPath(), raw, 0o600); err != nil {
		return err
	}
	return securePath(platform.AgentPublicIdentityPath())
}

func readPublicIdentity() (publicIdentity, error) {
	var summary publicIdentity
	raw, err := os.ReadFile(platform.AgentPublicIdentityPath())
	if err != nil {
		return summary, err
	}
	if err := protocol.RejectDuplicateKeys(raw); err != nil {
		return summary, err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&summary); err != nil {
		return summary, err
	}
	return summary, nil
}
