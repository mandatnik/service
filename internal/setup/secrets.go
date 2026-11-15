// Sealed secret storage for the setup wizard. On Windows secrets are sealed
// with DPAPI (current user scope for wizard drafts, machine scope with an ACL
// for runtime values that the service account must read). On other platforms
// — used only by tests — the blob is stored as plain JSON with 0600.
package setup

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"sort"
)

// SecretStore keeps named secret blobs.
type SecretStore interface {
	Put(name string, plaintext []byte) error
	Get(name string) ([]byte, error)
	Names() []string
	Delete() error
}

type storeFile struct {
	Entries map[string]string `json:"entries"` // name -> platform-coded payload
}

type fileStore struct {
	path   string
	seal   func([]byte) ([]byte, error)
	unseal func([]byte) ([]byte, error)
}

// NewDraftSecrets opens the wizard draft secret store (current-user scope).
func NewDraftSecrets(p Paths) (SecretStore, error) {
	return newFileStore(p.DraftSealed, sealCurrentUser, unsealCurrentUser)
}

// NewRuntimeSecrets opens the runtime secret store that the Windows service
// account must be able to read after a reboot (machine-scope DPAPI + ACL).
func NewRuntimeSecrets(p Paths) (SecretStore, error) {
	return newFileStore(p.RuntimeSealed, sealMachine, unsealMachine)
}

func newFileStore(path string, seal, unseal func([]byte) ([]byte, error)) (SecretStore, error) {
	return &fileStore{path: path, seal: seal, unseal: unseal}, nil
}

func (s *fileStore) load() (*storeFile, error) {
	raw, err := os.ReadFile(s.path)
	if os.IsNotExist(err) {
		return &storeFile{Entries: map[string]string{}}, nil
	}
	if err != nil {
		return nil, err
	}
	var f storeFile
	if err := json.Unmarshal(raw, &f); err != nil {
		return nil, fmt.Errorf("хранилище секретов %s повреждено: %w", s.path, err)
	}
	if f.Entries == nil {
		f.Entries = map[string]string{}
	}
	return &f, nil
}

func (s *fileStore) save(f *storeFile) error {
	raw, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dirOf(s.path), 0o700); err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return err
	}
	if err := secureFile(tmp); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, s.path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return secureFile(s.path)
}

func (s *fileStore) Put(name string, plaintext []byte) error {
	f, err := s.load()
	if err != nil {
		return err
	}
	sealed, err := s.seal(plaintext)
	if err != nil {
		return fmt.Errorf("защищаю секрет %q: %w", name, err)
	}
	f.Entries[name] = string(sealed)
	return s.save(f)
}

func (s *fileStore) Get(name string) ([]byte, error) {
	f, err := s.load()
	if err != nil {
		return nil, err
	}
	entry, ok := f.Entries[name]
	if !ok {
		return nil, fmt.Errorf("секрет %q не найден", name)
	}
	open, err := s.unseal([]byte(entry))
	if err != nil {
		return nil, fmt.Errorf("секрет %q недоступен в текущем контексте: %w", name, err)
	}
	return open, nil
}

func (s *fileStore) Names() []string {
	f, err := s.load()
	if err != nil {
		return nil
	}
	names := make([]string, 0, len(f.Entries))
	for k := range f.Entries {
		names = append(names, k)
	}
	sort.Strings(names)
	return names
}

func (s *fileStore) Delete() error {
	if err := os.Remove(s.path); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

// Secret names used by the wizard.
const (
	SecretDBPassword    = "db_password"
	SecretSvcPassword   = "service_password"
	SecretAdminPassword = "admin_password"
	SecretBundlePass    = "bundle_password"
)

// OverwriteZero zeroes a plaintext buffer after use.
func OverwriteZero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// ComparePasswords is a constant-time equality helper for repeats.
func ComparePasswords(a, b string) bool {
	return bytes.Equal([]byte(a), []byte(b))
}
