// Exported helpers used by the cmd layer and the Windows ACL plumbing.
package setup

import (
	"encoding/base64"
	"encoding/pem"
	"os"
	"path/filepath"
)

// SecurePath applies the protected DACL/permissions to a file.
func SecurePath(path string) error { return secureFile(path) }

// SecureDir applies the protected DACL/permissions to a directory.
func SecureDir(path string) error { return secureDir(path) }

// MarshalKeyPEM encodes a parsed private key as PEM.
func MarshalKeyPEM(key any) []byte { return marshalKey(key) }

// EncodePEM encodes DER bytes as a PEM block.
func EncodePEM(blockType string, der []byte) string {
	return string(pem.EncodeToMemory(&pem.Block{Type: blockType, Bytes: der}))
}

// WriteRuntimePassword stores the DB password in the machine-protected file
// referenced by backend.json (db.password_file). On Windows the content is
// sealed with machine-scope DPAPI; the config reader detects the header.
func WriteRuntimePassword(path string, password []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	sealed, err := sealMachine(password)
	if err != nil {
		return err
	}
	payload := MachineDPAPIHeader + " " + base64.StdEncoding.EncodeToString(sealed) + "\n"
	if err := os.WriteFile(path, []byte(payload), 0o600); err != nil {
		return err
	}
	if err := secureFile(path); err != nil {
		return err
	}
	return secureDir(filepath.Dir(path))
}

// MachineDPAPIHeader marks a DPAPI-sealed runtime password file.
const MachineDPAPIHeader = "MNDKDPAPI1\x1e"

// RuntimePasswordUnsealer decrypts machine-sealed password files. It lives in
// the platform helpers on Windows; off Windows the header never appears.
func RuntimePasswordUnseal(raw []byte) ([]byte, error) {
	return unsealMachine(raw)
}

// ServiceNameText is the backend SCM service name (portable constant).
const ServiceNameText = "MandatnikBackend"
