//go:build !windows

package setup

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// Non-Windows builds exist so that the wizard core can be unit-tested on the
// build machine. They store the sealed blob as plain JSON with 0600 and are
// never used for production installs.

func sealCurrentUser(plain []byte) ([]byte, error) { return append([]byte(nil), plain...), nil }

func unsealCurrentUser(blob []byte) ([]byte, error) { return append([]byte(nil), blob...), nil }

func sealMachine(plain []byte) ([]byte, error) { return append([]byte(nil), plain...), nil }

func unsealMachine(blob []byte) ([]byte, error) { return append([]byte(nil), blob...), nil }

func secureFile(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	if info.Mode().Perm()&0o077 != 0 {
		if err := os.Chmod(path, 0o600); err != nil {
			return fmt.Errorf("ограничиваю права на %s: %w", path, err)
		}
	}
	return nil
}

func secureDir(path string) error {
	if err := os.MkdirAll(path, 0o700); err != nil {
		return err
	}
	return os.Chmod(path, 0o700)
}

// WindowsAdministratorsCheck is never true outside Windows; the wizard reports
// the platform restriction explicitly.
var ErrWindowsOnly = errors.New("операция доступна только на Windows")

var _ = filepath.Join
