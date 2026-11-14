//go:build !windows

package licensecrypto

import "os"

func checkPrivateFile(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	if info.Mode().Perm()&0o077 != 0 {
		return &permissionError{path: path}
	}
	return nil
}
