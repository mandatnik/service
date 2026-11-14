//go:build !windows

package licensecrypto

import "os"

func securePrivateFile(path string) error {
	return os.Chmod(path, 0o600)
}
