//go:build !windows

package agent

import "fmt"

func currentSystemIdentity() (SystemIdentity, error) {
	return SystemIdentity{}, fmt.Errorf("%w: Windows identity is unavailable", ErrUnsupportedPlatform)
}

func secureState(string) error { return nil }
