//go:build !windows

package agent

import "fmt"

func protectIdentity([]byte) ([]byte, error) {
	return nil, fmt.Errorf("%w: DPAPI identity is Windows-only", ErrUnsupportedPlatform)
}

func unprotectIdentity([]byte) ([]byte, error) {
	return nil, fmt.Errorf("%w: DPAPI identity is Windows-only", ErrUnsupportedPlatform)
}

func securePath(string) error { return nil }
