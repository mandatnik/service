//go:build !windows

package agent

import "fmt"

func runPlatform(configPath string) error {
	_ = configPath
	return fmt.Errorf("%w: the agent service is a Windows-only component", ErrUnsupportedPlatform)
}
