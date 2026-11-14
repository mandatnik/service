//go:build !windows

package agent

import "fmt"

func runPlatform(configPath string, diagDirs []string) error {
	_ = configPath
	_ = diagDirs
	return fmt.Errorf("%w: the agent service is a Windows-only component", ErrUnsupportedPlatform)
}
