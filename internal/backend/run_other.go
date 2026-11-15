//go:build !windows

package backend

// RunPlatform is the plain console run path off Windows.
func RunPlatform(configPath string) error { return Run(configPath) }
