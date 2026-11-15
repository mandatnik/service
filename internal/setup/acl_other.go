//go:build !windows

package setup

// WidenRuntimeSecretsACL is a Windows-only operation.
func WidenRuntimeSecretsACL(p Paths, serviceAccount string) error { return nil }
