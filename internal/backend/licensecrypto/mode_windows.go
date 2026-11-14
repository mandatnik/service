//go:build windows

package licensecrypto

// Windows ACLs are enforced by deployment policy (backend service account and
// Administrators). POSIX mode bits are not a meaningful substitute there.
func checkPrivateFile(string) error { return nil }
