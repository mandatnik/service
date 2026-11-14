package agent

// Secret protection is a variable solely to allow deterministic unit tests on
// non-Windows hosts. Production always uses DPAPI on Windows; other platforms
// fail closed and never write plaintext secrets.
var (
	protectSecret   = protectIdentity
	unprotectSecret = unprotectIdentity
)
