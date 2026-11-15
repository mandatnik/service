package platform

import (
	"os"
	"strings"
)

// Env prefers the current product prefix, including an explicitly empty value.
func Env(name string) string {
	if value, ok := os.LookupEnv(name); ok {
		return value
	}
	return os.Getenv(strings.Replace(name, "MANDATNIK_", "TELEHACK_", 1))
}
