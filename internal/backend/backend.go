// Package backend implements the single-process portable backend. The HTTP
// API, SQL storage and migrations are implemented in stages P04/P05.
package backend

import "errors"

// Run starts the backend. It is replaced by the real runtime in P04/P05.
func Run(configPath string) error {
	_ = configPath
	return errors.New("backend runtime is not implemented yet (P04/P05)")
}
