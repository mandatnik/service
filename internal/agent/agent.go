// Package agent implements the Windows service runtime. The full service,
// collector and delivery loop are implemented in stages P02/P03/P06.
package agent

import "errors"

// Run starts the agent. It is replaced by the real service runtime in P02/P06.
func Run(configPath string) error {
	_ = configPath
	return errors.New("agent runtime is not implemented yet (P02/P06)")
}
