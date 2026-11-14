package agent

import "os"

// purgeAgentState removes agent-owned state only when the caller explicitly
// requested a purge. Upgrade, repair and ordinary uninstall must keep the
// DPAPI identity so reinstalling the same product does not silently create a
// new machine.
func purgeAgentState(purge bool, dir string) error {
	if !purge {
		return nil
	}
	return os.RemoveAll(dir)
}
