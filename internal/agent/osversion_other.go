//go:build !windows

package agent

import "runtime"

func agentOSVersion() string { return runtime.GOOS }
