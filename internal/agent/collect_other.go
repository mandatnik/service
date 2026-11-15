//go:build !windows

package agent

import (
	"context"

	"mandatnik/internal/protocol"
)

type unsupportedCollector struct{}

func (unsupportedCollector) Collect(context.Context, protocol.AgentConfig) (Collection, error) {
	return Collection{}, ErrUnsupportedPlatform
}

// NewCollector returns an explicit unsupported-platform collector. It is not a
// mock implementation and is never presented as Windows support.
func NewCollector(_ *Logger) Collector {
	return unsupportedCollector{}
}
