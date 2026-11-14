package agent

import (
	"context"
	"errors"
	"time"

	"telehack2026/internal/protocol"
)

// ErrUnsupportedPlatform is returned by builds without a real collector.
var ErrUnsupportedPlatform = errors.New("agent collector is not supported on this platform")

// Collection is the platform-independent result of one scan. The runtime adds
// identity, report_id and scan_seq when it turns this into a wire report.
type Collection struct {
	StartedAt        time.Time                `json:"started_at"`
	FinishedAt       time.Time                `json:"finished_at"`
	Hostname         string                   `json:"hostname"`
	ProfilesComplete bool                     `json:"profiles_complete"`
	Profiles         []protocol.ProfileResult `json:"profiles"`
	Sources          []protocol.SourceResult  `json:"sources"`
	CSP              protocol.CSPResult       `json:"csp"`
	Errors           []string                 `json:"errors,omitempty"`
}

// Collector reads personal certificate stores and configured folders. A
// collector returns per-source errors inside Collection; a fatal error means
// it could not even start.
type Collector interface {
	Collect(ctx context.Context, cfg protocol.AgentConfig) (Collection, error)
}

// BuildReport converts a collection into the protocol report. The caller
// supplies stable identity fields.
func BuildReport(collection Collection, reportID string, scanSeq int64, agentVersion string) protocol.Report {
	status := "complete"
	if !collection.ProfilesComplete || !collection.CSP.Complete {
		status = "partial"
	}
	for _, source := range collection.Sources {
		if !source.Complete {
			status = "partial"
			break
		}
	}
	return protocol.Report{
		ReportID:         reportID,
		ScanSeq:          scanSeq,
		CollectedAt:      collection.StartedAt.UTC().Format(time.RFC3339Nano),
		StartedAt:        collection.StartedAt.UTC().Format(time.RFC3339Nano),
		FinishedAt:       collection.FinishedAt.UTC().Format(time.RFC3339Nano),
		AgentVersion:     agentVersion,
		Hostname:         collection.Hostname,
		Status:           status,
		ProfilesComplete: collection.ProfilesComplete,
		Profiles:         collection.Profiles,
		Sources:          collection.Sources,
		CSP:              collection.CSP,
		Errors:           collection.Errors,
	}
}
