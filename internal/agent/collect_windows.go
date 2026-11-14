//go:build windows

package agent

import (
	"context"
	"fmt"
	"os"
	"sort"
	"time"

	"telehack2026/internal/agent/winapi"
	"telehack2026/internal/protocol"
)

// NewCollector returns the Windows collector.
func NewCollector(logger *Logger) Collector {
	return &windowsCollector{logger: logger}
}

type windowsCollector struct{ logger *Logger }

func (c *windowsCollector) Collect(ctx context.Context, cfg protocol.AgentConfig) (Collection, error) {
	started := time.Now().UTC()
	hostname, _ := os.Hostname()
	collection := Collection{
		StartedAt:        started,
		Hostname:         hostname,
		ProfilesComplete: true,
		Profiles:         []protocol.ProfileResult{},
		Sources:          []protocol.SourceResult{},
	}
	if err := winapi.EnableBackupRestorePrivileges(); err != nil {
		collection.Errors = append(collection.Errors, "privileges: "+boundError(err.Error()))
	}

	profiles, err := winapi.EnumerateProfiles()
	if err != nil {
		collection.ProfilesComplete = false
		collection.Errors = append(collection.Errors, "profile enumeration: "+boundError(err.Error()))
	}
	for _, profile := range profiles {
		if ctx.Err() != nil {
			collection.ProfilesComplete = false
			collection.Errors = append(collection.Errors, "scan canceled during profile collection")
			break
		}
		profileResult := protocol.ProfileResult{
			SID:         profile.SID,
			Name:        profile.Name,
			ProfilePath: profile.Path,
			Loaded:      profile.Loaded,
			Complete:    true,
		}
		source := protocol.SourceResult{
			SourceType:   "user_store",
			SourceKey:    profile.SID,
			DisplayName:  profile.Name,
			UserSID:      profile.SID,
			Complete:     true,
			Certificates: []protocol.ObservedCertificate{},
		}
		present, records, readErr := winapi.ReadUserStore(profile)
		if readErr != nil {
			profileResult.Complete = false
			profileResult.Error = boundError(readErr.Error())
			source.Complete = false
			source.Error = boundError(readErr.Error())
			collection.Errors = append(collection.Errors, fmt.Sprintf("%s: %s", profile.SID, boundError(readErr.Error())))
		} else {
			profileResult.StorePresent = present
			for _, record := range records {
				observation, observationErr := observeDER(record.DER)
				observation.ProviderBindings = record.Bindings
				if observationErr != nil {
					profileResult.Complete = false
					source.Complete = false
					source.Error = boundError("certificate field parsing failed: " + observationErr.Error())
					collection.Errors = append(collection.Errors, fmt.Sprintf("%s: certificate parse failed", profile.SID))
				}
				source.Certificates = append(source.Certificates, observation)
			}
			sort.Slice(source.Certificates, func(i, j int) bool {
				return source.Certificates[i].SHA256 < source.Certificates[j].SHA256
			})
		}
		collection.Profiles = append(collection.Profiles, profileResult)
		collection.Sources = append(collection.Sources, source)
	}

	folderSources := ScanFolders(ctx, cfg, c.logger)
	collection.Sources = append(collection.Sources, folderSources...)

	if ctx.Err() == nil {
		collection.CSP = winapi.CollectCSP()
	} else {
		collection.CSP = protocol.CSPResult{
			Scanned:  false,
			Complete: false,
			Present:  false,
			License: protocol.LicenseInfo{
				Kind: "unknown", State: "unknown", TermKind: "unknown", IsTrial: "unknown",
			},
			Error: "scan canceled",
		}
	}
	collection.FinishedAt = time.Now().UTC()
	if len(collection.Errors) > 100 {
		collection.Errors = collection.Errors[:100]
	}
	return collection, nil
}
