package agent

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"

	"mandatnik/internal/platform"
	"mandatnik/internal/protocol"
)

// State is durable agent scheduling and configuration state. It contains no
// secrets and is written atomically.
type State struct {
	ScanSeq                int64                 `json:"scan_seq"`
	LastScanStartedAt      string                `json:"last_scan_started_at,omitempty"`
	LastScanSuccessAt      string                `json:"last_scan_success_at,omitempty"`
	LastReportID           string                `json:"last_report_id,omitempty"`
	MachineID              string                `json:"machine_id,omitempty"`
	ConfigHash             string                `json:"config_hash,omitempty"`
	Config                 *protocol.AgentConfig `json:"config,omitempty"`
	EncryptionKeyID        string                `json:"encryption_key_id,omitempty"`
	CapabilitiesRegistered bool                  `json:"capabilities_registered,omitempty"`
	UpdatedAt              string                `json:"updated_at"`
}

func loadState() (*State, error) {
	path := platform.AgentStatePath()
	raw, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return &State{}, nil
		}
		return nil, err
	}
	if err := protocol.RejectDuplicateKeys(raw); err != nil {
		return nil, fmt.Errorf("state.json: %w", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var state State
	if err := decoder.Decode(&state); err != nil {
		return nil, fmt.Errorf("decode state.json: %w", err)
	}
	if state.Config != nil {
		if err := protocol.ValidateConfig(state.Config); err != nil {
			return nil, fmt.Errorf("cached configuration: %w", err)
		}
	}
	return &state, nil
}

func (s *State) save() error {
	s.UpdatedAt = time.Now().UTC().Format(time.RFC3339Nano)
	raw, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	if err := writeFileAtomic(platform.AgentStatePath(), raw, 0o600); err != nil {
		return err
	}
	return securePath(platform.AgentStatePath())
}

// EffectiveConfig returns the cached configuration or the agreed defaults.
func (s *State) EffectiveConfig() protocol.AgentConfig {
	if s != nil && s.Config != nil {
		return *s.Config
	}
	return protocol.DefaultAgentConfig()
}

// SetConfig replaces the cached configuration only when the hash changes.
func (s *State) SetConfig(cfg protocol.AgentConfig, hash string) {
	if s.ConfigHash == hash && s.Config != nil {
		return
	}
	s.Config = &cfg
	s.ConfigHash = hash
}

func (s *State) scanDue(now time.Time) bool {
	if s.LastScanSuccessAt == "" {
		return true
	}
	last, err := time.Parse(time.RFC3339Nano, s.LastScanSuccessAt)
	if err != nil {
		return true
	}
	days := s.EffectiveConfig().ScanIntervalDays
	if days < 1 {
		days = protocol.DefaultScanIntervalDays
	}
	return !now.Before(last.Add(time.Duration(days) * 24 * time.Hour))
}

func (s *State) lastScanSuccess() time.Time {
	if s == nil || s.LastScanSuccessAt == "" {
		return time.Time{}
	}
	value, err := time.Parse(time.RFC3339Nano, s.LastScanSuccessAt)
	if err != nil {
		return time.Time{}
	}
	return value
}

// Jobs is the durable local job state, separate from the two-report queue.
type Jobs struct {
	mu   sync.Mutex
	Jobs map[string]JobState `json:"jobs"`
}

// JobState records one manual scan job.
type JobState struct {
	State       string `json:"state"`
	ReportID    string `json:"report_id,omitempty"`
	CompletedAt string `json:"completed_at,omitempty"`
	Message     string `json:"message,omitempty"`
	Evicted     bool   `json:"evicted,omitempty"`
	Acked       bool   `json:"acked,omitempty"`
}

func loadJobs() (*Jobs, error) {
	path := platform.AgentJobsPath()
	raw, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return &Jobs{Jobs: map[string]JobState{}}, nil
		}
		return nil, err
	}
	if err := protocol.RejectDuplicateKeys(raw); err != nil {
		return nil, fmt.Errorf("jobs.json: %w", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var jobs Jobs
	if err := decoder.Decode(&jobs); err != nil {
		return nil, fmt.Errorf("decode jobs.json: %w", err)
	}
	if jobs.Jobs == nil {
		jobs.Jobs = map[string]JobState{}
	}
	return &jobs, nil
}

func (j *Jobs) save() error {
	j.mu.Lock()
	defer j.mu.Unlock()
	raw, err := json.MarshalIndent(j, "", "  ")
	if err != nil {
		return err
	}
	if err := writeFileAtomic(platform.AgentJobsPath(), raw, 0o600); err != nil {
		return err
	}
	return securePath(platform.AgentJobsPath())
}

func (j *Jobs) merge(serverJobs []protocol.Job) bool {
	j.mu.Lock()
	defer j.mu.Unlock()
	changed := false
	for _, job := range serverJobs {
		id := job.JobID
		if existing, ok := j.Jobs[id]; ok {
			if existing.Acked {
				continue
			}
			if existing.State == "" {
				existing.State = "pending"
				j.Jobs[id] = existing
				changed = true
			}
			continue
		}
		j.Jobs[id] = JobState{State: "pending"}
		changed = true
	}
	return changed
}

func (j *Jobs) pendingIDs() []string {
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.pendingIDsLocked()
}

func (j *Jobs) pendingIDsLocked() []string {
	var ids []string
	for id, state := range j.Jobs {
		if state.State == "pending" {
			ids = append(ids, id)
		}
	}
	return ids
}

func (j *Jobs) hasPending() bool {
	j.mu.Lock()
	defer j.mu.Unlock()
	return len(j.pendingIDsLocked()) > 0
}

func (j *Jobs) markCompleted(reportID string, jobIDs []string) bool {
	j.mu.Lock()
	defer j.mu.Unlock()
	changed := false
	now := time.Now().UTC().Format(time.RFC3339Nano)
	for _, id := range jobIDs {
		state, ok := j.Jobs[id]
		if !ok {
			continue
		}
		if state.State == "pending" {
			state.State = "completed"
			state.ReportID = reportID
			state.CompletedAt = now
			j.Jobs[id] = state
			changed = true
		}
	}
	return changed
}

func (j *Jobs) markReportEvicted(reportID string) bool {
	j.mu.Lock()
	defer j.mu.Unlock()
	changed := false
	for id, state := range j.Jobs {
		if state.ReportID == reportID && !state.Acked {
			state.Evicted = true
			state.Message = "report was evicted from the two-item queue before delivery"
			j.Jobs[id] = state
			changed = true
		}
	}
	return changed
}

func (j *Jobs) markAcked(jobID string) bool {
	j.mu.Lock()
	defer j.mu.Unlock()
	state, ok := j.Jobs[jobID]
	if !ok || state.Acked {
		return false
	}
	state.Acked = true
	j.Jobs[jobID] = state
	return true
}

func (j *Jobs) markFailed(jobIDs []string, message string) bool {
	j.mu.Lock()
	defer j.mu.Unlock()
	changed := false
	now := time.Now().UTC().Format(time.RFC3339Nano)
	for _, id := range jobIDs {
		state, ok := j.Jobs[id]
		if !ok || state.State != "pending" {
			continue
		}
		state.State = "failed"
		state.Message = message
		state.CompletedAt = now
		j.Jobs[id] = state
		changed = true
	}
	return changed
}

type jobAck struct {
	JobID    string
	Status   string
	ReportID string
	Message  string
}

func (j *Jobs) pendingAcks() []jobAck {
	j.mu.Lock()
	defer j.mu.Unlock()
	var acks []jobAck
	for id, state := range j.Jobs {
		if state.Acked || (state.State != "completed" && state.State != "failed") {
			continue
		}
		status := state.State
		reportID := state.ReportID
		if state.Evicted {
			status = "report_evicted"
			// The server may never have received the evicted report; do not
			// reference a report_id that does not exist there.
			reportID = ""
		}
		acks = append(acks, jobAck{JobID: id, Status: status, ReportID: reportID, Message: state.Message})
	}
	return acks
}
