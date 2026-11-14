package agent

import (
	"context"
	"fmt"
	"os"
	"runtime/debug"
	"time"

	"telehack2026/internal/platform"
	"telehack2026/internal/protocol"
	"telehack2026/internal/version"
)

// agentRuntime is the normal Windows service loop. It owns the outbound
// client, DPAPI identity, schedule, durable queue and job acknowledgements.
type agentRuntime struct {
	configPath string
	logger     *Logger
	collector  Collector
	fileConfig FileConfig
	client     *APIClient
	identity   *Identity
	pending    *Identity
	state      *State
	jobs       *Jobs
	queue      *Queue

	registered          bool
	lastRegisterAttempt time.Time
	lastSync            time.Time
	lastScanAttempt     time.Time
	lastDeliveryAttempt time.Time
}

func runAgentRuntime(ctx context.Context, configPath string) error {
	runtime, err := newAgentRuntime(configPath)
	if err != nil {
		return err
	}
	defer runtime.logger.Close()
	return runtime.Run(ctx)
}

func newAgentRuntime(configPath string) (*agentRuntime, error) {
	if err := os.MkdirAll(platform.AgentDir(), 0o755); err != nil {
		return nil, fmt.Errorf("create agent state directory: %w", err)
	}
	logger, err := OpenLogger(platform.AgentLogDir())
	if err != nil {
		return nil, err
	}
	secureAgentState(logger)
	fileConfig, err := LoadFileConfig(configPath)
	if err != nil {
		logger.Logf("agent configuration failed: %v", err)
		logger.Close()
		return nil, err
	}
	identity, pending, err := LoadOrCreateIdentity()
	if err != nil {
		logger.Logf("identity initialization failed: %v", err)
		logger.Close()
		return nil, err
	}
	acceptedMarker := platform.AgentPendingRenameAcceptedPath()
	if pending != nil {
		if _, markerErr := os.Stat(acceptedMarker); markerErr == nil {
			next, promoteErr := promotePendingIdentity()
			if promoteErr == nil {
				identity = next
				pending = nil
				_ = os.Remove(acceptedMarker)
				logger.Logf("completed previously accepted identity transition: uuid=%s hostname=%s", next.UUID, next.Hostname)
			} else {
				logger.Logf("accepted pending identity could not be promoted: %v", promoteErr)
			}
		}
	} else {
		_ = os.Remove(acceptedMarker)
	}
	state, err := loadState()
	if err != nil {
		logger.Logf("state load failed: %v", err)
		logger.Close()
		return nil, err
	}
	jobs, err := loadJobs()
	if err != nil {
		logger.Logf("job state load failed, starting with empty job state: %v", err)
		jobs = &Jobs{Jobs: map[string]JobState{}}
	}
	queue, err := openQueue(logger)
	if err != nil {
		logger.Logf("queue open failed: %v", err)
		logger.Close()
		return nil, err
	}
	evicted, err := queue.trim()
	if err != nil {
		logger.Logf("queue trim failed: %v", err)
		logger.Close()
		return nil, err
	}
	if len(evicted) > 0 {
		for _, reportID := range evicted {
			jobs.markReportEvicted(reportID)
		}
		if err := jobs.save(); err != nil {
			logger.Logf("save job state after queue trim: %v", err)
		}
	}
	runtime := &agentRuntime{
		configPath: configPath,
		logger:     logger,
		collector:  NewCollector(logger),
		fileConfig: fileConfig,
		client:     newAPIClient(fileConfig.ServerURL, time.Duration(fileConfig.RequestTimeoutSeconds)*time.Second),
		identity:   identity,
		pending:    pending,
		state:      state,
		jobs:       jobs,
		queue:      queue,
	}
	logger.Logf("agent runtime starting: %s", version.String())
	if system, err := currentSystemIdentity(); err == nil {
		logger.Logf("service identity: user=%s sid=%s session=%d os=%q host=%s", system.User, system.SID, system.SessionID, system.OSVersion, system.Hostname)
	}
	logger.Logf("identity uuid=%s hostname=%s pending_rename=%t", identity.UUID, identity.Hostname, pending != nil)
	logger.Logf("queue items=%d scan_seq=%d config_hash=%s", queue.Count(), state.ScanSeq, state.ConfigHash)
	return runtime, nil
}

func (r *agentRuntime) Run(ctx context.Context) error {
	r.logger.Logf("agent cycle started")
	r.ensureRegistered(ctx)
	r.syncNow(ctx)
	r.work(ctx)
	pollTicker := time.NewTicker(protocol.AgentPollInterval)
	defer pollTicker.Stop()
	workTicker := time.NewTicker(30 * time.Second)
	defer workTicker.Stop()
	for {
		select {
		case <-ctx.Done():
			r.logger.Logf("agent cycle stopping")
			return nil
		case <-pollTicker.C:
			r.reloadFileConfig()
			r.ensureRegistered(ctx)
			r.syncNow(ctx)
		case <-workTicker.C:
			r.work(ctx)
		}
	}
}

func (r *agentRuntime) work(ctx context.Context) {
	defer func() {
		if recovered := recover(); recovered != nil {
			r.logger.Logf("panic in agent work loop: %v\n%s", recovered, debug.Stack())
		}
	}()
	r.refreshPending()
	if r.pending != nil && r.queue.Count() == 0 {
		if r.attemptRename(ctx) {
			r.registered = true
		}
	}
	if !r.registered {
		if !r.ensureRegistered(ctx) {
			// Local collection still runs; queued reports wait for registration.
		}
	}
	if r.registered {
		if r.lastSync.IsZero() || time.Since(r.lastSync) >= protocol.AgentPollInterval {
			r.syncNow(ctx)
		}
		r.deliverOnce(ctx)
		r.sendAcks(ctx)
	}
	now := time.Now().UTC()
	if r.scanWanted(now) {
		r.scanNow(ctx)
	}
}

func (r *agentRuntime) scanWanted(now time.Time) bool {
	if r.lastScanAttempt.IsZero() || now.Sub(r.lastScanAttempt) >= 10*time.Minute {
		if r.jobs.hasPending() {
			return true
		}
		if r.lastScanAttempt.IsZero() {
			return r.state.scanDue(now)
		}
		return r.state.scanDue(now)
	}
	return false
}

func (r *agentRuntime) ensureRegistered(ctx context.Context) bool {
	if r.registered {
		return true
	}
	if !r.lastRegisterAttempt.IsZero() && time.Since(r.lastRegisterAttempt) < time.Minute {
		return false
	}
	r.lastRegisterAttempt = time.Now()
	response, result := r.client.register(ctx, r.identity, agentOSVersion())
	if result.Error != nil {
		r.logger.Logf("registration failed: status=%d code=%s message=%s", result.Status, result.Error.Code, result.Error.Message)
		return false
	}
	r.registered = true
	r.state.MachineID = response.MachineID
	if response.ConfigHash != "" {
		r.state.SetConfig(response.Config, response.ConfigHash)
	}
	if err := r.state.save(); err != nil {
		r.logger.Logf("save state after registration: %v", err)
	}
	secureAgentState(r.logger)
	r.logger.Logf("registration ok: machine_id=%s uuid=%s hostname=%s warnings=%v", response.MachineID, response.UUID, response.Hostname, response.Warnings)
	return true
}

func (r *agentRuntime) syncNow(ctx context.Context) {
	if !r.registered {
		return
	}
	r.lastSync = time.Now()
	response, result := r.client.sync(ctx, r.identity, r.state.ConfigHash, agentOSVersion())
	if result.Error != nil {
		r.logger.Logf("sync failed: status=%d code=%s message=%s", result.Status, result.Error.Code, result.Error.Message)
		if result.Error.Code == protocol.CodeUnknownIdentity || result.Error.Code == protocol.CodeIdentityRevoked {
			r.registered = false
		}
		return
	}
	changed := false
	if response.Config != nil {
		r.state.SetConfig(*response.Config, response.ConfigHash)
		changed = true
	} else if response.ConfigHash != "" && response.ConfigHash != r.state.ConfigHash {
		r.logger.Logf("server config_hash changed without a config body: local=%s remote=%s", r.state.ConfigHash, response.ConfigHash)
	}
	if r.jobs.merge(response.Jobs) {
		if err := r.jobs.save(); err != nil {
			r.logger.Logf("save jobs after sync: %v", err)
		}
	}
	if changed {
		if err := r.state.save(); err != nil {
			r.logger.Logf("save state after config sync: %v", err)
		}
		secureAgentState(r.logger)
	}
	if len(response.Warnings) > 0 {
		r.logger.Logf("sync warnings: %v", response.Warnings)
	}
	r.logger.Logf("sync ok: config_hash=%s config_received=%t jobs=%d", response.ConfigHash, response.Config != nil, len(response.Jobs))
}

func (r *agentRuntime) refreshPending() {
	current, err := os.Hostname()
	if err != nil {
		r.logger.Logf("read hostname: %v", err)
		return
	}
	current, err = protocol.NormalizeHostname(current)
	if err != nil {
		r.logger.Logf("normalize current hostname: %v", err)
		return
	}
	if current == r.identity.Hostname {
		if r.pending != nil {
			_ = os.Remove(platform.AgentPendingRenamePath())
			r.pending = nil
			r.logger.Logf("discarded stale pending rename; hostname matches active identity")
		}
		return
	}
	if r.pending != nil && r.pending.Hostname == current {
		return
	}
	pending, err := newIdentity(current)
	if err != nil {
		r.logger.Logf("prepare rename identity: %v", err)
		return
	}
	if err := saveIdentity(platform.AgentPendingRenamePath(), pending); err != nil {
		r.logger.Logf("save pending rename: %v", err)
		return
	}
	r.pending = pending
	r.logger.Logf("hostname changed from %s to %s; prepared signed rename uuid=%s", r.identity.Hostname, current, pending.UUID)
}

func (r *agentRuntime) attemptRename(ctx context.Context) bool {
	if r.pending == nil {
		return false
	}
	r.logger.Logf("attempting signed rename %s -> %s", r.identity.UUID, r.pending.UUID)
	response, result := r.client.rename(ctx, r.identity, r.pending, agentOSVersion())
	if result.Error != nil {
		r.logger.Logf("rename failed: status=%d code=%s message=%s", result.Status, result.Error.Code, result.Error.Message)
		return false
	}
	if err := writeFileAtomic(platform.AgentPendingRenameAcceptedPath(), []byte("accepted\n"), 0o600); err != nil {
		r.logger.Logf("write rename accepted marker: %v", err)
	}
	next, err := promotePendingIdentity()
	if err != nil {
		r.logger.Logf("promote pending identity (accepted marker retained for retry): %v", err)
		return false
	}
	_ = os.Remove(platform.AgentPendingRenameAcceptedPath())
	r.identity = next
	r.pending = nil
	r.state.MachineID = response.MachineID
	if response.ConfigHash != "" {
		r.state.SetConfig(response.Config, response.ConfigHash)
	}
	if err := r.state.save(); err != nil {
		r.logger.Logf("save state after rename: %v", err)
	}
	secureAgentState(r.logger)
	r.logger.Logf("rename committed: machine_id=%s uuid=%s hostname=%s warnings=%v", response.MachineID, response.UUID, response.Hostname, response.Warnings)
	return true
}

func (r *agentRuntime) deliverOnce(ctx context.Context) {
	items, err := r.queue.Items()
	if err != nil {
		r.logger.Logf("read queue: %v", err)
		return
	}
	if len(items) == 0 {
		return
	}
	if !r.lastDeliveryAttempt.IsZero() && time.Since(r.lastDeliveryAttempt) < 10*time.Second {
		return
	}
	r.lastDeliveryAttempt = time.Now()
	item := items[0]
	r.logger.Logf("delivering report %s scan_seq=%d", item.ReportID, item.ScanSeq)
	response, result := r.client.report(ctx, r.identity, item, agentOSVersion())
	if result.Error != nil {
		switch result.Error.Code {
		case protocol.CodeReportConflict, protocol.CodeReportInvalid, protocol.CodePayloadTooLarge:
			r.logger.Logf("report %s rejected permanently: %s", item.ReportID, result.Error.Message)
			if r.jobs.markFailed(item.JobIDs, "report rejected: "+result.Error.Message) {
				_ = r.jobs.save()
			}
			if err := r.queue.Remove(item.ReportID); err != nil {
				r.logger.Logf("remove rejected report: %v", err)
			}
		case protocol.CodeUnknownIdentity, protocol.CodeIdentityRevoked:
			r.logger.Logf("report %s deferred: identity is not active: %s", item.ReportID, result.Error.Message)
			r.registered = false
		case "network_error":
			r.logger.Logf("report %s deferred: network error: %s", item.ReportID, result.Error.Message)
		default:
			r.logger.Logf("report %s deferred: status=%d code=%s message=%s", item.ReportID, result.Status, result.Error.Code, result.Error.Message)
		}
		return
	}
	if err := r.queue.Remove(item.ReportID); err != nil {
		r.logger.Logf("remove delivered report: %v", err)
		return
	}
	r.logger.Logf("report %s accepted duplicate=%t applied=%t", item.ReportID, response.Duplicate, response.Applied)
}

func (r *agentRuntime) sendAcks(ctx context.Context) {
	for _, ack := range r.jobs.pendingAcks() {
		_, result := r.client.ack(ctx, r.identity, ack, agentOSVersion())
		if result.Error != nil {
			switch result.Error.Code {
			case protocol.CodeJobConflict, protocol.CodeNotFound:
				r.logger.Logf("job %s ack resolved by server: %s", ack.JobID, result.Error.Message)
				if r.jobs.markAcked(ack.JobID) {
					_ = r.jobs.save()
				}
			case "network_error":
				return
			default:
				r.logger.Logf("job %s ack deferred: status=%d code=%s", ack.JobID, result.Status, result.Error.Code)
			}
			continue
		}
		if r.jobs.markAcked(ack.JobID) {
			_ = r.jobs.save()
		}
		r.logger.Logf("job %s acknowledged as %s", ack.JobID, ack.Status)
	}
}

func (r *agentRuntime) scanNow(ctx context.Context) {
	r.lastScanAttempt = time.Now().UTC()
	seq := r.state.ScanSeq + 1
	r.state.ScanSeq = seq
	r.state.LastScanStartedAt = time.Now().UTC().Format(time.RFC3339Nano)
	if err := r.state.save(); err != nil {
		r.logger.Logf("save scan start state: %v", err)
	}
	cfg := r.state.EffectiveConfig()
	started := time.Now()
	collection, err := r.collector.Collect(ctx, cfg)
	if err != nil {
		r.logger.Logf("collection failed: %v", err)
		return
	}
	if ctx.Err() != nil {
		r.logger.Logf("collection canceled by service stop; report not queued")
		return
	}
	report := BuildReport(collection, protocol.NewUUID(), seq, version.Version)
	report.Hostname = r.identity.Hostname
	scanComplete := report.Status == "complete"
	jobIDs := r.jobs.pendingIDs()
	item := QueueItem{
		ReportID:    report.ReportID,
		ScanSeq:     seq,
		CollectedAt: report.CollectedAt,
		QueuedAt:    time.Now().UTC().Format(time.RFC3339Nano),
		JobIDs:      jobIDs,
		Report:      report,
	}
	if apiErr := protocol.ValidateReport(&report); apiErr != nil {
		r.logger.Logf("generated report is invalid: %s: %s", apiErr.Code, apiErr.Message)
		if r.jobs.markFailed(jobIDs, "generated report invalid: "+apiErr.Message) {
			_ = r.jobs.save()
		}
		return
	}
	evicted, err := r.queue.Add(item)
	if err != nil {
		r.logger.Logf("queue report: %v", err)
		return
	}
	for _, reportID := range evicted {
		if r.jobs.markReportEvicted(reportID) {
			_ = r.jobs.save()
		}
	}
	if r.jobs.markCompleted(report.ReportID, jobIDs) {
		_ = r.jobs.save()
	}
	r.state.LastScanSuccessAt = report.FinishedAt
	r.state.LastReportID = report.ReportID
	if err := r.state.save(); err != nil {
		r.logger.Logf("save scan success state: %v", err)
	}
	secureAgentState(r.logger)
	certCount := 0
	for _, source := range collection.Sources {
		certCount += len(source.Certificates)
	}
	r.logger.Logf("collection finished in %s: scan_seq=%d status=%s complete=%t profiles=%d sources=%d certificates=%d csp_present=%t csp_complete=%t job_count=%d errors=%d",
		time.Since(started).Round(time.Millisecond), seq, report.Status, scanComplete, len(collection.Profiles), len(collection.Sources), certCount, collection.CSP.Present, collection.CSP.Complete, len(jobIDs), len(collection.Errors))
	for _, message := range collection.Errors {
		r.logger.Logf("collection error: %s", message)
	}
}

func (r *agentRuntime) reloadFileConfig() {
	cfg, err := LoadFileConfig(r.configPath)
	if err != nil {
		r.logger.Logf("reload agent configuration: %v", err)
		return
	}
	if cfg.ServerURL != r.fileConfig.ServerURL || cfg.RequestTimeoutSeconds != r.fileConfig.RequestTimeoutSeconds {
		r.fileConfig = cfg
		r.client = newAPIClient(cfg.ServerURL, time.Duration(cfg.RequestTimeoutSeconds)*time.Second)
		r.registered = false
		r.lastSync = time.Time{}
		r.logger.Logf("agent bootstrap configuration reloaded: server=%s timeout=%ds", cfg.ServerURL, cfg.RequestTimeoutSeconds)
	}
}
