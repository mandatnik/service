package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"strings"
	"time"

	"telehack2026/internal/backend/db"
	"telehack2026/internal/backend/store"
	"telehack2026/internal/protocol"
)

type contract struct {
	client     *client
	store      *store.Store
	pool       *sql.DB
	ev         *evidence
	fixtures   fixtures
	prefix     string
	uuids      []string
	machineIDs []string
}

func runContract(ctx context.Context, cfg acceptanceConfig) error {
	client, err := newClient(cfg.ServerURL, cfg.CAFile, 60*time.Second)
	if err != nil {
		return err
	}
	pool, err := db.Open(ctx, cfg.DB)
	if err != nil {
		return err
	}
	defer pool.Close()
	fixtures, err := loadFixtures()
	if err != nil {
		return err
	}
	suffix := make([]byte, 4)
	if _, err := rand.Read(suffix); err != nil {
		return err
	}
	c := &contract{
		client: client, store: store.New(pool), pool: pool,
		ev: newEvidence(cfg.ServerURL), fixtures: fixtures,
		prefix: "ACCEPT-" + strings.ToUpper(hex.EncodeToString(suffix)),
	}
	runErr := c.run(ctx)
	cleanupErr := c.cleanup(ctx)
	if cleanupErr != nil {
		c.ev.add("cleanup synthetic records", false, nil, cleanupErr)
	} else if runErr == nil {
		c.ev.add("cleanup synthetic records", true, nil, nil)
	}
	path, writeErr := c.ev.write(cfg.EvidenceDir)
	if writeErr != nil {
		return writeErr
	}
	fmt.Println("evidence:", path)
	if runErr != nil {
		return runErr
	}
	if c.ev.failed() > 0 {
		return fmt.Errorf("%d acceptance checks failed", c.ev.failed())
	}
	return cleanupErr
}

func (c *contract) track(id *identity) {
	c.uuids = append(c.uuids, id.UUID)
	if id.MachineID != "" {
		c.machineIDs = append(c.machineIDs, id.MachineID)
	}
}

func (c *contract) check(name string, err error, detail map[string]any) bool {
	c.ev.add(name, err == nil, detail, err)
	return err == nil
}

func (c *contract) expectStatus(name string, result apiResult, callErr error, status int, code string, detail map[string]any) bool {
	if detail == nil {
		detail = map[string]any{}
	}
	if callErr != nil {
		detail["call_error"] = callErr.Error()
	}
	detail["http_status"] = result.Status
	if result.Error != nil {
		detail["error_code"] = result.Error.Code
		detail["error_message"] = result.Error.Message
	}
	if result.Status != status {
		return c.check(name, fmt.Errorf("HTTP %d, want %d (%s)", result.Status, status, code), detail)
	}
	if code != "" && (result.Error == nil || result.Error.Code != code) {
		return c.check(name, fmt.Errorf("error code does not match %s", code), detail)
	}
	return c.check(name, nil, detail)
}

func (c *contract) run(ctx context.Context) error {
	hostA := c.prefix + "-A"
	hostB := c.prefix + "-B"

	// Registration matrix.
	idA, err := newIdentity(hostA)
	if err != nil {
		return err
	}
	registeredA, resultA, err := c.client.register(ctx, idA)
	if err != nil {
		c.check("register new machine", err, nil)
		return err
	}
	c.track(idA)
	ok := c.expectStatus("register new machine", resultA, nil, 200, "", map[string]any{"uuid": idA.UUID, "machine_id": idA.MachineID})
	ok = ok && c.check("registration returned machine/config", nilIf(registeredA.MachineID == "" || registeredA.ConfigHash == "", "empty machine_id/config_hash"), map[string]any{"machine_id": registeredA.MachineID, "config_hash": registeredA.ConfigHash})
	if !ok {
		return fmt.Errorf("registration contract failed")
	}
	originalConfig := registeredA.Config
	originalHash := registeredA.ConfigHash

	again, resultAgain, err := c.client.register(ctx, idA)
	c.expectStatus("re-register same UUID/key/hostname", resultAgain, err, 200, "", nil)
	c.check("re-registration preserves machine_id", nilIf(err != nil || again.MachineID != idA.MachineID, "machine_id changed"), map[string]any{"machine_id": again.MachineID})

	keyConflict, err := newIdentity(hostA)
	if err != nil {
		return err
	}
	keyConflict.UUID = idA.UUID
	_, resultKeyConflict, err := c.client.register(ctx, keyConflict)
	c.expectStatus("known UUID with a different key is rejected", resultKeyConflict, err, 409, protocol.CodeKeyConflict, nil)

	hostnameMismatch, err := newIdentity(hostA + "-moved")
	if err != nil {
		return err
	}
	hostnameMismatch.UUID = idA.UUID
	hostnameMismatch.Key = idA.Key
	hostnameMismatch.PublicPEM = idA.PublicPEM
	_, resultHostname, err := c.client.register(ctx, hostnameMismatch)
	c.expectStatus("known UUID with changed hostname requires rename", resultHostname, err, 409, protocol.CodeHostnameMismatch, nil)

	idB, err := newIdentity(hostB)
	if err != nil {
		return err
	}
	_, resultB, err := c.client.register(ctx, idB)
	c.track(idB)
	c.expectStatus("register independent machine B", resultB, err, 200, "", nil)

	idConflict, err := newIdentity(hostA)
	if err != nil {
		return err
	}
	registeredConflict, resultConflictRegister, err := c.client.register(ctx, idConflict)
	c.track(idConflict)
	c.expectStatus("new UUID reusing an active hostname is accepted with warning", resultConflictRegister, err, 200, "", nil)
	c.check("hostname conflict is not a silent takeover", nilIf(resultConflictRegister.Status != 200 || !contains(registeredConflict.Warnings, "hostname_conflict"), "hostname_conflict warning missing"), map[string]any{"warnings": registeredConflict.Warnings, "machine_id": registeredConflict.MachineID})
	c.check("hostname conflict creates a different machine record", nilIf(registeredConflict.MachineID == idA.MachineID, "machine_id was reused"), map[string]any{"machine_a": idA.MachineID, "machine_b": registeredConflict.MachineID})

	// Config cache and jobs.
	syncA, resultSync, err := c.client.sync(ctx, idA, "")
	c.expectStatus("sync with empty config hash returns config", resultSync, err, 200, "", nil)
	c.check("config body present for empty hash", nilIf(syncA.Config == nil, "config body missing"), map[string]any{"config_hash": syncA.ConfigHash})
	unchanged, resultUnchanged, err := c.client.sync(ctx, idA, syncA.ConfigHash)
	c.expectStatus("sync with matching hash", resultUnchanged, err, 200, "", nil)
	c.check("matching config hash omits body", nilIf(unchanged.Config != nil, "config body was repeated"), nil)

	replayBody, err := c.client.syncEnvelope(ctx, idA, syncA.ConfigHash)
	if err != nil {
		return err
	}
	firstReplay := c.client.post(ctx, protocol.PathSync, replayBody)
	secondReplay := c.client.post(ctx, protocol.PathSync, replayBody)
	c.expectStatus("first use of a request_id succeeds", firstReplay, nil, 200, "", nil)
	c.expectStatus("replay of the same request_id is rejected", secondReplay, nil, 409, protocol.CodeReplay, nil)

	concurrentBody, err := c.client.syncEnvelope(ctx, idA, syncA.ConfigHash)
	if err != nil {
		return err
	}
	firstConcurrent, secondConcurrent := c.client.rawSyncWithSameRequest(ctx, concurrentBody)
	statuses := []int{firstConcurrent.Status, secondConcurrent.Status}
	c.check("concurrent identical request_ids: exactly one succeeds", nilIf(!(containsInt(statuses, 200) && containsInt(statuses, 409)), fmt.Sprintf("statuses=%v", statuses)), map[string]any{"statuses": statuses})

	changedConfig := originalConfig
	changedConfig.ScanIntervalDays = 2
	changedConfig.CertDirectories = []string{}
	updatedConfig, updatedHash, err := c.store.SetConfig(ctx, changedConfig, "acceptance")
	if !c.check("update configuration", err, map[string]any{"new_hash": updatedHash, "version": updatedConfig.Version}) {
		return err
	}
	afterConfig, resultConfig, err := c.client.sync(ctx, idA, originalHash)
	c.expectStatus("sync after config change", resultConfig, err, 200, "", nil)
	c.check("changed config and hash are returned", nilIf(afterConfig.Config == nil || afterConfig.ConfigHash != updatedHash, "config/hash mismatch"), map[string]any{"config_hash": afterConfig.ConfigHash})
	jobID, err := c.store.AddJob(ctx, idA.MachineID, "acceptance")
	if !c.check("create manual job", err, map[string]any{"job_id": jobID}) {
		return err
	}
	withJob, resultJob, err := c.client.sync(ctx, idA, updatedHash)
	c.expectStatus("sync with unchanged hash still returns jobs", resultJob, err, 200, "", nil)
	c.check("job is delivered with unchanged config hash", nilIf(!hasJob(withJob.Jobs, jobID), "job missing"), map[string]any{"jobs": len(withJob.Jobs)})

	// Reports.
	userCerts, err := observedFixtures(c.fixtures)
	if err != nil {
		return err
	}
	folderCert, err := observe(c.fixtures.future)
	if err != nil {
		return err
	}
	ipCert, err := observe(c.fixtures.ip)
	if err != nil {
		return err
	}
	fullA := withHostname(baseReport(1, "complete", userCerts, []protocol.ObservedCertificate{folderCert, ipCert}, true), idA.Hostname)
	reportA, resultReportA, err := c.client.report(ctx, idA, fullA)
	c.expectStatus("submit complete report", resultReportA, err, 200, "", nil)
	c.check("complete report applied", nilIf(!reportA.Accepted || !reportA.Applied, "report not applied"), map[string]any{"report_id": fullA.ReportID})
	c.check("report observations are active", c.observationAllActive(idA.MachineID, []string{userCerts[0].SHA256, userCerts[1].SHA256, folderCert.SHA256, ipCert.SHA256}), nil)

	duplicate, resultDuplicate, err := c.client.report(ctx, idA, fullA)
	c.expectStatus("duplicate report_id with new request_id", resultDuplicate, err, 200, "", nil)
	c.check("duplicate report is idempotent", nilIf(!duplicate.Duplicate || duplicate.Applied, "duplicate semantics wrong"), map[string]any{"duplicate": duplicate.Duplicate, "applied": duplicate.Applied})

	conflictReport := fullA
	conflictReport.FinishedAt = time.Now().UTC().Add(time.Second).Format(time.RFC3339Nano)
	_, resultConflict, err := c.client.report(ctx, idA, conflictReport)
	c.expectStatus("same report_id with different payload conflicts", resultConflict, err, 409, protocol.CodeReportConflict, nil)

	exactBody, err := c.client.reportEnvelope(idA, fullA)
	if err != nil {
		return err
	}
	exactFirst := c.client.post(ctx, protocol.PathReport, exactBody)
	exactSecond := c.client.post(ctx, protocol.PathReport, exactBody)
	c.expectStatus("exact report retry succeeds idempotently", exactFirst, nil, 200, "", nil)
	c.expectStatus("exact report request replay is rejected", exactSecond, nil, 409, protocol.CodeReplay, nil)

	partial := withHostname(baseReport(2, "partial", []protocol.ObservedCertificate{userCerts[0]}, nil, false), idA.Hostname)
	partialResponse, resultPartial, err := c.client.report(ctx, idA, partial)
	c.expectStatus("submit partial report", resultPartial, err, 200, "", nil)
	c.check("partial report applied without removing unobserved certs", c.partialPreserved(idA.MachineID, userCerts[1].SHA256, folderCert.SHA256), map[string]any{"report_id": partial.ReportID, "applied": partialResponse.Applied})

	empty := withHostname(baseReport(3, "complete", nil, nil, true), idA.Hostname)
	emptyResponse, resultEmpty, err := c.client.report(ctx, idA, empty)
	c.expectStatus("submit empty successful report", resultEmpty, err, 200, "", nil)
	c.check("empty complete report removes observations", c.observationAllInactive(idA.MachineID, []string{userCerts[0].SHA256, userCerts[1].SHA256, folderCert.SHA256, ipCert.SHA256}), map[string]any{"report_id": empty.ReportID, "applied": emptyResponse.Applied})

	idD, err := newIdentity(c.prefix + "-D")
	if err != nil {
		return err
	}
	if _, result, err := c.client.register(ctx, idD); err != nil {
		c.expectStatus("register delayed-report machine", result, nil, 200, "", nil)
		return err
	}
	c.track(idD)
	delayed2 := withHostname(baseReport(2, "complete", []protocol.ObservedCertificate{userCerts[0]}, nil, true), idD.Hostname)
	if _, result, err := c.client.report(ctx, idD, delayed2); err != nil {
		c.expectStatus("submit newer delayed baseline", result, nil, 200, "", nil)
		return err
	}
	delayed1 := withHostname(baseReport(1, "complete", []protocol.ObservedCertificate{folderCert}, nil, true), idD.Hostname)
	delayedResponse, resultDelayed, err := c.client.report(ctx, idD, delayed1)
	c.expectStatus("submit delayed older report", resultDelayed, err, 200, "", nil)
	c.check("delayed report does not roll back a newer source", nilIf(delayedResponse.Applied, "older report was applied"), map[string]any{"applied": delayedResponse.Applied, "reason": delayedResponse.Reason})
	c.check("delayed certificate is not active", c.observationAllInactive(idD.MachineID, []string{folderCert.SHA256}), nil)

	c.policyReportTransitions(ctx, idD, folderCert, ipCert)

	// Job acknowledgement.
	ackResponse, resultAck, err := c.client.ack(ctx, idA, jobID, "completed", fullA.ReportID, "acceptance complete")
	c.expectStatus("acknowledge manual job", resultAck, err, 200, "", nil)
	c.check("job acknowledgement records report", nilIf(ackResponse.State != "completed", "unexpected state"), map[string]any{"state": ackResponse.State})
	_, resultAckDup, err := c.client.ack(ctx, idA, jobID, "completed", fullA.ReportID, "acceptance complete")
	c.expectStatus("duplicate job acknowledgement is idempotent", resultAckDup, err, 200, "", nil)
	_, resultAckConflict, err := c.client.ack(ctx, idA, jobID, "failed", "", "different")
	c.expectStatus("different terminal job state conflicts", resultAckConflict, err, 409, protocol.CodeJobConflict, nil)

	// Rename.
	idA2, err := newIdentity(hostA + "-R")
	if err != nil {
		return err
	}
	renamed, resultRename, err := c.client.rename(ctx, idA, idA2)
	c.expectStatus("signed rename", resultRename, err, 200, "", nil)
	c.track(idA2)
	c.check("rename preserves machine_id", nilIf(renamed.MachineID != idA.MachineID, "machine_id changed"), map[string]any{"machine_id": renamed.MachineID})
	_, resultOldSync, _ := c.client.sync(ctx, idA, "")
	c.expectStatus("old UUID is no longer authorized", resultOldSync, nil, 401, protocol.CodeIdentityRevoked, nil)
	_, resultNewSync, err := c.client.sync(ctx, idA2, "")
	c.expectStatus("new UUID works after rename", resultNewSync, err, 200, "", nil)
	renameReport := withHostname(baseReport(4, "complete", []protocol.ObservedCertificate{userCerts[0]}, nil, true), idA2.Hostname)
	renameReportResponse, resultRenameReport, err := c.client.report(ctx, idA2, renameReport)
	c.expectStatus("report from the renamed identity", resultRenameReport, err, 200, "", nil)
	c.check("renamed identity applies fresh source sequences", nilIf(!renameReportResponse.Applied, "report was stale after rename"), map[string]any{"applied": renameReportResponse.Applied})

	idA3, err := newIdentity(hostB)
	if err != nil {
		return err
	}
	conflictRename, resultConflictRename, err := c.client.rename(ctx, idA2, idA3)
	c.expectStatus("rename to a busy hostname is accepted with warning", resultConflictRename, err, 200, "", nil)
	c.track(idA3)
	c.check("rename hostname conflict is explicit", nilIf(!contains(conflictRename.Warnings, "hostname_conflict"), "warning missing"), map[string]any{"warnings": conflictRename.Warnings})
	c.check("rename preserves machine history under conflict", nilIf(conflictRename.MachineID != idA.MachineID, "machine_id changed"), nil)

	// Certificate identity is preserved across repeated observations.
	createdBefore, err := c.certificateCreatedAt(userCerts[0].SHA256)
	if err == nil {
		if _, _, err := c.client.report(ctx, idA3, withHostname(baseReport(5, "complete", []protocol.ObservedCertificate{userCerts[0]}, nil, true), idA3.Hostname)); err == nil {
			createdAfter, err := c.certificateCreatedAt(userCerts[0].SHA256)
			c.check("certificate created_at is preserved across reports", nilIf(err != nil || !createdAfter.Equal(createdBefore), "created_at changed"), map[string]any{"sha256": userCerts[0].SHA256, "created_at": createdBefore})
		}
	}

	c.negativeChecks(ctx, idA3)

	// Restore the original configuration before leaving.
	if _, _, err := c.store.SetConfig(ctx, originalConfig, "acceptance-restore"); err != nil {
		c.check("restore original configuration", err, nil)
	}
	return nil
}

func (c *contract) certificateCreatedAt(hash string) (time.Time, error) {
	var created time.Time
	err := c.pool.QueryRowContext(context.Background(), `SELECT created_at FROM dbo.certificates WHERE sha256=@p1`, hash).Scan(&created)
	return created, err
}

func (c *contract) negativeChecks(ctx context.Context, id *identity) {
	getResult := c.client.raw(ctx, http.MethodGet, protocol.PathSync, "", nil)
	c.expectStatus("non-POST method is rejected", getResult, nil, http.StatusMethodNotAllowed, protocol.CodeMethodNotAllowed, nil)

	wrongContentType := c.client.raw(ctx, http.MethodPost, protocol.PathSync, "text/plain", []byte(`{}`))
	c.expectStatus("wrong content type is rejected", wrongContentType, nil, http.StatusBadRequest, protocol.CodeInvalidJSON, nil)

	emptyBody := c.client.raw(ctx, http.MethodPost, protocol.PathSync, protocol.ContentTypeJSON, nil)
	c.expectStatus("empty body is rejected", emptyBody, nil, http.StatusBadRequest, protocol.CodeInvalidJSON, nil)

	unknownPath := c.client.raw(ctx, http.MethodPost, protocol.AgentBasePath+"/unknown", protocol.ContentTypeJSON, []byte(`{}`))
	c.expectStatus("unknown endpoint is rejected", unknownPath, nil, http.StatusNotFound, protocol.CodeNotFound, nil)

	oversized := make([]byte, protocol.MaxRequestBytes+1024)
	c.expectStatus("oversized body is rejected", c.client.raw(ctx, http.MethodPost, protocol.PathSync, protocol.ContentTypeJSON, oversized), nil, http.StatusRequestEntityTooLarge, protocol.CodePayloadTooLarge, nil)

	p384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err == nil {
		der, marshalErr := x509.MarshalPKIXPublicKey(&p384.PublicKey)
		if marshalErr == nil {
			pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
			wrongCurve, identityErr := newIdentity(c.prefix + "-CURVE")
			if identityErr == nil {
				wrongCurve.Key = p384
				wrongCurve.PublicPEM = string(pemBytes)
				_, result, _ := c.client.register(ctx, wrongCurve)
				c.expectStatus("wrong ECDSA curve is rejected", result, nil, http.StatusBadRequest, protocol.CodeInvalidCurve, nil)
			}
		}
	}

	validBody, err := c.client.syncEnvelope(ctx, id, "")
	if err == nil {
		var env protocol.Envelope
		if json.Unmarshal(validBody, &env) == nil {
			if len(env.Sign) > 8 {
				env.Sign = env.Sign[:len(env.Sign)-4] + "AAAA"
			}
			tampered, _ := json.Marshal(env)
			c.expectStatus("tampered signature is rejected", c.client.post(ctx, protocol.PathSync, tampered), nil, http.StatusBadRequest, protocol.CodeInvalidSignature, nil)
		}
	}

	wrongPathData := baseData(protocol.OpSync, protocol.PathReport, id)
	wrongPathEnvelope, err := protocol.BuildSignedEnvelope(id.Key, wrongPathData)
	if err == nil {
		c.expectStatus("signed path substitution is rejected", c.client.post(ctx, protocol.PathSync, wrongPathEnvelope), nil, http.StatusBadRequest, protocol.CodeInvalidEnvelope, nil)
	}
}

func nilIf(condition bool, message string) error {
	if condition {
		return fmt.Errorf("%s", message)
	}
	return nil
}

func contains(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}

func containsInt(values []int, wanted int) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}

func hasJob(jobs []protocol.Job, wanted string) bool {
	for _, job := range jobs {
		if strings.EqualFold(job.JobID, wanted) {
			return true
		}
	}
	return false
}

func (c *contract) observationAllActive(machineID string, hashes []string) error {
	for _, hash := range hashes {
		var active bool
		err := c.pool.QueryRowContext(context.Background(), `
SELECT active FROM dbo.certificate_observations WHERE machine_id=@p1 AND certificate_sha256=@p2 AND active=1`, machineID, hash).Scan(&active)
		if err != nil {
			return fmt.Errorf("certificate %s: %w", hash, err)
		}
		if !active {
			return fmt.Errorf("certificate %s is not active", hash)
		}
	}
	return nil
}

func (c *contract) observationAllInactive(machineID string, hashes []string) error {
	for _, hash := range hashes {
		var count int
		if err := c.pool.QueryRowContext(context.Background(), `
SELECT COUNT(1) FROM dbo.certificate_observations WHERE machine_id=@p1 AND certificate_sha256=@p2 AND active=1`, machineID, hash).Scan(&count); err != nil {
			return err
		}
		if count != 0 {
			return fmt.Errorf("certificate %s is still active", hash)
		}
	}
	return nil
}

func (c *contract) partialPreserved(machineID string, hashes ...string) error {
	for _, hash := range hashes {
		var count int
		if err := c.pool.QueryRowContext(context.Background(), `
SELECT COUNT(1) FROM dbo.certificate_observations WHERE machine_id=@p1 AND certificate_sha256=@p2 AND active=1`, machineID, hash).Scan(&count); err != nil {
			return err
		}
		if count == 0 {
			return fmt.Errorf("partial report removed certificate %s", hash)
		}
	}
	return nil
}

func setStandConfig(ctx context.Context, cfg acceptanceConfig, interval int, dirs []string, recursive bool) error {
	pool, err := db.Open(ctx, cfg.DB)
	if err != nil {
		return err
	}
	defer pool.Close()
	storeInstance := store.New(pool)
	current, _, err := storeInstance.Config(ctx)
	if err != nil {
		return err
	}
	var clean []string
	for _, dir := range dirs {
		if dir = strings.TrimSpace(dir); dir != "" {
			clean = append(clean, dir)
		}
	}
	current.ScanIntervalDays = interval
	if len(clean) > 0 {
		return fmt.Errorf("global folders are no longer supported; assign folder policies through the admin API")
	}
	current.CertDirectories = []string{}
	current.Recursive = recursive
	updated, hash, err := storeInstance.SetConfig(ctx, current, "stand-config")
	if err != nil {
		return err
	}
	fmt.Printf("config version=%d hash=%s dirs=%v interval=%d\n", updated.Version, hash, updated.CertDirectories, updated.ScanIntervalDays)
	return nil
}
