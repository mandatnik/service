package store

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	mssql "github.com/microsoft/go-mssqldb"
	"mandatnik/internal/activation"
	"mandatnik/internal/backend/config"
	"mandatnik/internal/backend/db"
	"mandatnik/internal/backend/licensecrypto"
	"mandatnik/internal/protocol"
)

// TestTasksSQLServer exercises the real reservation/task SQL. It is skipped
// unless an authorized stand configuration is provided.
func TestTasksSQLServer(t *testing.T) {
	file := os.Getenv("MANDATNIK_POLICY_TEST_CONFIG")
	if file == "" {
		t.Skip("set MANDATNIK_POLICY_TEST_CONFIG to an authorized SQL Server acceptance config")
	}
	raw, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	var cfg struct {
		DB config.DB `json:"db"`
	}
	if err = json.Unmarshal(raw, &cfg); err != nil {
		t.Fatal(err)
	}
	if err = cfg.DB.Validate(); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	pool, err := db.Open(ctx, cfg.DB)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	if err = db.Migrate(ctx, pool, t.Logf); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	keyringPath := dir + "/keyring.json"
	fingerprintPath := dir + "/fingerprint.key"
	if _, err := licensecrypto.InitKeyring(keyringPath); err != nil {
		t.Fatal(err)
	}
	if err := licensecrypto.InitFingerprintKey(fingerprintPath); err != nil {
		t.Fatal(err)
	}
	ring, err := licensecrypto.LoadKeyring(keyringPath)
	if err != nil {
		t.Fatal(err)
	}
	fingerprint, err := licensecrypto.LoadFingerprintKey(fingerprintPath)
	if err != nil {
		t.Fatal(err)
	}
	s := New(pool)
	s.SetLicenseCrypto(ring, fingerprint)

	t.Run("machine filters distinguish current offline and historical", func(t *testing.T) {
		f := newTaskFixture(t, ctx, pool, s, 2, 1)
		defer f.cleanup()
		if _, err := pool.ExecContext(ctx, `UPDATE dbo.registrations SET last_seen_at=DATEADD(minute,-30,SYSUTCDATETIME()) WHERE machine_id=@p1`, f.machineIDs[0]); err != nil {
			t.Fatal(err)
		}
		if _, err := pool.ExecContext(ctx, `UPDATE dbo.registrations SET state=N'revoked' WHERE machine_id=@p1`, f.machineIDs[1]); err != nil {
			t.Fatal(err)
		}
		for _, tc := range []struct {
			name, machine, status string
			want                  int
		}{
			{"current includes offline workstation", f.machineIDs[0], "active", 1},
			{"offline includes current workstation", f.machineIDs[0], "offline", 1},
			{"current excludes historical workstation", f.machineIDs[1], "active", 0},
			{"offline excludes historical workstation", f.machineIDs[1], "offline", 0},
			{"all includes historical workstation", f.machineIDs[1], "", 1},
		} {
			page, err := s.ListMachines(ctx, AdminMachineFilter{MachineID: tc.machine, Status: tc.status, Page: 1, PageSize: 25})
			if err != nil {
				t.Fatal(tc.name, err)
			}
			if len(page.Items) != tc.want {
				t.Errorf("%s: got %d items, want %d", tc.name, len(page.Items), tc.want)
			}
		}
	})

	t.Run("preview reservation idempotency and result", func(t *testing.T) {
		f := newTaskFixture(t, ctx, pool, s, 2, 2)
		defer f.cleanup()
		preview, apiErr := s.BuildActivationPreview(ctx, ActivationPreviewInput{PoolID: f.poolID, MachineIDs: f.machineIDs}, "test")
		if apiErr != nil {
			t.Fatalf("preview: %v", apiErr)
		}
		if preview.Preview.RequiredKeys != 2 || preview.Preview.Compatible != 2 {
			t.Fatalf("preview counts: %+v", preview.Preview)
		}
		key := "idem-" + protocol.NewUUID()
		detail, apiErr := s.CreateInstallTask(ctx, CreateInstallTaskInput{PoolID: f.poolID, PreviewID: preview.PreviewID, MachineIDs: f.machineIDs, IdempotencyKey: key}, "test")
		if apiErr != nil {
			t.Fatalf("create install: %v", apiErr)
		}
		if len(detail.Items) != 2 || detail.Task.State != protocol.TaskAggregateQueued {
			t.Fatalf("task: %+v", detail.Task)
		}
		again, apiErr := s.CreateInstallTask(ctx, CreateInstallTaskInput{PoolID: f.poolID, PreviewID: preview.PreviewID, MachineIDs: f.machineIDs, IdempotencyKey: key}, "test")
		if apiErr != nil || again.Task.ID != detail.Task.ID {
			t.Fatalf("idempotent create: %v %+v", apiErr, again)
		}
		if _, apiErr := s.CreateInstallTask(ctx, CreateInstallTaskInput{PoolID: f.poolID, PreviewID: preview.PreviewID, MachineIDs: f.machineIDs[:1], IdempotencyKey: key}, "test"); apiErr == nil || apiErr.Code != protocol.CodeIdempotencyConflict {
			t.Fatalf("different body with same idempotency key: %v", apiErr)
		}
		var reserved int
		if err := pool.QueryRowContext(ctx, `SELECT COUNT(1) FROM dbo.licenses WHERE pool_id=@p1 AND state=N'reserved'`, f.poolID).Scan(&reserved); err != nil || reserved != 2 {
			t.Fatalf("reserved=%d err=%v", reserved, err)
		}
		// Claim one item, then a task cancel must not release it.
		itemID := detail.Items[0].ID
		claim, apiErr := s.ClaimTaskItem(ctx, f.identity(0), itemID, 1)
		if apiErr != nil || !claim.Granted {
			t.Fatalf("claim: %v %+v", apiErr, claim)
		}
		cancelled, apiErr := s.CancelTask(ctx, detail.Task.ID, "test")
		if apiErr != nil {
			t.Fatalf("cancel: %v", apiErr)
		}
		for _, item := range cancelled.Items {
			if item.ID == itemID && item.State == protocol.TaskStateCancelled {
				t.Fatal("started item was cancelled after claim")
			}
		}
		var licenseID mssql.UniqueIdentifier
		if err := pool.QueryRowContext(ctx, `SELECT license_id FROM dbo.task_items WHERE item_id=@p1`, itemID).Scan(&licenseID); err != nil {
			t.Fatal(err)
		}
		var state string
		if err := pool.QueryRowContext(ctx, `SELECT state FROM dbo.licenses WHERE license_id=@p1`, licenseID).Scan(&state); err != nil || state != protocol.LicenseStateReserved {
			t.Fatalf("claimed license state=%s err=%v", state, err)
		}
		// The other item was not started and is cancelled/released.
		var available int
		if err := pool.QueryRowContext(ctx, `SELECT COUNT(1) FROM dbo.licenses WHERE pool_id=@p1 AND state=N'available'`, f.poolID).Scan(&available); err != nil {
			t.Fatal(err)
		}
		if available != 1 {
			t.Fatalf("available=%d after cancel; started item must keep its reservation", available)
		}
		history, err := s.LicenseHistory(ctx, f.poolID, 50)
		if err != nil || len(history) == 0 {
			t.Fatalf("history: %v %d", err, len(history))
		}
		for _, item := range history {
			if item.Mask != "" && !strings.HasPrefix(item.Mask, "****") {
				t.Fatalf("history exposed a non-mask serial: %q", item.Mask)
			}
		}
	})

	t.Run("legacy AddJob and AckJob update one task item", func(t *testing.T) {
		f := newTaskFixture(t, ctx, pool, s, 1, 1)
		defer f.cleanup()
		jobID, err := s.AddJob(ctx, f.machineIDs[0], "test")
		if err != nil {
			t.Fatalf("add job: %v", err)
		}
		var itemID mssql.UniqueIdentifier
		if err := pool.QueryRowContext(ctx, `SELECT task_item_id FROM dbo.jobs WHERE job_id=@p1`, jobID).Scan(&itemID); err != nil {
			t.Fatal(err)
		}
		if uuidString(itemID) == "00000000-0000-0000-0000-000000000000" {
			t.Fatal("new job has no linked task item")
		}
		request := &protocol.SignedRequest{Data: protocol.SignedData{
			RequestID: protocol.NewUUID(), JobID: jobID, JobStatus: "completed", JobReportID: f.reportIDs[0],
		}}
		if _, apiErr := s.AckJob(ctx, &Identity{UUID: protocol.NewUUID(), MachineID: f.machineIDs[0], RegistrationID: f.regIDs[0]}, request); apiErr != nil {
			t.Fatalf("ack job: %v", apiErr)
		}
		var state string
		var report mssql.UniqueIdentifier
		if err := pool.QueryRowContext(ctx, `SELECT state,scan_report_id FROM dbo.task_items WHERE item_id=@p1`, itemID).Scan(&state, &report); err != nil {
			t.Fatal(err)
		}
		if state != protocol.TaskStateSucceeded || uuidString(report) != f.reportIDs[0] {
			t.Fatalf("task item state=%s report=%s", state, uuidString(report))
		}
	})

	t.Run("deficit rolls back whole task", func(t *testing.T) {
		f := newTaskFixture(t, ctx, pool, s, 2, 1)
		defer f.cleanup()
		preview, apiErr := s.BuildActivationPreview(ctx, ActivationPreviewInput{PoolID: f.poolID, MachineIDs: f.machineIDs}, "test")
		if apiErr != nil {
			t.Fatalf("preview: %v", apiErr)
		}
		if preview.Preview.RequiredKeys != 2 || preview.AvailableKeys != 1 {
			t.Fatalf("preview deficit: %+v", preview)
		}
		_, apiErr = s.CreateInstallTask(ctx, CreateInstallTaskInput{PoolID: f.poolID, PreviewID: preview.PreviewID, MachineIDs: f.machineIDs, IdempotencyKey: "deficit-" + protocol.NewUUID()}, "test")
		if apiErr == nil || apiErr.Code != protocol.CodeLicenseDeficit {
			t.Fatalf("deficit error: %v", apiErr)
		}
		var tasks, items, available int
		_ = pool.QueryRowContext(ctx, `SELECT COUNT(1) FROM dbo.tasks WHERE selection_snapshot LIKE @p1`, "%"+f.poolID+"%").Scan(&tasks)
		_ = pool.QueryRowContext(ctx, `SELECT COUNT(1) FROM dbo.task_items WHERE task_id IN (SELECT task_id FROM dbo.tasks WHERE selection_snapshot LIKE @p1)`, "%"+f.poolID+"%").Scan(&items)
		_ = pool.QueryRowContext(ctx, `SELECT COUNT(1) FROM dbo.licenses WHERE pool_id=@p1 AND state=N'available'`, f.poolID).Scan(&available)
		if tasks != 0 || items != 0 || available != 1 {
			t.Fatalf("partial deficit state: tasks=%d items=%d available=%d", tasks, items, available)
		}
	})

	t.Run("expiry before start releases reservation", func(t *testing.T) {
		f := newTaskFixture(t, ctx, pool, s, 1, 1)
		defer f.cleanup()
		preview, apiErr := s.BuildActivationPreview(ctx, ActivationPreviewInput{PoolID: f.poolID, MachineIDs: f.machineIDs}, "test")
		if apiErr != nil {
			t.Fatalf("preview: %v", apiErr)
		}
		detail, apiErr := s.CreateInstallTask(ctx, CreateInstallTaskInput{PoolID: f.poolID, PreviewID: preview.PreviewID, MachineIDs: f.machineIDs, IdempotencyKey: "expiry-" + protocol.NewUUID()}, "test")
		if apiErr != nil {
			t.Fatalf("create: %v", apiErr)
		}
		if _, err := pool.ExecContext(ctx, `UPDATE dbo.tasks SET expires_at=DATEADD(minute,-1,SYSUTCDATETIME()) WHERE task_id=@p1`, detail.Task.ID); err != nil {
			t.Fatal(err)
		}
		if apiErr := s.ExpireDueTasks(ctx); apiErr != nil {
			t.Fatalf("expire: %v", apiErr)
		}
		expired, apiErr := s.TaskDetail(ctx, detail.Task.ID)
		if apiErr != nil {
			t.Fatalf("detail: %v", apiErr)
		}
		if expired.Items[0].State != protocol.TaskStateExpired {
			t.Fatalf("item state=%s", expired.Items[0].State)
		}
		var available int
		_ = pool.QueryRowContext(ctx, `SELECT COUNT(1) FROM dbo.licenses WHERE pool_id=@p1 AND state=N'available'`, f.poolID).Scan(&available)
		if available != 1 {
			t.Fatalf("expired reservation was not released: %d", available)
		}
	})

	t.Run("success marks license used and task completed", func(t *testing.T) {
		f := newTaskFixture(t, ctx, pool, s, 1, 1)
		defer f.cleanup()
		preview, apiErr := s.BuildActivationPreview(ctx, ActivationPreviewInput{PoolID: f.poolID, MachineIDs: f.machineIDs}, "test")
		if apiErr != nil {
			t.Fatalf("preview: %v", apiErr)
		}
		detail, apiErr := s.CreateInstallTask(ctx, CreateInstallTaskInput{PoolID: f.poolID, PreviewID: preview.PreviewID, MachineIDs: f.machineIDs, IdempotencyKey: "result-" + protocol.NewUUID()}, "test")
		if apiErr != nil {
			t.Fatalf("create: %v", apiErr)
		}
		itemID := detail.Items[0].ID
		claim, apiErr := s.ClaimTaskItem(ctx, f.identity(0), itemID, 1)
		if apiErr != nil || !claim.Granted {
			t.Fatalf("claim: %v %+v", apiErr, claim)
		}
		result := &protocol.TaskResult{
			ItemID: itemID, DeliveryVersion: 1, State: protocol.TaskStateSucceeded,
			ResultVersion: 1, Modified: "yes", SerialMatch: true, AttemptNo: 1,
			License: protocol.TaskLicenseState{Present: true, Complete: true, Kind: "client", State: "active", TermKind: "perpetual", IsTrial: "false"},
		}
		response, apiErr := s.SubmitTaskResult(ctx, f.identity(0), result)
		if apiErr != nil || response.State != protocol.TaskStateSucceeded {
			t.Fatalf("result: %v %+v", apiErr, response)
		}
		var licenseState string
		_ = pool.QueryRowContext(ctx, `SELECT state FROM dbo.licenses WHERE pool_id=@p1`, f.poolID).Scan(&licenseState)
		if licenseState != protocol.LicenseStateUsed {
			t.Fatalf("license state=%s", licenseState)
		}
		done, apiErr := s.TaskDetail(ctx, detail.Task.ID)
		if apiErr != nil || done.Task.State != protocol.TaskAggregateCompleted {
			t.Fatalf("task: %v %+v", apiErr, done)
		}
	})

	t.Run("concurrent tasks cannot share one key", func(t *testing.T) {
		f := newTaskFixture(t, ctx, pool, s, 2, 1)
		defer f.cleanup()
		previews := make([]*ActivationPreviewResponse, 2)
		for i := range previews {
			preview, apiErr := s.BuildActivationPreview(ctx, ActivationPreviewInput{PoolID: f.poolID, MachineIDs: f.machineIDs[i : i+1]}, "test")
			if apiErr != nil {
				t.Fatalf("preview %d: %v", i, apiErr)
			}
			previews[i] = preview
		}
		var wg sync.WaitGroup
		results := make([]*protocol.APIError, 2)
		for i := range previews {
			wg.Add(1)
			go func(index int) {
				defer wg.Done()
				_, apiErr := s.CreateInstallTask(ctx, CreateInstallTaskInput{
					PoolID: f.poolID, PreviewID: previews[index].PreviewID, MachineIDs: f.machineIDs[index : index+1],
					IdempotencyKey: "race-" + protocol.NewUUID(),
				}, "test")
				results[index] = apiErr
			}(i)
		}
		wg.Wait()
		success, deficit := 0, 0
		for _, apiErr := range results {
			if apiErr == nil {
				success++
			} else if apiErr.Code == protocol.CodeLicenseDeficit {
				deficit++
			} else {
				t.Fatalf("unexpected concurrent error: %v", apiErr)
			}
		}
		if success != 1 || deficit != 1 {
			t.Fatalf("success=%d deficit=%d", success, deficit)
		}
		var reserved, available int
		_ = pool.QueryRowContext(ctx, `SELECT COUNT(1) FROM dbo.licenses WHERE pool_id=@p1 AND state=N'reserved'`, f.poolID).Scan(&reserved)
		_ = pool.QueryRowContext(ctx, `SELECT COUNT(1) FROM dbo.licenses WHERE pool_id=@p1 AND state=N'available'`, f.poolID).Scan(&available)
		if reserved != 1 || available != 0 {
			t.Fatalf("reserved=%d available=%d", reserved, available)
		}
	})

	t.Run("scan task success is bound to accepted report", func(t *testing.T) {
		f := newTaskFixture(t, ctx, pool, s, 1, 1)
		defer f.cleanup()
		detail, apiErr := s.CreateScanTask(ctx, CreateScanTaskInput{MachineIDs: f.machineIDs, IdempotencyKey: "scan-" + protocol.NewUUID()}, "test")
		if apiErr != nil {
			t.Fatalf("scan: %v", apiErr)
		}
		itemID := detail.Items[0].ID
		claim, apiErr := s.ClaimTaskItem(ctx, f.identity(0), itemID, 1)
		if apiErr != nil || !claim.Granted {
			t.Fatalf("claim: %v %+v", apiErr, claim)
		}
		result := &protocol.TaskResult{
			ItemID: itemID, DeliveryVersion: 1, State: protocol.TaskStateSucceeded,
			ResultVersion: 1, Modified: "no", ReportID: f.reportIDs[0],
		}
		response, apiErr := s.SubmitTaskResult(ctx, f.identity(0), result)
		if apiErr != nil || response.State != protocol.TaskStateSucceeded {
			t.Fatalf("scan result: %v %+v", apiErr, response)
		}
		var jobState string
		_ = pool.QueryRowContext(ctx, `SELECT j.state FROM dbo.jobs j JOIN dbo.task_items i ON i.legacy_job_id=j.job_id WHERE i.item_id=@p1`, itemID).Scan(&jobState)
		if jobState != "completed" {
			t.Fatalf("legacy job state=%s", jobState)
		}
	})

	t.Run("report apply stores provider binding at observation", func(t *testing.T) {
		f := newTaskFixture(t, ctx, pool, s, 1, 1)
		defer f.cleanup()
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		template := x509.Certificate{SerialNumber: big.NewInt(99), Subject: pkix.Name{CommonName: "binding test"}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour)}
		der, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
		if err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(der)
		certSHA := hex.EncodeToString(sum[:])
		reportID := protocol.NewUUID()
		now := time.Now().UTC()
		if _, err := pool.ExecContext(ctx, `
INSERT INTO dbo.reports(report_id,machine_id,registration_id,scan_seq,collected_at,received_at,status,applied,applied_sources,payload_sha256,payload_json,profiles_complete,personal_complete)
VALUES(@p1,@p2,@p3,2,@p4,@p4,N'complete',0,0,REPLICATE('b',64),N'{}',1,1)`,
			reportID, f.machineIDs[0], f.regIDs[0], now); err != nil {
			t.Fatal(err)
		}
		f.certSHAs = append(f.certSHAs, certSHA)
		report := &protocol.Report{ReportID: reportID, ScanSeq: 2, CollectedAt: now.Format(time.RFC3339Nano)}
		source := &protocol.SourceResult{
			SourceType: "user_store", SourceKey: f.sids[0], UserSID: f.sids[0], Complete: true,
			Certificates: []protocol.ObservedCertificate{{
				SHA256: certSHA, DERBase64: base64.StdEncoding.EncodeToString(der),
				ProviderBindings: []protocol.ProviderBinding{{ProviderName: "Crypto-Pro GOST R 34.10-2012 Cryptographic Service Provider", ProviderAPI: "capi", BindingState: "present", ProviderOwner: "cryptopro", PrivateKeyState: "not_checked"}},
			}},
		}
		tx, err := pool.BeginTx(ctx, nil)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback()
		applied, apiErr := s.applySourceTx(ctx, tx, &Identity{MachineID: f.machineIDs[0], RegistrationID: f.regIDs[0]}, report, source, map[string]int64{}, now)
		if apiErr != nil || !applied {
			t.Fatalf("apply source: %v applied=%t", apiErr, applied)
		}
		if err := tx.Commit(); err != nil {
			t.Fatal(err)
		}
		var owner, state, privateKey string
		if err := pool.QueryRowContext(ctx, `
SELECT b.provider_owner,b.binding_state,b.private_key_state
FROM dbo.certificate_observation_bindings b
JOIN dbo.certificate_observations o ON o.observation_id=b.observation_id
WHERE o.machine_id=@p1 AND o.certificate_sha256=@p2`, f.machineIDs[0], certSHA).Scan(&owner, &state, &privateKey); err != nil {
			t.Fatal(err)
		}
		if owner != "cryptopro" || state != "present" || privateKey != "not_checked" {
			t.Fatalf("binding: owner=%s state=%s key=%s", owner, state, privateKey)
		}
	})

	t.Run("same DER with different provider bindings is not mixed", func(t *testing.T) {
		f := newTaskFixture(t, ctx, pool, s, 2, 2)
		defer f.cleanup()
		if _, err := pool.ExecContext(ctx, `UPDATE dbo.certificate_observations SET certificate_sha256=@p1 WHERE machine_id=@p2`, f.certSHAs[0], f.machineIDs[1]); err != nil {
			t.Fatal(err)
		}
		if _, err := pool.ExecContext(ctx, `DELETE FROM dbo.certificates WHERE sha256=@p1`, f.certSHAs[1]); err != nil {
			t.Fatal(err)
		}
		if _, err := pool.ExecContext(ctx, `
UPDATE b SET provider_name=N'Microsoft Enhanced RSA and AES Cryptographic Provider',provider_owner=N'other'
FROM dbo.certificate_observation_bindings b
JOIN dbo.certificate_observations o ON o.observation_id=b.observation_id
WHERE o.machine_id=@p1`, f.machineIDs[1]); err != nil {
			t.Fatal(err)
		}
		preview, apiErr := s.BuildActivationPreview(ctx, ActivationPreviewInput{PoolID: f.poolID, MachineIDs: f.machineIDs}, "test")
		if apiErr != nil {
			t.Fatalf("preview: %v", apiErr)
		}
		byMachine := map[string]activation.Classification{}
		for _, machine := range preview.Preview.Machines {
			byMachine[machine.MachineID] = machine
		}
		if byMachine[f.machineIDs[0]].Category != protocol.TaskCategoryActivation {
			t.Fatalf("CryptoPro binding machine: %+v", byMachine[f.machineIDs[0]])
		}
		if byMachine[f.machineIDs[1]].Category != protocol.TaskCategoryOptional {
			t.Fatalf("Microsoft binding machine was mixed: %+v", byMachine[f.machineIDs[1]])
		}
	})

	t.Run("scan task supports an old agent without encryption key", func(t *testing.T) {
		f := newTaskFixture(t, ctx, pool, s, 1, 1)
		defer f.cleanup()
		if _, err := pool.ExecContext(ctx, `DELETE FROM dbo.agent_encryption_keys WHERE machine_id=@p1`, f.machineIDs[0]); err != nil {
			t.Fatal(err)
		}
		if _, err := pool.ExecContext(ctx, `DELETE FROM dbo.agent_capabilities WHERE registration_id=@p1`, f.regIDs[0]); err != nil {
			t.Fatal(err)
		}
		detail, apiErr := s.CreateScanTask(ctx, CreateScanTaskInput{
			MachineIDs: f.machineIDs, IdempotencyKey: "legacy-scan-" + protocol.NewUUID(),
		}, "test")
		if apiErr != nil {
			t.Fatalf("create scan for old agent: %v", apiErr)
		}
		if len(detail.Items) != 1 || detail.Items[0].State != protocol.TaskStateQueued {
			t.Fatalf("legacy scan item = %+v", detail.Items)
		}
		var deliveryVersion int
		var keyID sql.NullString
		var encrypted []byte
		if err := pool.QueryRowContext(ctx, `
SELECT delivery_version,encryption_key_id,encrypted_parameters FROM dbo.task_items WHERE item_id=@p1`, detail.Items[0].ID).
			Scan(&deliveryVersion, &keyID, &encrypted); err != nil {
			t.Fatal(err)
		}
		if deliveryVersion != 0 || keyID.Valid || len(encrypted) != 0 {
			t.Fatalf("legacy scan item has encrypted parameters: version=%d key=%v params=%d", deliveryVersion, keyID, len(encrypted))
		}
		var jobs int
		if err := pool.QueryRowContext(ctx, `SELECT COUNT(1) FROM dbo.jobs WHERE task_id=@p1 AND state=N'pending'`, detail.Task.ID).Scan(&jobs); err != nil {
			t.Fatal(err)
		}
		if jobs != 1 {
			t.Fatalf("legacy scan jobs = %d, want 1", jobs)
		}
	})

	t.Run("group recipients deduplicate directly selected machines and skip archived", func(t *testing.T) {
		f := newTaskFixture(t, ctx, pool, s, 3, 1)
		defer f.cleanup()
		groupName := "TASK-RECIPIENTS-" + strings.ReplaceAll(protocol.NewUUID(), "-", "")[:10]
		groupID, err := s.SaveGroup(ctx, MachineGroup{
			Name: groupName, MachineIDs: []string{f.machineIDs[0], f.machineIDs[1], f.machineIDs[2]},
		}, true, "test")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			cleanupCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			_, _ = pool.ExecContext(cleanupCtx, `DELETE FROM dbo.machine_group_members WHERE group_id=@p1`, groupID)
			_, _ = pool.ExecContext(cleanupCtx, `DELETE FROM dbo.machine_groups WHERE group_id=@p1`, groupID)
		})
		if _, err := pool.ExecContext(ctx, `
UPDATE dbo.machines SET archived_at=SYSUTCDATETIME(),archived_by=N'test',archive_reason=N'selection test'
WHERE machine_id=@p1`, f.machineIDs[1]); err != nil {
			t.Fatal(err)
		}
		selected, apiErr := s.ResolveMachineSelection(ctx, []string{f.machineIDs[0]}, []string{groupID})
		if apiErr != nil {
			t.Fatalf("resolve recipients: %v", apiErr)
		}
		if len(selected) != 2 || selected[0] != f.machineIDs[0] || selected[1] != f.machineIDs[2] {
			t.Fatalf("resolved recipients = %v, want [%s %s]", selected, f.machineIDs[0], f.machineIDs[2])
		}
		detail, apiErr := s.CreateScanTask(ctx, CreateScanTaskInput{
			MachineIDs: []string{f.machineIDs[0]}, GroupIDs: []string{groupID},
			IdempotencyKey: "group-scan-" + protocol.NewUUID(),
		}, "test")
		if apiErr != nil {
			t.Fatalf("create group scan: %v", apiErr)
		}
		if len(detail.Items) != 2 {
			t.Fatalf("group scan item count = %d, want 2", len(detail.Items))
		}
		seen := map[string]int{}
		for _, item := range detail.Items {
			seen[item.MachineID]++
		}
		if seen[f.machineIDs[0]] != 1 || seen[f.machineIDs[2]] != 1 || seen[f.machineIDs[1]] != 0 {
			t.Fatalf("group scan items = %+v", detail.Items)
		}
		if _, apiErr := s.ResolveMachineSelection(ctx, []string{f.machineIDs[1]}, nil); apiErr == nil || apiErr.Code != protocol.CodeMachineNotEligible {
			t.Fatalf("archived machine was selectable directly: %v", apiErr)
		}
	})
}

type taskFixture struct {
	s          *Store
	poolID     string
	machineIDs []string
	regIDs     []int64
	sids       []string
	certSHAs   []string
	reportIDs  []string
	// cleanup deletes only rows created by this test.
	cleanupFunc func()
}

func (f *taskFixture) cleanup() {
	if f != nil && f.cleanupFunc != nil {
		f.cleanupFunc()
	}
}

func (f *taskFixture) identity(index int) *Identity {
	return &Identity{MachineID: f.machineIDs[index], RegistrationID: f.regIDs[index]}
}

func newTaskFixture(t *testing.T, ctx context.Context, pool *sql.DB, s *Store, machineCount, licenseCount int) *taskFixture {
	t.Helper()
	fixture := &taskFixture{s: s}
	t.Cleanup(fixture.cleanup)
	for i := 0; i < machineCount; i++ {
		machineID := protocol.NewUUID()
		uuid := protocol.NewUUID()
		hostname := fmt.Sprintf("TASK-TEST-%d-%s", i, machineID[:8])
		sid := fmt.Sprintf("S-1-5-21-1000-2000-%d-1001", i+1)
		if _, err := pool.ExecContext(ctx, `INSERT INTO dbo.machines(machine_id,display_name,created_at,updated_at) VALUES(@p1,@p2,SYSUTCDATETIME(),SYSUTCDATETIME())`, machineID, hostname); err != nil {
			t.Fatal(err)
		}
		key, err := protocol.GenerateKey()
		if err != nil {
			t.Fatal(err)
		}
		publicPEM, _ := protocol.MarshalPublicKeyPEM(&key.PublicKey)
		keyHash, _ := protocol.PublicKeyFingerprint(&key.PublicKey)
		var registrationID int64
		if err := pool.QueryRowContext(ctx, `
INSERT INTO dbo.registrations(machine_id,uuid,hostname,hostname_norm,public_key_pem,public_key_sha256,state,agent_version,os_version,architecture,created_at,last_seen_at)
OUTPUT INSERTED.registration_id
VALUES(@p1,@p2,@p3,@p4,@p5,@p6,N'active',N'test',N'Windows 10',N'amd64',SYSUTCDATETIME(),SYSUTCDATETIME())`,
			machineID, uuid, hostname, strings.ToLower(hostname), publicPEM, keyHash).Scan(&registrationID); err != nil {
			t.Fatal(err)
		}
		if _, err := pool.ExecContext(ctx, `INSERT INTO dbo.agent_capabilities(registration_id,capabilities_json,schedule_v2,tasks_v1,install_v1,updated_at) VALUES(@p1,N'["task_v1","install_license_v1","schedule_v2"]',1,1,1,SYSUTCDATETIME())`, registrationID); err != nil {
			t.Fatal(err)
		}
		encryptionKey, err := protocol.GenerateTaskEncryptionKey()
		if err != nil {
			t.Fatal(err)
		}
		encryptionPEM, _ := protocol.MarshalTaskPublicKeyPEM(&encryptionKey.PublicKey)
		encryptionID, _ := protocol.TaskPublicKeyID(&encryptionKey.PublicKey)
		if _, err := pool.ExecContext(ctx, `INSERT INTO dbo.agent_encryption_keys(key_id,machine_id,registration_id,public_key_pem,algorithm,bits,active,created_at) VALUES(@p1,@p2,@p3,@p4,N'RSA-OAEP-SHA256+AES-256-GCM',3072,1,SYSUTCDATETIME())`, encryptionID, machineID, registrationID, encryptionPEM); err != nil {
			t.Fatal(err)
		}
		reportID := protocol.NewUUID()
		if _, err := pool.ExecContext(ctx, `
INSERT INTO dbo.reports(report_id,machine_id,registration_id,scan_seq,collected_at,received_at,status,applied,applied_sources,payload_sha256,payload_json,profiles_complete,personal_complete)
VALUES(@p1,@p2,@p3,1,SYSUTCDATETIME(),SYSUTCDATETIME(),N'complete',0,0,REPLICATE('a',64),N'{"profiles_complete":true,"sources":[{"source_type":"user_store","complete":true}]}',1,1)`,
			reportID, machineID, registrationID); err != nil {
			t.Fatal(err)
		}
		if _, err := pool.ExecContext(ctx, `
INSERT INTO dbo.csp_states(machine_id,scanned,complete,present,product_version,core_version,environment,license_kind,license_kind_raw,license_kind_source,license_state,time_basis,term_kind,is_trial,source,products_json,last_report_id,last_scan_seq,collected_at,updated_at,last_attempt_at)
VALUES(@p1,1,1,1,N'5.0.13003',N'5.0',N'workstation',N'unknown',N'',N'CPCSPLicense',N'not_installed',N'',N'unknown',N'unknown',N'CPCSPLicense',N'[]',@p2,1,SYSUTCDATETIME(),SYSUTCDATETIME(),SYSUTCDATETIME())`,
			machineID, reportID); err != nil {
			t.Fatal(err)
		}
		certSHA := strings.ReplaceAll(protocol.NewUUID(), "-", "") + strings.Repeat("0", 32)
		if _, err := pool.ExecContext(ctx, `
INSERT INTO dbo.certificates(sha256,der,serial_hex,serial_number,subject,issuer,embedded_license,not_before,not_after,created_at,updated_at)
VALUES(@p1,0x30,N'01',N'1',N'CN=test',N'CN=ca',N'absent',DATEADD(day,-1,SYSUTCDATETIME()),DATEADD(day,30,SYSUTCDATETIME()),SYSUTCDATETIME(),SYSUTCDATETIME())`, certSHA); err != nil {
			t.Fatal(err)
		}
		var observationID int64
		if err := pool.QueryRowContext(ctx, `
INSERT INTO dbo.certificate_observations(machine_id,source_type,source_key,source_scope_hash,observation_key_hash,certificate_sha256,active,first_seen_at,last_seen_at,last_report_id,last_scan_seq)
OUTPUT INSERTED.observation_id
VALUES(@p1,N'user_store',@p2,HASHBYTES('SHA2_256',CONCAT(N'user_store',CHAR(0),@p2)),HASHBYTES('SHA2_256',CONCAT(N'user_store',CHAR(0),@p2)),@p3,1,SYSUTCDATETIME(),SYSUTCDATETIME(),@p4,1)`,
			machineID, sid, certSHA, reportID).Scan(&observationID); err != nil {
			t.Fatal(err)
		}
		if _, err := pool.ExecContext(ctx, `INSERT INTO dbo.certificate_observation_bindings(observation_id,binding_index,provider_name,provider_api,provider_type,key_spec,binding_state,provider_owner,attribution_source,attribution_version,private_key_state,observed_at) VALUES(@p1,0,N'Crypto-Pro GOST R 34.10-2012 Cryptographic Service Provider',N'capi',80,1,N'present',N'cryptopro',N'test',N'1',N'not_checked',SYSUTCDATETIME())`, observationID); err != nil {
			t.Fatal(err)
		}
		fixture.machineIDs = append(fixture.machineIDs, machineID)
		fixture.regIDs = append(fixture.regIDs, registrationID)
		fixture.sids = append(fixture.sids, sid)
		fixture.certSHAs = append(fixture.certSHAs, certSHA)
		fixture.reportIDs = append(fixture.reportIDs, reportID)
	}
	poolResult, apiErr := s.CreatePool(ctx, PoolInput{Name: "TASK-TEST-" + protocol.NewUUID()[:8], CSPMajorVersion: 5, LicenseKind: protocol.PoolKindClient, Term: protocol.PoolTermPerpetual}, "test")
	if apiErr != nil {
		t.Fatal(apiErr)
	}
	fixture.poolID = poolResult.ID
	fixture.cleanupFunc = func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		machineLike := "%" + fixture.machineIDs[0] + "%"
		_, _ = pool.ExecContext(cleanupCtx, `DELETE j FROM dbo.jobs j JOIN dbo.tasks t ON t.task_id=j.task_id WHERE t.selection_snapshot LIKE @p1 OR t.selection_snapshot LIKE @p2`, "%"+fixture.poolID+"%", machineLike)
		_, _ = pool.ExecContext(cleanupCtx, `DELETE e FROM dbo.task_item_events e JOIN dbo.task_items i ON i.item_id=e.item_id JOIN dbo.tasks t ON t.task_id=i.task_id WHERE t.selection_snapshot LIKE @p1 OR t.selection_snapshot LIKE @p2`, "%"+fixture.poolID+"%", machineLike)
		_, _ = pool.ExecContext(cleanupCtx, `DELETE i FROM dbo.task_items i JOIN dbo.tasks t ON t.task_id=i.task_id WHERE t.selection_snapshot LIKE @p1 OR t.selection_snapshot LIKE @p2`, "%"+fixture.poolID+"%", machineLike)
		_, _ = pool.ExecContext(cleanupCtx, `DELETE FROM dbo.tasks WHERE selection_snapshot LIKE @p1 OR selection_snapshot LIKE @p2`, "%"+fixture.poolID+"%", machineLike)
		_, _ = pool.ExecContext(cleanupCtx, `DELETE FROM dbo.previews WHERE pool_id=@p1`, fixture.poolID)
		_, _ = pool.ExecContext(cleanupCtx, `DELETE FROM dbo.license_events WHERE pool_id=@p1 OR license_id IN (SELECT license_id FROM dbo.licenses WHERE pool_id=@p1)`, fixture.poolID)
		_, _ = pool.ExecContext(cleanupCtx, `DELETE FROM dbo.license_assignments WHERE license_id IN (SELECT license_id FROM dbo.licenses WHERE pool_id=@p1)`, fixture.poolID)
		_, _ = pool.ExecContext(cleanupCtx, `DELETE FROM dbo.licenses WHERE pool_id=@p1`, fixture.poolID)
		_, _ = pool.ExecContext(cleanupCtx, `DELETE FROM dbo.license_pools WHERE pool_id=@p1`, fixture.poolID)
		for i, machineID := range fixture.machineIDs {
			_, _ = pool.ExecContext(cleanupCtx, `DELETE FROM dbo.certificate_observation_bindings WHERE observation_id IN (SELECT observation_id FROM dbo.certificate_observations WHERE machine_id=@p1)`, machineID)
			_, _ = pool.ExecContext(cleanupCtx, `DELETE FROM dbo.certificate_observations WHERE machine_id=@p1`, machineID)
			_, _ = pool.ExecContext(cleanupCtx, `DELETE FROM dbo.machine_user_certificates WHERE machine_user_id IN (SELECT machine_user_id FROM dbo.machine_users WHERE machine_id=@p1)`, machineID)
			_, _ = pool.ExecContext(cleanupCtx, `DELETE FROM dbo.machine_users WHERE machine_id=@p1`, machineID)
			_, _ = pool.ExecContext(cleanupCtx, `DELETE FROM dbo.source_states WHERE machine_id=@p1`, machineID)
			_, _ = pool.ExecContext(cleanupCtx, `DELETE FROM dbo.csp_states WHERE machine_id=@p1`, machineID)
			_, _ = pool.ExecContext(cleanupCtx, `DELETE FROM dbo.reports WHERE machine_id=@p1`, machineID)
			_, _ = pool.ExecContext(cleanupCtx, `DELETE FROM dbo.events WHERE machine_id=@p1`, machineID)
			_, _ = pool.ExecContext(cleanupCtx, `DELETE FROM dbo.agent_encryption_keys WHERE machine_id=@p1`, machineID)
			_, _ = pool.ExecContext(cleanupCtx, `DELETE FROM dbo.agent_capabilities WHERE registration_id IN (SELECT registration_id FROM dbo.registrations WHERE machine_id=@p1)`, machineID)
			_, _ = pool.ExecContext(cleanupCtx, `DELETE FROM dbo.registrations WHERE machine_id=@p1`, machineID)
			_, _ = pool.ExecContext(cleanupCtx, `DELETE FROM dbo.certificates WHERE sha256=@p1`, fixture.certSHAs[i])
			_, _ = pool.ExecContext(cleanupCtx, `DELETE FROM dbo.machines WHERE machine_id=@p1`, machineID)
		}
	}
	serials := make([]string, licenseCount)
	for i := range serials {
		serials[i] = fmt.Sprintf("123456789012345678901%04d", i+1)
	}
	importResult, apiErr := s.ImportLicenses(ctx, fixture.poolID, serials, "test")
	if apiErr != nil || !importResult.Accepted {
		t.Fatalf("import: %v %+v", apiErr, importResult)
	}

	return fixture
}

func stringsLower(value string) string {
	return strings.ToLower(value)
}
