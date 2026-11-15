package store

import (
	"context"
	"crypto/ecdsa"
	"database/sql"
	"encoding/json"
	"net"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	mssql "github.com/microsoft/go-mssqldb"
	"mandatnik/internal/backend/config"
	"mandatnik/internal/backend/db"
	"mandatnik/internal/protocol"
)

type installationFixture struct {
	s          *Store
	pool       *sql.DB
	ctx        context.Context
	hostname   string
	machineID  string
	regID      int64
	uuid       string
	key        *protocol.SignedData
	publicPEM  string
	groupName  string
	policyName string
	uuids      []string
	machineIDs []string
	cleanup    func()
}

func newInstallationFixture(t *testing.T, ctx context.Context, pool *sql.DB, s *Store) *installationFixture {
	t.Helper()
	f := &installationFixture{s: s, pool: pool, ctx: ctx}
	suffix := strings.ReplaceAll(protocol.NewUUID(), "-", "")[:10]
	f.hostname = "INSTALL-TEST-" + strings.ToUpper(suffix)
	f.groupName = "INSTALL-GROUP-" + suffix
	f.policyName = "INSTALL-POLICY-" + suffix
	key, err := protocol.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	f.uuid = protocol.NewUUID()
	f.uuids = append(f.uuids, f.uuid)
	request := testRegisterRequest(t, f.uuid, f.hostname, &key.PublicKey, "0.5.0-test")
	result, apiErr := s.Register(ctx, request, net.ParseIP("192.0.2.10"), "verified")
	if apiErr != nil {
		t.Fatalf("initial register: %v", apiErr)
	}
	f.machineID = result.MachineID
	f.machineIDs = append(f.machineIDs, result.MachineID)
	if _, regID, err := s.MachineByUUID(ctx, f.uuid); err != nil {
		t.Fatal(err)
	} else {
		f.regID = regID
	}
	if _, err := pool.ExecContext(ctx, `INSERT INTO dbo.machine_groups(group_id,name) VALUES(@p1,@p2)`, protocol.NewUUID(), f.groupName); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.ExecContext(ctx, `
INSERT INTO dbo.machine_group_members(group_id,machine_id)
SELECT group_id,@p1 FROM dbo.machine_groups WHERE name=@p2`, f.machineID, f.groupName); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.ExecContext(ctx, `INSERT INTO dbo.folder_policies(policy_id,name,rules) VALUES(@p1,@p2,N'C:/Certs')`, protocol.NewUUID(), f.policyName); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.ExecContext(ctx, `
INSERT INTO dbo.folder_policy_machines(policy_id,machine_id)
SELECT policy_id,@p1 FROM dbo.folder_policies WHERE name=@p2`, f.machineID, f.policyName); err != nil {
		t.Fatal(err)
	}
	oldReport := protocol.NewUUID()
	if _, err := pool.ExecContext(ctx, `
INSERT INTO dbo.reports(report_id,machine_id,registration_id,scan_epoch,scan_seq,collected_at,received_at,status,applied,applied_sources,payload_sha256,payload_json,profiles_complete,personal_complete)
VALUES(@p1,@p2,@p3,0,50,SYSUTCDATETIME(),SYSUTCDATETIME(),N'complete',1,1,REPLICATE('a',64),N'{}',1,1)`,
		oldReport, f.machineID, f.regID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.ExecContext(ctx, `
INSERT INTO dbo.source_states(machine_id,source_type,source_key,source_key_hash,last_scan_seq,last_report_id,last_complete,last_collected_at,updated_at,last_scan_epoch)
VALUES(@p1,N'user_store',N'S-1-5-21-100-200-300-1001',@p3,50,@p2,1,SYSUTCDATETIME(),SYSUTCDATETIME(),0)`,
		f.machineID, oldReport, scopeHash("user_store", "S-1-5-21-100-200-300-1001")); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.ExecContext(ctx, `
INSERT INTO dbo.csp_states(machine_id,scanned,complete,present,license_kind,license_kind_raw,license_kind_source,license_state,
 time_basis,term_kind,is_trial,source,products_json,last_scan_seq,last_scan_epoch,collected_at,updated_at,last_attempt_at)
VALUES(@p1,1,1,0,N'unknown',N'',N'test',N'not_installed',N'',N'unknown',N'unknown',N'test',N'[]',50,0,SYSUTCDATETIME(),SYSUTCDATETIME(),SYSUTCDATETIME())`,
		f.machineID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.ExecContext(ctx, `
INSERT INTO dbo.agent_capabilities(registration_id,capabilities_json,schedule_v2,tasks_v1,install_v1,updated_at)
VALUES(@p1,N'["task_v1"]',1,1,1,SYSUTCDATETIME())`, f.regID); err != nil {
		t.Fatal(err)
	}
	encKey, err := protocol.GenerateTaskEncryptionKey()
	if err != nil {
		t.Fatal(err)
	}
	encPEM, _ := protocol.MarshalTaskPublicKeyPEM(&encKey.PublicKey)
	encID, _ := protocol.TaskPublicKeyID(&encKey.PublicKey)
	if _, err := pool.ExecContext(ctx, `
INSERT INTO dbo.agent_encryption_keys(key_id,machine_id,registration_id,public_key_pem,algorithm,bits,active,created_at)
VALUES(@p1,@p2,@p3,@p4,N'RSA-OAEP-SHA256+AES-256-GCM',3072,1,SYSUTCDATETIME())`,
		encID, f.machineID, f.regID, encPEM); err != nil {
		t.Fatal(err)
	}
	f.cleanup = func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
		defer cancel()
		cleanup := func(query string, args ...any) {
			if _, err := pool.ExecContext(cleanupCtx, query, args...); err != nil {
				t.Logf("installation fixture cleanup: %v", err)
			}
		}
		for _, uuid := range f.uuids {
			cleanup(`DELETE FROM dbo.agent_install_requests WHERE uuid=@p1`, uuid)
			cleanup(`DELETE FROM dbo.request_ids WHERE identity_uuid=@p1`, uuid)
		}
		for _, machineID := range f.machineIDs {
			cleanup(`DELETE FROM dbo.agent_install_requests WHERE resolved_machine_id=@p1`, machineID)
			cleanup(`DELETE FROM dbo.jobs WHERE machine_id=@p1`, machineID)
			cleanup(`DELETE FROM dbo.task_item_events WHERE item_id IN (SELECT item_id FROM dbo.task_items WHERE machine_id=@p1)`, machineID)
			cleanup(`DELETE FROM dbo.task_items WHERE machine_id=@p1`, machineID)
			cleanup(`DELETE t FROM dbo.tasks t WHERE NOT EXISTS (SELECT 1 FROM dbo.task_items i WHERE i.task_id=t.task_id) AND (t.selection_snapshot LIKE N'%'+@p1+N'%' OR t.selection_snapshot=N'{"test":"install"}')`, machineID)
			cleanup(`DELETE FROM dbo.hostnames WHERE owner_machine_id=@p1`, machineID)
			cleanup(`DELETE FROM dbo.certificate_observation_bindings WHERE observation_id IN (SELECT observation_id FROM dbo.certificate_observations WHERE machine_id=@p1)`, machineID)
			cleanup(`DELETE FROM dbo.certificate_observations WHERE machine_id=@p1`, machineID)
			cleanup(`DELETE FROM dbo.machine_user_certificates WHERE machine_user_id IN (SELECT machine_user_id FROM dbo.machine_users WHERE machine_id=@p1)`, machineID)
			cleanup(`DELETE FROM dbo.machine_users WHERE machine_id=@p1`, machineID)
			cleanup(`DELETE FROM dbo.source_states WHERE machine_id=@p1`, machineID)
			cleanup(`DELETE FROM dbo.csp_states WHERE machine_id=@p1`, machineID)
			cleanup(`DELETE FROM dbo.events WHERE machine_id=@p1`, machineID)
			cleanup(`DELETE FROM dbo.reports WHERE machine_id=@p1`, machineID)
			cleanup(`DELETE FROM dbo.agent_capabilities WHERE registration_id IN (SELECT registration_id FROM dbo.registrations WHERE machine_id=@p1)`, machineID)
			cleanup(`DELETE FROM dbo.agent_encryption_keys WHERE machine_id=@p1`, machineID)
			cleanup(`DELETE FROM dbo.machine_group_members WHERE machine_id=@p1`, machineID)
			cleanup(`DELETE FROM dbo.folder_policy_machines WHERE machine_id=@p1`, machineID)
			cleanup(`DELETE FROM dbo.registrations WHERE machine_id=@p1`, machineID)
			cleanup(`DELETE FROM dbo.machines WHERE machine_id=@p1`, machineID)
		}
		cleanup(`DELETE FROM dbo.machine_groups WHERE name=@p1`, f.groupName)
		cleanup(`DELETE FROM dbo.folder_policies WHERE name=@p1`, f.policyName)
	}
	t.Cleanup(f.cleanup)
	return f
}

func testRegisterRequest(t *testing.T, uuid, hostname string, pub *ecdsa.PublicKey, agentVersion string) *protocol.SignedRequest {
	t.Helper()
	return &protocol.SignedRequest{Data: protocol.SignedData{
		ProtocolVersion: protocol.ProtocolVersion, Operation: protocol.OpRegister,
		RequestID: protocol.NewUUID(), UUID: uuid, Hostname: hostname,
		Method: protocol.MethodPost, Path: protocol.PathRegister,
		IssuedAt: time.Now().UTC().Format(time.RFC3339Nano), AgentVersion: agentVersion,
		OSVersion: "Windows 10 22H2", Architecture: "amd64", PublicKey: testPublicPEM(t, pub),
	}}
}

func testPublicPEM(t *testing.T, pub *ecdsa.PublicKey) string {
	t.Helper()
	pem, err := protocol.MarshalPublicKeyPEM(pub)
	if err != nil {
		t.Fatal(err)
	}
	return pem
}

func (f *installationFixture) newPending(t *testing.T, key *ecdsa.PrivateKey, uuid string, agentVersion string) PendingInstallation {
	t.Helper()
	f.uuids = append(f.uuids, uuid)
	request := &protocol.SignedRequest{Data: protocol.SignedData{
		ProtocolVersion: protocol.ProtocolVersion, Operation: protocol.OpRegister,
		RequestID: protocol.NewUUID(), UUID: uuid, Hostname: f.hostname,
		Method: protocol.MethodPost, Path: protocol.PathRegister,
		IssuedAt: time.Now().UTC().Format(time.RFC3339Nano), AgentVersion: agentVersion,
		OSVersion: "Windows 10 22H2", Architecture: "amd64", PublicKey: testPublicPEM(t, &key.PublicKey),
	}}
	_, apiErr := f.s.Register(f.ctx, request, net.ParseIP("192.0.2.20"), "mismatch")
	if apiErr == nil || apiErr.Code != protocol.CodeInstallationPending {
		t.Fatalf("pending register error = %v", apiErr)
	}
	items, err := f.s.ListInstallations(f.ctx, "pending")
	if err != nil {
		t.Fatal(err)
	}
	for _, item := range items {
		if strings.EqualFold(item.Hostname, f.hostname) && strings.EqualFold(item.UUID, uuid) {
			return item
		}
	}
	t.Fatalf("pending installation %s for %s not found", uuid, f.hostname)
	return PendingInstallation{}
}

func TestInstallationReplacementSQLServer(t *testing.T) {
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
	ctx, cancel := context.WithTimeout(context.Background(), 180*time.Second)
	defer cancel()
	pool, err := db.Open(ctx, cfg.DB)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pool.Close() })
	if err = db.Migrate(ctx, pool, t.Logf); err != nil {
		t.Fatal(err)
	}
	s := New(pool)

	t.Run("pending request, key conflict and stale confirmation", func(t *testing.T) {
		f := newInstallationFixture(t, ctx, pool, s)
		key, err := protocol.GenerateKey()
		if err != nil {
			t.Fatal(err)
		}
		newUUID := protocol.NewUUID()
		pending := f.newPending(t, key, newUUID, "0.5.0-test")
		if pending.RequestVersion == 0 || pending.KeyFingerprint == "" {
			t.Fatalf("pending request has no version/fingerprint: %+v", pending)
		}
		var machines int
		if err := pool.QueryRowContext(ctx, `SELECT COUNT(1) FROM dbo.machines WHERE LOWER(display_name)=@p1`, strings.ToLower(f.hostname)).Scan(&machines); err != nil {
			t.Fatal(err)
		}
		if machines != 1 {
			t.Fatalf("pending registration created %d machine cards, want 1", machines)
		}
		if len(pending.Candidates) != 1 || pending.Candidates[0].MachineID != f.machineID {
			t.Fatalf("candidates = %+v, want target %s", pending.Candidates, f.machineID)
		}
		if pending.Candidates[0].ActiveRegistration == nil || pending.Candidates[0].ActiveRegistration.RegistrationID != f.regID {
			t.Fatalf("active candidate registration = %+v", pending.Candidates[0].ActiveRegistration)
		}
		if pending.LastSeenAt.IsZero() || pending.SourceIP != "192.0.2.20" || pending.DNSStatus != "mismatch" {
			t.Fatalf("pending metadata incomplete: %+v", pending)
		}

		// Repeated contact from the same installation updates one request and
		// does not create a second pending row.
		again := f.newPending(t, key, newUUID, "0.5.0-test")
		if again.RequestID != pending.RequestID || again.RequestVersion != pending.RequestVersion {
			t.Fatalf("repeat contact changed request: first=%+v second=%+v", pending, again)
		}
		var requestCount int
		if err := pool.QueryRowContext(ctx, `SELECT COUNT(1) FROM dbo.agent_install_requests WHERE uuid=@p1`, newUUID).Scan(&requestCount); err != nil {
			t.Fatal(err)
		}
		if requestCount != 1 {
			t.Fatalf("pending request count = %d, want 1", requestCount)
		}

		// A changed key for the same UUID must not silently mutate the request.
		other, err := protocol.GenerateKey()
		if err != nil {
			t.Fatal(err)
		}
		changed := &protocol.SignedRequest{Data: protocol.SignedData{
			ProtocolVersion: protocol.ProtocolVersion, Operation: protocol.OpRegister,
			RequestID: protocol.NewUUID(), UUID: newUUID, Hostname: f.hostname,
			Method: protocol.MethodPost, Path: protocol.PathRegister,
			IssuedAt: time.Now().UTC().Format(time.RFC3339Nano), AgentVersion: "0.5.0-test",
			OSVersion: "Windows 10 22H2", Architecture: "amd64", PublicKey: testPublicPEM(t, &other.PublicKey),
		}}
		if _, apiErr := s.Register(ctx, changed, net.ParseIP("192.0.2.20"), "mismatch"); apiErr == nil || apiErr.Code != protocol.CodeKeyConflict {
			t.Fatalf("changed key error = %v, want key_conflict", apiErr)
		}
		var fingerprint string
		if err := pool.QueryRowContext(ctx, `SELECT public_key_sha256 FROM dbo.agent_install_requests WHERE uuid=@p1`, newUUID).Scan(&fingerprint); err != nil {
			t.Fatal(err)
		}
		if !strings.EqualFold(fingerprint, pending.KeyFingerprint) {
			t.Fatalf("pending fingerprint changed silently: %s -> %s", pending.KeyFingerprint, fingerprint)
		}

		// Changing displayed metadata bumps the request version. A decision
		// prepared against the previous version must be rejected.
		f.newPending(t, key, newUUID, "0.5.0-test-updated")
		if _, apiErr := s.ReplaceInstallation(ctx, InstallationDecisionInput{
			RequestID: pending.RequestID, RequestVersion: pending.RequestVersion,
			KeyFingerprint: pending.KeyFingerprint, MachineID: f.machineID, OldRegistrationID: f.regID,
		}, "admin@test"); apiErr == nil || apiErr.Code != protocol.CodeInstallationStale {
			t.Fatalf("stale replacement error = %v, want installation_stale", apiErr)
		}

		// Rejection is final for this request and cannot be approved later.
		current := f.newPending(t, key, newUUID, "0.5.0-test-updated")
		if _, apiErr := s.RejectInstallation(ctx, InstallationDecisionInput{
			RequestID: current.RequestID, RequestVersion: current.RequestVersion,
			KeyFingerprint: current.KeyFingerprint, Reason: "test rejection",
		}, "admin@test"); apiErr != nil {
			t.Fatalf("reject: %v", apiErr)
		}
		if _, apiErr := s.ReplaceInstallation(ctx, InstallationDecisionInput{
			RequestID: current.RequestID, RequestVersion: current.RequestVersion,
			KeyFingerprint: current.KeyFingerprint, MachineID: f.machineID, OldRegistrationID: f.regID,
		}, "admin@test"); apiErr == nil {
			t.Fatal("rejected request was approved by a stale confirmation")
		}
		rejected := f.newPendingKey(t, key, newUUID, "0.5.0-test-updated")
		if rejected.Code != protocol.CodeInstallationRejected {
			t.Fatalf("re-register after rejection = %v, want installation_rejected", rejected.Error())
		}
		// Rejection must remain final even if the old name later becomes free.
		// Otherwise a rejected installation could auto-register as a new card.
		newName := f.hostname + "-RENAMED"
		if _, err := pool.ExecContext(ctx, `DELETE FROM dbo.hostnames WHERE hostname_norm=@p1`, strings.ToLower(f.hostname)); err != nil {
			t.Fatal(err)
		}
		if _, err := pool.ExecContext(ctx, `UPDATE dbo.machines SET display_name=@p1 WHERE machine_id=@p2`, newName, f.machineID); err != nil {
			t.Fatal(err)
		}
		if _, err := pool.ExecContext(ctx, `UPDATE dbo.registrations SET hostname=@p1,hostname_norm=@p2 WHERE machine_id=@p3`, newName, strings.ToLower(newName), f.machineID); err != nil {
			t.Fatal(err)
		}
		rejectedAfterRename := f.newPendingKey(t, key, newUUID, "0.5.0-test-updated")
		if rejectedAfterRename.Code != protocol.CodeInstallationRejected {
			t.Fatalf("rejected request auto-registered after the name became free: %v", rejectedAfterRename)
		}
	})

	t.Run("replacement preserves machine and starts a new scan epoch", func(t *testing.T) {
		f := newInstallationFixture(t, ctx, pool, s)
		jobQueued, err := s.AddJob(ctx, f.machineID, "test")
		if err != nil {
			t.Fatal(err)
		}
		jobStarted, err := s.AddJob(ctx, f.machineID, "test")
		if err != nil {
			t.Fatal(err)
		}
		var startedItem mssql.UniqueIdentifier
		if err := pool.QueryRowContext(ctx, `SELECT task_item_id FROM dbo.jobs WHERE job_id=@p1`, jobStarted).Scan(&startedItem); err != nil {
			t.Fatal(err)
		}
		if _, err := pool.ExecContext(ctx, `UPDATE dbo.jobs SET state=N'delivered',delivered_at=SYSUTCDATETIME() WHERE job_id=@p1`, jobStarted); err != nil {
			t.Fatal(err)
		}
		if _, err := pool.ExecContext(ctx, `UPDATE dbo.task_items SET state=N'running',started_at=SYSUTCDATETIME(),attempt_count=1 WHERE item_id=@p1`, uuidString(startedItem)); err != nil {
			t.Fatal(err)
		}
		installTask := protocol.NewUUID()
		installItem := protocol.NewUUID()
		if _, err := pool.ExecContext(ctx, `
INSERT INTO dbo.tasks(task_id,kind,created_by,created_at,expires_at,settings_snapshot,selection_snapshot)
VALUES(@p1,N'install_license',N'test',SYSUTCDATETIME(),DATEADD(day,1,SYSUTCDATETIME()),N'{}',N'{"test":"install"}')`, installTask); err != nil {
			t.Fatal(err)
		}
		if _, err := pool.ExecContext(ctx, `
INSERT INTO dbo.task_items(item_id,task_id,machine_id,registration_id,kind,state,delivery_version,attempt_count,started_at,created_at,updated_at)
VALUES(@p1,@p2,@p3,@p4,N'install_license',N'running',1,1,SYSUTCDATETIME(),SYSUTCDATETIME(),SYSUTCDATETIME())`,
			installItem, installTask, f.machineID, f.regID); err != nil {
			t.Fatal(err)
		}

		key, err := protocol.GenerateKey()
		if err != nil {
			t.Fatal(err)
		}
		newUUID := protocol.NewUUID()
		pending := f.newPending(t, key, newUUID, "0.5.0-test")
		result, apiErr := s.ReplaceInstallation(ctx, InstallationDecisionInput{
			RequestID: pending.RequestID, RequestVersion: pending.RequestVersion,
			KeyFingerprint: pending.KeyFingerprint, MachineID: f.machineID, OldRegistrationID: f.regID,
			Reason: "reinstall",
		}, "admin@test")
		if apiErr != nil {
			t.Fatalf("replace: %v", apiErr)
		}
		if result.MachineID != f.machineID || result.Duplicate {
			t.Fatalf("replace result = %+v", result)
		}
		var oldState, newState string
		var newRegID int64
		if err := pool.QueryRowContext(ctx, `SELECT state FROM dbo.registrations WHERE registration_id=@p1`, f.regID).Scan(&oldState); err != nil {
			t.Fatal(err)
		}
		if err := pool.QueryRowContext(ctx, `SELECT registration_id,state FROM dbo.registrations WHERE uuid=@p1`, newUUID).Scan(&newRegID, &newState); err != nil {
			t.Fatal(err)
		}
		if oldState != "replaced" || newState != "active" {
			t.Fatalf("registration states old=%s new=%s", oldState, newState)
		}
		var active int
		if err := pool.QueryRowContext(ctx, `SELECT COUNT(1) FROM dbo.registrations WHERE machine_id=@p1 AND state=N'active'`, f.machineID).Scan(&active); err != nil {
			t.Fatal(err)
		}
		if active != 1 {
			t.Fatalf("active registration count = %d, want 1", active)
		}
		var hostnameOwner int64
		if err := pool.QueryRowContext(ctx, `SELECT owner_registration_id FROM dbo.hostnames WHERE hostname_norm=@p1`, strings.ToLower(f.hostname)).Scan(&hostnameOwner); err != nil {
			t.Fatal(err)
		}
		if hostnameOwner != newRegID {
			t.Fatalf("hostname owner = %d, want replacement registration %d", hostnameOwner, newRegID)
		}
		var groups, policies, reports int
		_ = pool.QueryRowContext(ctx, `SELECT COUNT(1) FROM dbo.machine_group_members gm JOIN dbo.machine_groups g ON g.group_id=gm.group_id WHERE gm.machine_id=@p1 AND g.name=@p2`, f.machineID, f.groupName).Scan(&groups)
		_ = pool.QueryRowContext(ctx, `SELECT COUNT(1) FROM dbo.folder_policy_machines pm JOIN dbo.folder_policies p ON p.policy_id=pm.policy_id WHERE pm.machine_id=@p1 AND p.name=@p2`, f.machineID, f.policyName).Scan(&policies)
		_ = pool.QueryRowContext(ctx, `SELECT COUNT(1) FROM dbo.reports WHERE machine_id=@p1`, f.machineID).Scan(&reports)
		if groups != 1 || policies != 1 || reports != 1 {
			t.Fatalf("history after replacement groups=%d policies=%d reports=%d", groups, policies, reports)
		}
		var caps, activeKeys int
		_ = pool.QueryRowContext(ctx, `SELECT COUNT(1) FROM dbo.agent_capabilities WHERE registration_id=@p1`, newRegID).Scan(&caps)
		_ = pool.QueryRowContext(ctx, `SELECT COUNT(1) FROM dbo.agent_encryption_keys WHERE machine_id=@p1 AND active=1 AND revoked_at IS NULL`, f.machineID).Scan(&activeKeys)
		if caps != 0 || activeKeys != 0 {
			t.Fatalf("old capabilities/keys followed replacement: caps=%d keys=%d", caps, activeKeys)
		}
		var oldTaskState, startedTaskState, installState string
		if err := pool.QueryRowContext(ctx, `
SELECT ti.state FROM dbo.task_items ti JOIN dbo.jobs j ON j.task_item_id=ti.item_id WHERE j.job_id=@p1`, jobQueued).Scan(&oldTaskState); err != nil {
			t.Fatal(err)
		}
		if err := pool.QueryRowContext(ctx, `SELECT state FROM dbo.task_items WHERE item_id=@p1`, uuidString(startedItem)).Scan(&startedTaskState); err != nil {
			t.Fatal(err)
		}
		if err := pool.QueryRowContext(ctx, `SELECT state FROM dbo.task_items WHERE item_id=@p1`, installItem).Scan(&installState); err != nil {
			t.Fatal(err)
		}
		if oldTaskState != protocol.TaskStateExpired || startedTaskState != protocol.TaskStateFailed || installState != protocol.TaskStateOutcomeUnknown {
			t.Fatalf("old task policy: queued=%s started=%s install=%s", oldTaskState, startedTaskState, installState)
		}
		var oldJobState, startedJobState string
		_ = pool.QueryRowContext(ctx, `SELECT state FROM dbo.jobs WHERE job_id=@p1`, jobQueued).Scan(&oldJobState)
		_ = pool.QueryRowContext(ctx, `SELECT state FROM dbo.jobs WHERE job_id=@p1`, jobStarted).Scan(&startedJobState)
		if oldJobState != "canceled" || startedJobState != "failed" {
			t.Fatalf("legacy job states queued=%s started=%s", oldJobState, startedJobState)
		}

		identity, apiErr := s.LookupActiveIdentity(ctx, newUUID)
		if apiErr != nil {
			t.Fatalf("lookup new identity: %v", apiErr)
		}
		if identity.MachineID != f.machineID || identity.ScanEpoch != 1 {
			t.Fatalf("new identity machine=%s epoch=%d", identity.MachineID, identity.ScanEpoch)
		}
		if _, apiErr := s.LookupActiveIdentity(ctx, f.uuid); apiErr == nil {
			t.Fatal("old installation still authenticates after replacement")
		}

		// A renewed registration returns the existing card and configuration.
		renewed := &protocol.SignedRequest{Data: protocol.SignedData{
			ProtocolVersion: protocol.ProtocolVersion, Operation: protocol.OpRegister,
			RequestID: protocol.NewUUID(), UUID: newUUID, Hostname: f.hostname,
			Method: protocol.MethodPost, Path: protocol.PathRegister,
			IssuedAt: time.Now().UTC().Format(time.RFC3339Nano), AgentVersion: "0.5.0-test",
			OSVersion: "Windows 10 22H2", Architecture: "amd64", PublicKey: testPublicPEM(t, &key.PublicKey),
		}}
		registered, apiErr := s.Register(ctx, renewed, net.ParseIP("192.0.2.20"), "verified")
		if apiErr != nil {
			t.Fatalf("renewed register: %v", apiErr)
		}
		if registered.MachineID != f.machineID {
			t.Fatalf("renewed machine id = %s, want %s", registered.MachineID, f.machineID)
		}

		// A fresh installation may restart scan_seq at 1. The epoch keeps it
		// newer than the historical report with seq 50.
		collected := time.Now().UTC().Format(time.RFC3339Nano)
		report := protocol.Report{
			ReportID: protocol.NewUUID(), ScanSeq: 1, CollectedAt: collected, StartedAt: collected, FinishedAt: collected,
			AgentVersion: "0.5.0-test", Hostname: f.hostname, Status: "complete", ProfilesComplete: true,
			Profiles: []protocol.ProfileResult{{SID: "S-1-5-21-100-200-300-1001", Name: "test", Complete: true, StorePresent: true}},
			Sources:  []protocol.SourceResult{{SourceType: "user_store", SourceKey: "S-1-5-21-100-200-300-1001", UserSID: "S-1-5-21-100-200-300-1001", Complete: true, Certificates: []protocol.ObservedCertificate{}}},
			CSP:      protocol.CSPResult{Scanned: true, Complete: true, Present: false, Licenses: []protocol.LicenseInfo{}},
		}
		rawReport, _ := json.Marshal(report)
		seq := int64(1)
		reportResponse, apiErr := s.SubmitReport(ctx, identity, &protocol.SignedRequest{Data: protocol.SignedData{
			RequestID: protocol.NewUUID(), ReportID: report.ReportID, ScanSeq: &seq, CollectedAt: collected, Report: rawReport,
		}}, net.ParseIP("192.0.2.20"), "verified")
		if apiErr != nil {
			t.Fatalf("new report: %v", apiErr)
		}
		if !reportResponse.Accepted || !reportResponse.Applied {
			t.Fatalf("new scan epoch report not applied: %+v", reportResponse)
		}
		var sourceEpoch, cspEpoch int
		var sourceSeq, cspSeq int64
		_ = pool.QueryRowContext(ctx, `SELECT last_scan_epoch,last_scan_seq FROM dbo.source_states WHERE machine_id=@p1 AND source_key_hash=@p2`, f.machineID, scopeHash("user_store", "S-1-5-21-100-200-300-1001")).Scan(&sourceEpoch, &sourceSeq)
		_ = pool.QueryRowContext(ctx, `SELECT last_scan_epoch,last_scan_seq FROM dbo.csp_states WHERE machine_id=@p1`, f.machineID).Scan(&cspEpoch, &cspSeq)
		if sourceEpoch != 1 || sourceSeq != 1 || cspEpoch != 1 || cspSeq != 1 {
			t.Fatalf("new ordering source=%d/%d csp=%d/%d", sourceEpoch, sourceSeq, cspEpoch, cspSeq)
		}
		detail, err := s.MachineDetail(ctx, f.machineID)
		if err != nil {
			t.Fatal(err)
		}
		if len(detail.Reports) < 2 || detail.Reports[0].ScanEpoch != 1 || detail.Reports[0].ScanSeq != 1 {
			t.Fatalf("latest report selection = %+v", detail.Reports)
		}
		for _, source := range detail.Sources {
			if source.Stale {
				t.Fatalf("source %s marked stale after new installation report", source.SourceKey)
			}
		}

		// Repeating the exact confirmation is idempotent.
		duplicate, apiErr := s.ReplaceInstallation(ctx, InstallationDecisionInput{
			RequestID: pending.RequestID, RequestVersion: pending.RequestVersion,
			KeyFingerprint: pending.KeyFingerprint, MachineID: f.machineID, OldRegistrationID: f.regID,
		}, "admin@test")
		if apiErr != nil {
			t.Fatalf("repeat replace: %v", apiErr)
		}
		if !duplicate.Duplicate || duplicate.RegistrationID != newRegID {
			t.Fatalf("repeat replace result = %+v", duplicate)
		}
		var registrations int
		_ = pool.QueryRowContext(ctx, `SELECT COUNT(1) FROM dbo.registrations WHERE machine_id=@p1 AND uuid=@p2`, f.machineID, newUUID).Scan(&registrations)
		if registrations != 1 {
			t.Fatalf("repeat confirmation created %d registrations, want 1", registrations)
		}

		if err := s.ArchiveMachine(ctx, f.machineID, "must not archive active", "admin@test"); err == nil {
			t.Fatal("active machine was archived")
		}
		if err := s.RevokeRegistration(ctx, newRegID, "test"); err != nil {
			t.Fatal(err)
		}
		if err := s.ArchiveMachine(ctx, f.machineID, "historical duplicate", "admin@test"); err != nil {
			t.Fatalf("archive: %v", err)
		}
		page, err := s.ListMachines(ctx, AdminMachineFilter{Query: f.hostname, Page: 1, PageSize: 25})
		if err != nil {
			t.Fatal(err)
		}
		if len(page.Items) != 0 {
			t.Fatalf("archived machine remained in the acting list: %+v", page.Items)
		}
		archived, err := s.ListMachines(ctx, AdminMachineFilter{Query: f.hostname, Status: "archived", Page: 1, PageSize: 25})
		if err != nil {
			t.Fatal(err)
		}
		if len(archived.Items) != 1 || !archived.Items[0].Archived || archived.Items[0].ArchiveReason != "historical duplicate" {
			t.Fatalf("archived filter = %+v", archived.Items)
		}
		archivedDetail, err := s.MachineDetail(ctx, f.machineID)
		if err != nil {
			t.Fatal(err)
		}
		if len(archivedDetail.Events) == 0 {
			t.Fatal("archive lost machine history/events")
		}
	})

	t.Run("signed rename keeps the machine and moves unfinished tasks", func(t *testing.T) {
		f := newInstallationFixture(t, ctx, pool, s)
		jobID, err := s.AddJob(ctx, f.machineID, "test")
		if err != nil {
			t.Fatal(err)
		}
		newKey, err := protocol.GenerateKey()
		if err != nil {
			t.Fatal(err)
		}
		newUUID := protocol.NewUUID()
		newHostname := f.hostname + "-RENAMED"
		request := &protocol.SignedRequest{Data: protocol.SignedData{
			ProtocolVersion: protocol.ProtocolVersion, Operation: protocol.OpRename,
			RequestID: protocol.NewUUID(), UUID: f.uuid, Hostname: f.hostname,
			Method: protocol.MethodPost, Path: protocol.PathRename,
			IssuedAt: time.Now().UTC().Format(time.RFC3339Nano), AgentVersion: "0.5.0-test",
			OSVersion: "Windows 10 22H2", Architecture: "amd64",
			NewUUID: newUUID, NewHostname: newHostname, NewPublicKey: testPublicPEM(t, &newKey.PublicKey),
		}}
		result, apiErr := s.Rename(ctx, request, net.ParseIP("192.0.2.20"), "verified")
		if apiErr != nil {
			t.Fatalf("rename: %v", apiErr)
		}
		if result.MachineID != f.machineID {
			t.Fatalf("rename changed machine_id: %s -> %s", f.machineID, result.MachineID)
		}
		identity, apiErr := s.LookupActiveIdentity(ctx, newUUID)
		if apiErr != nil {
			t.Fatalf("lookup renamed identity: %v", apiErr)
		}
		if identity.MachineID != f.machineID || identity.ScanEpoch != 1 {
			t.Fatalf("renamed identity machine=%s epoch=%d", identity.MachineID, identity.ScanEpoch)
		}
		var oldState string
		_ = pool.QueryRowContext(ctx, `SELECT state FROM dbo.registrations WHERE registration_id=@p1`, f.regID).Scan(&oldState)
		if oldState != "renamed" {
			t.Fatalf("old registration state = %s, want renamed", oldState)
		}
		var taskRegistration int64
		var encrypted []byte
		if err := pool.QueryRowContext(ctx, `
SELECT ti.registration_id,ti.encrypted_parameters FROM dbo.task_items ti JOIN dbo.jobs j ON j.task_item_id=ti.item_id WHERE j.job_id=@p1`, jobID).
			Scan(&taskRegistration, &encrypted); err != nil {
			t.Fatal(err)
		}
		if taskRegistration != identity.RegistrationID || len(encrypted) != 0 {
			t.Fatalf("rename task binding registration=%d params=%d, want new registration and reissue", taskRegistration, len(encrypted))
		}
	})

	t.Run("concurrent confirmation creates exactly one registration", func(t *testing.T) {
		f := newInstallationFixture(t, ctx, pool, s)
		key, err := protocol.GenerateKey()
		if err != nil {
			t.Fatal(err)
		}
		newUUID := protocol.NewUUID()
		pending := f.newPending(t, key, newUUID, "0.5.0-test")
		input := InstallationDecisionInput{
			RequestID: pending.RequestID, RequestVersion: pending.RequestVersion,
			KeyFingerprint: pending.KeyFingerprint, MachineID: f.machineID, OldRegistrationID: f.regID,
		}
		var wg sync.WaitGroup
		results := make([]*InstallationDecisionResult, 2)
		errs := make([]*protocol.APIError, 2)
		for i := 0; i < 2; i++ {
			wg.Add(1)
			go func(index int) {
				defer wg.Done()
				results[index], errs[index] = s.ReplaceInstallation(ctx, input, "admin@test")
			}(i)
		}
		wg.Wait()
		if errs[0] != nil || errs[1] != nil {
			t.Fatalf("concurrent errors: %v / %v", errs[0], errs[1])
		}
		if results[0].RegistrationID != results[1].RegistrationID {
			t.Fatalf("concurrent replacements chose different registrations: %+v / %+v", results[0], results[1])
		}
		if results[0].Duplicate == results[1].Duplicate {
			t.Fatalf("expected one fresh and one duplicate result: %+v / %+v", results[0], results[1])
		}
		var count int
		_ = pool.QueryRowContext(ctx, `SELECT COUNT(1) FROM dbo.registrations WHERE machine_id=@p1 AND state=N'active'`, f.machineID).Scan(&count)
		if count != 1 {
			t.Fatalf("concurrent confirmation active registrations = %d, want 1", count)
		}
	})

	t.Run("separate machine requires explicit decision and is idempotent", func(t *testing.T) {
		f := newInstallationFixture(t, ctx, pool, s)
		key, err := protocol.GenerateKey()
		if err != nil {
			t.Fatal(err)
		}
		newUUID := protocol.NewUUID()
		pending := f.newPending(t, key, newUUID, "0.5.0-test")
		result, apiErr := s.RegisterSeparateInstallation(ctx, InstallationDecisionInput{
			RequestID: pending.RequestID, RequestVersion: pending.RequestVersion,
			KeyFingerprint: pending.KeyFingerprint, ConfirmNameConflict: true, Reason: "same name, new PC",
		}, "admin@test")
		if apiErr != nil {
			t.Fatalf("separate: %v", apiErr)
		}
		if result.MachineID == f.machineID {
			t.Fatal("separate installation reused the historical machine")
		}
		f.machineIDs = append(f.machineIDs, result.MachineID)
		var cards, active int
		_ = pool.QueryRowContext(ctx, `SELECT COUNT(1) FROM dbo.machines WHERE LOWER(display_name)=@p1`, strings.ToLower(f.hostname)).Scan(&cards)
		_ = pool.QueryRowContext(ctx, `SELECT COUNT(1) FROM dbo.registrations WHERE machine_id IN (SELECT machine_id FROM dbo.machines WHERE LOWER(display_name)=@p1) AND state=N'active'`, strings.ToLower(f.hostname)).Scan(&active)
		if cards != 2 || active != 2 {
			t.Fatalf("separate cards=%d active=%d, want 2/2", cards, active)
		}
		var oldGroup, oldPolicy, oldReport int
		_ = pool.QueryRowContext(ctx, `SELECT COUNT(1) FROM dbo.machine_group_members WHERE machine_id=@p1`, f.machineID).Scan(&oldGroup)
		_ = pool.QueryRowContext(ctx, `SELECT COUNT(1) FROM dbo.folder_policy_machines WHERE machine_id=@p1`, f.machineID).Scan(&oldPolicy)
		_ = pool.QueryRowContext(ctx, `SELECT COUNT(1) FROM dbo.reports WHERE machine_id=@p1`, f.machineID).Scan(&oldReport)
		if oldGroup != 1 || oldPolicy != 1 || oldReport != 1 {
			t.Fatalf("separate registration moved history: group=%d policy=%d reports=%d", oldGroup, oldPolicy, oldReport)
		}
		duplicate, apiErr := s.RegisterSeparateInstallation(ctx, InstallationDecisionInput{
			RequestID: pending.RequestID, RequestVersion: pending.RequestVersion,
			KeyFingerprint: pending.KeyFingerprint, ConfirmNameConflict: true,
		}, "admin@test")
		if apiErr != nil || !duplicate.Duplicate || duplicate.MachineID != result.MachineID {
			t.Fatalf("separate repeat = %+v, %v", duplicate, apiErr)
		}
	})

	t.Run("historical card without active registration requires confirmation", func(t *testing.T) {
		f := newInstallationFixture(t, ctx, pool, s)
		if err := s.RevokeRegistration(ctx, f.regID, "test"); err != nil {
			t.Fatal(err)
		}
		key, err := protocol.GenerateKey()
		if err != nil {
			t.Fatal(err)
		}
		newUUID := protocol.NewUUID()
		pending := f.newPending(t, key, newUUID, "0.5.0-test")
		if len(pending.Candidates) != 1 || pending.Candidates[0].ActiveRegistration != nil {
			t.Fatalf("historical candidate = %+v", pending.Candidates)
		}
		if pending.Candidates[0].LastRegistration == nil || pending.Candidates[0].LastRegistration.State != "revoked" {
			t.Fatalf("historical last registration = %+v", pending.Candidates[0].LastRegistration)
		}
		result, apiErr := s.ReplaceInstallation(ctx, InstallationDecisionInput{
			RequestID: pending.RequestID, RequestVersion: pending.RequestVersion,
			KeyFingerprint: pending.KeyFingerprint, MachineID: f.machineID, OldRegistrationID: 0,
		}, "admin@test")
		if apiErr != nil {
			t.Fatalf("replace historical: %v", apiErr)
		}
		if result.MachineID != f.machineID || result.RegistrationID == 0 {
			t.Fatalf("historical replacement = %+v", result)
		}
		var previous sql.NullInt64
		_ = pool.QueryRowContext(ctx, `SELECT previous_registration_id FROM dbo.registrations WHERE registration_id=@p1`, result.RegistrationID).Scan(&previous)
		if !previous.Valid || previous.Int64 != f.regID {
			t.Fatalf("new registration previous id = %+v, want %d", previous, f.regID)
		}
	})
}

// newPendingKey asserts that re-registering a rejected pending request returns
// the stable rejected code instead of creating a new card.
func (f *installationFixture) newPendingKey(t *testing.T, key *ecdsa.PrivateKey, uuid, agentVersion string) *protocol.APIError {
	t.Helper()
	request := &protocol.SignedRequest{Data: protocol.SignedData{
		ProtocolVersion: protocol.ProtocolVersion, Operation: protocol.OpRegister,
		RequestID: protocol.NewUUID(), UUID: uuid, Hostname: f.hostname,
		Method: protocol.MethodPost, Path: protocol.PathRegister,
		IssuedAt: time.Now().UTC().Format(time.RFC3339Nano), AgentVersion: agentVersion,
		OSVersion: "Windows 10 22H2", Architecture: "amd64", PublicKey: testPublicPEM(t, &key.PublicKey),
	}}
	_, apiErr := f.s.Register(f.ctx, request, net.ParseIP("192.0.2.20"), "mismatch")
	if apiErr == nil {
		t.Fatal("rejected pending request registered without a decision")
	}
	return apiErr
}
