package store

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"telehack2026/internal/backend/config"
	"telehack2026/internal/backend/db"
	"telehack2026/internal/protocol"
)

// TestListMachinesSummarySQLServer verifies the SQL plumbing behind the
// machine table: group badges, CSP presence, unique registry/file certificate
// counts, licensed certificates, license expiry and the derived status.
func TestListMachinesSummarySQLServer(t *testing.T) {
	file := os.Getenv("TELEHACK_POLICY_TEST_CONFIG")
	if file == "" {
		t.Skip("set TELEHACK_POLICY_TEST_CONFIG to an authorized SQL Server acceptance config")
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
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	pool, err := db.Open(ctx, cfg.DB)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	if err = db.Migrate(ctx, pool, t.Logf); err != nil {
		t.Fatal(err)
	}
	s := New(pool)

	machineID := protocol.NewUUID()
	uuid := protocol.NewUUID()
	hostname := "SUMMARY-TEST-" + machineID[:8]
	groupA := protocol.NewUUID()
	groupB := protocol.NewUUID()
	groupAName := "A-group-" + machineID[:8]
	groupBName := "B-group-" + machineID[:8]
	reportID := protocol.NewUUID()
	certs := make([]string, 3)
	for i := range certs {
		sum := sha256.Sum256([]byte(fmt.Sprintf("%s-cert-%d", machineID, i)))
		certs[i] = hex.EncodeToString(sum[:])
	}
	fallbackMachine := protocol.NewUUID()
	fallbackUUID := protocol.NewUUID()

	cleanup := func() {
		cleanupCtx, cancelCleanup := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancelCleanup()
		for _, id := range []string{machineID, fallbackMachine} {
			_, _ = pool.ExecContext(cleanupCtx, `DELETE FROM dbo.certificate_observation_bindings WHERE observation_id IN (SELECT observation_id FROM dbo.certificate_observations WHERE machine_id=@p1)`, id)
			_, _ = pool.ExecContext(cleanupCtx, `DELETE FROM dbo.certificate_observations WHERE machine_id=@p1`, id)
			_, _ = pool.ExecContext(cleanupCtx, `DELETE FROM dbo.machine_user_certificates WHERE machine_user_id IN (SELECT machine_user_id FROM dbo.machine_users WHERE machine_id=@p1)`, id)
			_, _ = pool.ExecContext(cleanupCtx, `DELETE FROM dbo.machine_users WHERE machine_id=@p1`, id)
			_, _ = pool.ExecContext(cleanupCtx, `DELETE FROM dbo.source_states WHERE machine_id=@p1`, id)
			_, _ = pool.ExecContext(cleanupCtx, `DELETE FROM dbo.csp_states WHERE machine_id=@p1`, id)
			_, _ = pool.ExecContext(cleanupCtx, `DELETE FROM dbo.reports WHERE machine_id=@p1`, id)
			_, _ = pool.ExecContext(cleanupCtx, `DELETE FROM dbo.machine_group_members WHERE machine_id=@p1`, id)
			_, _ = pool.ExecContext(cleanupCtx, `DELETE FROM dbo.registrations WHERE machine_id=@p1`, id)
			_, _ = pool.ExecContext(cleanupCtx, `DELETE FROM dbo.machines WHERE machine_id=@p1`, id)
		}
		_, _ = pool.ExecContext(cleanupCtx, `DELETE FROM dbo.machine_groups WHERE group_id IN (@p1,@p2)`, groupA, groupB)
		for _, sha := range certs {
			_, _ = pool.ExecContext(cleanupCtx, `DELETE FROM dbo.certificates WHERE sha256=@p1`, sha)
		}
	}
	cleanup()
	defer cleanup()

	if _, err := pool.ExecContext(ctx, `INSERT INTO dbo.machines(machine_id,display_name,created_at,updated_at) VALUES(@p1,@p2,SYSUTCDATETIME(),SYSUTCDATETIME())`, machineID, hostname); err != nil {
		t.Fatal(err)
	}
	var registrationID int64
	if err := pool.QueryRowContext(ctx, `
INSERT INTO dbo.registrations(machine_id,uuid,hostname,hostname_norm,public_key_pem,public_key_sha256,state,agent_version,os_version,architecture,created_at,last_seen_at)
OUTPUT INSERTED.registration_id
VALUES(@p1,@p2,@p3,@p4,N'test',REPLICATE('a',64),N'active',N'test',N'Windows 10',N'amd64',SYSUTCDATETIME(),SYSUTCDATETIME())`,
		machineID, uuid, hostname, strings.ToLower(hostname)).Scan(&registrationID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.ExecContext(ctx, `
INSERT INTO dbo.reports(report_id,machine_id,registration_id,scan_seq,collected_at,received_at,status,applied,applied_sources,payload_sha256,payload_json,profiles_complete,personal_complete)
VALUES(@p1,@p2,@p3,1,SYSUTCDATETIME(),SYSUTCDATETIME(),N'complete',0,0,REPLICATE('b',64),N'{}',1,1)`,
		reportID, machineID, registrationID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.ExecContext(ctx, `
INSERT INTO dbo.csp_states(machine_id,scanned,complete,present,product_version,core_version,license_kind,license_kind_raw,license_kind_source,license_state,valid_to_raw,valid_to_utc,time_basis,term_kind,is_trial,source,products_json,last_scan_seq,collected_at,updated_at,last_attempt_at)
VALUES(@p1,1,1,1,N'5.0.13003',N'5.0',N'client',N'0',N'CPCSPLicense.GetType',N'active',N'2027-02-14T18:59:59',DATEADD(day,30,SYSUTCDATETIME()),N'system_local_assumed',N'time_limited',N'no',N'CPCSPLicense',N'[]',1,SYSUTCDATETIME(),SYSUTCDATETIME(),SYSUTCDATETIME())`,
		machineID); err != nil {
		t.Fatal(err)
	}
	for i, sha := range certs {
		embedded := "absent"
		if i == 1 {
			embedded = "present"
		}
		if _, err := pool.ExecContext(ctx, `
INSERT INTO dbo.certificates(sha256,der,serial_hex,serial_number,subject,issuer,embedded_license,not_before,not_after,created_at,updated_at)
VALUES(@p1,0x30,N'01',N'1',N'CN=test',N'CN=ca',@p2,DATEADD(day,-1,SYSUTCDATETIME()),DATEADD(day,30,SYSUTCDATETIME()),SYSUTCDATETIME(),SYSUTCDATETIME())`,
			sha, embedded); err != nil {
			t.Fatal(err)
		}
	}
	observations := []struct {
		sha, sourceType, sourceKey, filePath string
	}{
		{certs[0], "user_store", "S-1-5-21-1", ""},
		{certs[1], "user_store", "S-1-5-21-1", ""},
		{certs[2], "folder", `C:\certs`, `C:\certs\a.cer`},
	}
	for _, o := range observations {
		if _, err := pool.ExecContext(ctx, `
INSERT INTO dbo.certificate_observations(machine_id,source_type,source_key,source_scope_hash,observation_key_hash,file_path,certificate_sha256,active,first_seen_at,last_seen_at,last_report_id,last_scan_seq)
VALUES(@p1,@p2,@p3,HASHBYTES('SHA2_256',CONCAT(@p2,CHAR(0),@p3)),HASHBYTES('SHA2_256',CONCAT(@p2,CHAR(0),@p4)),@p5,@p4,1,SYSUTCDATETIME(),SYSUTCDATETIME(),@p6,1)`,
			machineID, o.sourceType, o.sourceKey, o.sha, nilIfEmpty(o.filePath), reportID); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := pool.ExecContext(ctx, `INSERT INTO dbo.machine_groups(group_id,name) VALUES(@p1,@p2),(@p3,@p4)`, groupB, groupBName, groupA, groupAName); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.ExecContext(ctx, `INSERT INTO dbo.machine_group_members(group_id,machine_id) VALUES(@p1,@p2),(@p3,@p2)`, groupB, machineID, groupA); err != nil {
		t.Fatal(err)
	}

	page, err := s.ListMachines(ctx, AdminMachineFilter{MachineID: machineID, Page: 1, PageSize: 25})
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Items) != 1 {
		t.Fatalf("items = %d, want 1", len(page.Items))
	}
	item := page.Items[0]
	if item.DisplayName != hostname {
		t.Fatalf("display_name = %q, want %q", item.DisplayName, hostname)
	}
	if !item.CSPPresent {
		t.Fatal("csp_present = false, want true")
	}
	if item.ProductVersion != "5.0.13003" {
		t.Fatalf("product_version = %q", item.ProductVersion)
	}
	if item.RegistryCerts != 2 || item.FileCerts != 1 || item.LicensedCerts != 1 {
		t.Fatalf("certificate counts = registry:%d file:%d licensed:%d, want 2/1/1", item.RegistryCerts, item.FileCerts, item.LicensedCerts)
	}
	if item.LicenseValidTo == nil {
		t.Fatal("license_valid_to is nil")
	}
	if item.Status != MachineStatusOK {
		t.Fatalf("status = %q, want %q", item.Status, MachineStatusOK)
	}
	if len(item.Groups) != 2 || item.Groups[0].Name != groupAName || item.Groups[1].Name != groupBName {
		t.Fatalf("groups = %+v, want sorted [%s %s]", item.Groups, groupAName, groupBName)
	}

	// A machine without a user-facing name must present its registration UUID,
	// and a live machine without a CSP row must report csp_missing.
	if _, err := pool.ExecContext(ctx, `INSERT INTO dbo.machines(machine_id,display_name,created_at,updated_at) VALUES(@p1,N'',SYSUTCDATETIME(),SYSUTCDATETIME())`, fallbackMachine); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.ExecContext(ctx, `
INSERT INTO dbo.registrations(machine_id,uuid,hostname,hostname_norm,public_key_pem,public_key_sha256,state,created_at,last_seen_at)
VALUES(@p1,@p2,N'FALLBACK-TEST',N'fallback-test',N'test',REPLICATE('c',64),N'active',SYSUTCDATETIME(),SYSUTCDATETIME())`,
		fallbackMachine, fallbackUUID); err != nil {
		t.Fatal(err)
	}
	fallbackPage, err := s.ListMachines(ctx, AdminMachineFilter{MachineID: fallbackMachine, Page: 1, PageSize: 25})
	if err != nil {
		t.Fatal(err)
	}
	if len(fallbackPage.Items) != 1 {
		t.Fatalf("fallback items = %d, want 1", len(fallbackPage.Items))
	}
	if got := fallbackPage.Items[0].DisplayName; got != fallbackUUID {
		t.Fatalf("fallback display_name = %q, want UUID %q", got, fallbackUUID)
	}
	if got := fallbackPage.Items[0].Status; got != MachineStatusCSPMissing {
		t.Fatalf("fallback status = %q, want %q", got, MachineStatusCSPMissing)
	}

	// Going offline must not hide the licensing status: the online column and
	// the status column are independent.
	if _, err := pool.ExecContext(ctx, `UPDATE dbo.registrations SET last_seen_at=DATEADD(minute,-30,SYSUTCDATETIME()) WHERE machine_id=@p1`, fallbackMachine); err != nil {
		t.Fatal(err)
	}
	offlinePage, err := s.ListMachines(ctx, AdminMachineFilter{MachineID: fallbackMachine, Page: 1, PageSize: 25})
	if err != nil {
		t.Fatal(err)
	}
	if len(offlinePage.Items) != 1 {
		t.Fatalf("offline items = %d, want 1", len(offlinePage.Items))
	}
	if !offlinePage.Items[0].Offline {
		t.Fatal("offline flag = false, want true")
	}
	if got := offlinePage.Items[0].Status; got != MachineStatusCSPMissing {
		t.Fatalf("offline status = %q, want %q", got, MachineStatusCSPMissing)
	}
}
