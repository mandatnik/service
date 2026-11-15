package store

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"mandatnik/internal/backend/config"
	"mandatnik/internal/backend/db"
	"mandatnik/internal/protocol"
)

func TestAdminMonitoringSQLServer(t *testing.T) {
	path := os.Getenv("MANDATNIK_MONITOR_TEST_CONFIG")
	if path == "" {
		t.Skip("set MANDATNIK_MONITOR_TEST_CONFIG to a disposable monitoring database")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var cfg struct {
		DB config.DB `json:"db"`
	}
	if err = json.Unmarshal(raw, &cfg); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(cfg.DB.Database, "MandatnikMonitorTest_") {
		t.Fatal("test requires an isolated MandatnikMonitorTest_ database")
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
	var existing int
	if err = pool.QueryRowContext(ctx, "SELECT COUNT(*) FROM dbo.machines").Scan(&existing); err != nil || existing != 0 {
		t.Fatalf("requires empty disposable database: count=%d err=%v", existing, err)
	}
	now := time.Date(2026, 11, 15, 10, 0, 0, 0, time.UTC)
	s := New(pool)
	s.Now = func() time.Time { return now }
	exec := func(query string, args ...any) {
		t.Helper()
		if _, err := pool.ExecContext(ctx, query, args...); err != nil {
			t.Fatal(err)
		}
	}
	ids := map[string]string{}
	reports := map[string]string{}
	for _, name := range []string{"paid", "trial", "expired", "missing", "covered", "offline", "archived", "historical"} {
		id := protocol.NewUUID()
		ids[name] = id
		exec(`INSERT INTO dbo.machines(machine_id,display_name,created_at,updated_at) VALUES(@p1,@p2,@p3,@p3)`, id, name, now)
		if name == "historical" {
			continue
		}
		last := now
		if name == "offline" {
			last = now.Add(-3 * time.Minute)
		}
		var reg int64
		err := pool.QueryRowContext(ctx, `INSERT INTO dbo.registrations(machine_id,uuid,hostname,hostname_norm,public_key_pem,public_key_sha256,state,created_at,last_seen_at,last_source_ip)
   OUTPUT INSERTED.registration_id VALUES(@p1,@p2,@p3,@p3,N'test',REPLICATE('a',64),N'active',@p4,@p5,0xC0000201)`, id, protocol.NewUUID(), name, now, last).Scan(&reg)
		if err != nil {
			t.Fatal(err)
		}
		report := protocol.NewUUID()
		reports[name] = report
		exec(`INSERT INTO dbo.reports(report_id,machine_id,registration_id,scan_seq,collected_at,received_at,status,applied,applied_sources,payload_sha256,payload_json,profiles_complete,personal_complete)
   VALUES(@p1,@p2,@p3,1,@p4,@p4,N'complete',0,0,REPLICATE('b',64),N'{}',1,1)`, report, id, reg, now)
		if name == "archived" {
			exec(`UPDATE dbo.machines SET archived_at=@p2 WHERE machine_id=@p1`, id, now)
		}
		if name == "missing" || name == "archived" {
			continue
		}
		state, trial := "active", "false"
		if name == "trial" {
			trial = "yes"
		}
		if name == "expired" {
			state = "expired"
		}
		if name == "covered" {
			state = "unknown"
		}
		exec(`INSERT INTO dbo.csp_states(machine_id,scanned,complete,present,license_state,is_trial,products_json,last_scan_seq,collected_at,updated_at,last_attempt_at)
   VALUES(@p1,1,1,1,@p2,@p3,N'[]',1,@p4,@p4,@p4)`, id, state, trial, now)
	}
	// Historical registrations must not duplicate a logical machine in counters.
	exec(`INSERT INTO dbo.registrations(machine_id,uuid,hostname,hostname_norm,public_key_pem,public_key_sha256,state,created_at,last_seen_at)
 VALUES(@p1,@p2,N'paid-old',N'paid-old',N'test',REPLICATE('c',64),N'renamed',@p3,@p3)`, ids["paid"], protocol.NewUUID(), now.Add(-time.Minute))
	cert := func(label, inn, embedded string, before, after time.Time) string {
		sum := sha256.Sum256([]byte(label))
		sha := hex.EncodeToString(sum[:])
		exec(`INSERT INTO dbo.certificates(sha256,der,inn,embedded_license,not_before,not_after,created_at,updated_at) VALUES(@p1,0x30,@p2,@p3,@p4,@p5,@p6,@p6)`, sha, inn, embedded, before, after, now)
		return sha
	}
	observe := func(machine, sha, source string) {
		exec(`INSERT INTO dbo.certificate_observations(machine_id,source_type,source_key,source_scope_hash,observation_key_hash,certificate_sha256,active,first_seen_at,last_seen_at,last_report_id,last_scan_seq)
  VALUES(@p1,@p2,@p2,HASHBYTES('SHA2_256',@p2),HASHBYTES('SHA2_256',CONCAT(@p2,@p3)),@p3,1,@p4,@p4,@p5,1)`, ids[machine], source, sha, now, reports[machine])
	}
	before, after := now.AddDate(-1, 0, 0), now.AddDate(1, 0, 0)
	base := cert("base", "", "absent", before, after)
	for _, name := range []string{"paid", "trial", "expired"} {
		observe(name, base, "user_store")
	}
	covered := cert("covered", "", "present", before, after)
	observe("covered", covered, "user_store")
	expired := cert("recent", "111111111111", "absent", before, now.AddDate(0, 0, -10))
	observe("paid", expired, "folder")
	observe("trial", expired, "folder")
	observe("trial", expired, "user_store")
	boundary := cert("month-boundary", "666666666666", "absent", before, now.AddDate(0, -1, 0))
	observe("paid", boundary, "folder")
	renewed := cert("renewed", "222222222222", "absent", before, now.AddDate(0, 0, -10))
	observe("expired", renewed, "folder")
	cert("replacement", "222222222222", "absent", before, after)
	cert("future-replacement", "111111111111", "absent", now.AddDate(0, 0, 1), after)
	old := cert("old", "333333333333", "absent", before, now.AddDate(0, 0, -40))
	observe("missing", old, "folder")
	unknown := cert("unknown-owner", "", "absent", before, now.AddDate(0, 0, -10))
	observe("missing", unknown, "folder")
	cert("not-observed", "444444444444", "absent", before, now.AddDate(0, 0, -10))
	archived := cert("only-archived", "555555555555", "absent", before, now.AddDate(0, 0, -10))
	observe("archived", archived, "folder")
	exact := cert("exact-expiry", "777777777777", "absent", before, now)
	observe("paid", exact, "folder")
	overview, err := s.AdminOverview(ctx)
	if err != nil {
		t.Fatal(err)
	}
	m := overview.Monitoring
	if overview.Machines != 6 || m.OnlineMachines != 5 || m.ActiveLicenseMachines != 3 || m.ActiveLicenseTrialMachines != 1 || m.NeedsLicenseMachines != 2 || m.NeedsLicenseTrialMachines != 1 || m.MissingCSPMachines != 1 || m.ExpiredCertificates != 2 || m.ExpiredCertificateMachines != 2 {
		t.Fatalf("unexpected monitoring: machines=%d %+v", overview.Machines, m)
	}
	for key, wantNames := range map[string][]string{"online": {"paid", "trial", "expired", "missing", "covered"}, "active_license": {"paid", "trial", "offline"}, "needs_license": {"trial", "expired"}, "csp_missing": {"missing"}, "expired_certificates": {"paid", "trial"}} {
		page, err := s.ListMachines(ctx, AdminMachineFilter{Status: "active", Monitor: key, AsOf: &now, PageSize: 100})
		if err != nil {
			t.Fatal(err)
		}
		got, want := []string{}, []string{}
		for _, item := range page.Items {
			got = append(got, item.MachineID)
		}
		for _, name := range wantNames {
			want = append(want, ids[name])
		}
		sort.Strings(got)
		sort.Strings(want)
		if !reflect.DeepEqual(got, want) || page.Total != len(want) {
			t.Fatalf("monitor %s: got %v total %d want %v", key, got, page.Total, want)
		}
	}
	group := protocol.NewUUID()
	exec(`INSERT INTO dbo.machine_groups(group_id,name) VALUES(@p1,N'filter group')`, group)
	exec(`INSERT INTO dbo.machine_group_members(group_id,machine_id) VALUES(@p1,@p2),(@p1,@p3)`, group, ids["paid"], ids["trial"])
	page, err := s.ListMachines(ctx, AdminMachineFilter{Status: "active", Monitor: "needs_license", GroupID: group, License: "trial", SourceIP: "192.0.2.1", AsOf: &now})
	if err != nil || len(page.Items) != 1 || page.Items[0].MachineID != ids["trial"] {
		t.Fatalf("combined filters: %+v err=%v", page, err)
	}
	page, err = s.ListMachines(ctx, AdminMachineFilter{Status: "active", MachineStatus: MachineStatusLicenseRequired, AsOf: &now})
	if err != nil || len(page.Items) != 1 || page.Items[0].MachineID != ids["expired"] {
		t.Fatalf("status filter: %+v err=%v", page, err)
	}
	certs, err := s.ListCertificates(ctx, expired, "", 1, 25)
	if err != nil || len(certs.Items) != 1 {
		t.Fatalf("certificate list: %+v err=%v", certs, err)
	}
	c := certs.Items[0]
	if c.Machines != 2 || c.RegistryMachines != 1 || c.FileMachines != 2 || c.Observations != 3 {
		t.Fatalf("certificate source deduplication: %+v", c)
	}
}
