package store

import (
	"context"
	"encoding/json"
	"os"
	"testing"
	"time"

	"mandatnik/internal/backend/config"
	"mandatnik/internal/backend/db"
	"mandatnik/internal/protocol"
)

func TestPoliciesSQLServer(t *testing.T) {
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
	if err = db.Migrate(ctx, pool, t.Logf); err != nil {
		t.Fatal("migration repeat:", err)
	}
	s := New(pool)
	machine := protocol.NewUUID()
	name := "POLICY-TEST-" + machine[:8]
	if _, err = pool.ExecContext(ctx, `INSERT INTO dbo.machines(machine_id,display_name,created_at,updated_at) VALUES(@p1,@p2,SYSUTCDATETIME(),SYSUTCDATETIME())`, machine, name); err != nil {
		t.Fatal(err)
	}
	var groups, policies []string
	defer func() {
		for _, id := range policies {
			_ = s.DeleteInventoryItem(context.Background(), "folder-policies", id, "test-cleanup")
		}
		for _, id := range groups {
			_ = s.DeleteInventoryItem(context.Background(), "groups", id, "test-cleanup")
		}
		_, _ = pool.ExecContext(context.Background(), `DELETE FROM dbo.machines WHERE machine_id=@p1`, machine)
	}()
	effective := func() configRow {
		t.Helper()
		tx, e := pool.BeginTx(ctx, nil)
		if e != nil {
			t.Fatal(e)
		}
		defer tx.Rollback()
		v, e := effectiveConfigTx(ctx, tx, machine)
		if e != nil {
			t.Fatal(e)
		}
		return v
	}
	if err := s.BackfillLegacyJobs(ctx); err != nil {
		t.Fatal("legacy jobs backfill:", err)
	}
	initial := effective()
	if len(initial.Config.FolderPolicies) != 0 || len(initial.Config.CertDirectories) != 0 {
		t.Fatal("new machine has folder policies")
	}
	var unmappedJobs int
	if err := pool.QueryRowContext(ctx, `SELECT COUNT(1) FROM dbo.jobs j WHERE j.task_item_id IS NULL AND EXISTS (SELECT 1 FROM dbo.registrations r WHERE r.machine_id=j.machine_id)`).Scan(&unmappedJobs); err != nil {
		t.Fatal(err)
	}
	if unmappedJobs != 0 {
		t.Fatalf("legacy jobs not fully migrated: unmapped=%d", unmappedJobs)
	}
	g, err := s.SaveGroup(ctx, MachineGroup{Name: name, MachineIDs: []string{machine}}, true, "test")
	if err != nil {
		t.Fatal(err)
	}
	groups = append(groups, g)
	g2, err := s.SaveGroup(ctx, MachineGroup{Name: name + "-2", MachineIDs: []string{machine}}, true, "test")
	if err != nil {
		t.Fatal(err)
	}
	groups = append(groups, g2)
	p, err := s.SaveFolderPolicy(ctx, FolderPolicy{Name: name, Rules: "C:/Users/*/Certificates/", GroupIDs: []string{g, g2}}, true, "test")
	if err != nil {
		t.Fatal(err)
	}
	policies = append(policies, p)
	inherited := effective()
	if len(inherited.Config.FolderPolicies) != 1 || inherited.Config.FolderPolicies[0].Level != "group" || inherited.Hash == initial.Hash {
		t.Fatal("group config resolution/hash")
	}
	if _, err = s.SaveFolderPolicy(ctx, FolderPolicy{ID: p, Name: name, Rules: "!C:/Users/*/Certificates/trash/", MachineIDs: []string{machine}, GroupIDs: []string{g}}, false, "test"); err != nil {
		t.Fatal(err)
	}
	direct := effective()
	if direct.Config.FolderPolicies[0].Level != "machine" || direct.Hash == inherited.Hash {
		t.Fatal("direct assignment/hash")
	}
	if _, err = s.SaveFolderPolicy(ctx, FolderPolicy{ID: p, Name: name, Rules: "C:/Other/", MachineIDs: []string{protocol.NewUUID()}}, false, "test"); err == nil {
		t.Fatal("invalid target accepted")
	}
	if effective().Hash != direct.Hash {
		t.Fatal("failed update changed config")
	}
	if err = s.AddGroupMembers(ctx, g, []string{machine}, "test"); err != nil {
		t.Fatal("idempotent bulk add:", err)
	}
	catalog, err := s.InventorySettings(ctx)
	if err != nil {
		t.Fatal(err)
	}
	membership := 0
	for _, group := range catalog.Groups {
		for _, id := range group.MachineIDs {
			if id == machine {
				membership++
			}
		}
	}
	if membership != 2 {
		t.Fatalf("membership=%d", membership)
	}
	if err = s.DeleteInventoryItem(ctx, "folder-policies", p, "test"); err != nil {
		t.Fatal(err)
	}
	policies = nil
	final := effective()
	if final.Hash != initial.Hash {
		t.Fatal("deletion did not revoke policy")
	}
	t.Log("SQL Server: migrations, group many-to-many, assignment resolution, hash invalidation, atomic rollback, deletion: PASS")
}
