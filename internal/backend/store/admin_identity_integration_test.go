package store

import (
	"context"
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

func TestAdminIdentitySQLServer(t *testing.T) {
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
	if err = db.Migrate(ctx, pool, t.Logf); err != nil {
		t.Fatal("migration repeat:", err)
	}

	var columns int
	if err = pool.QueryRowContext(ctx, `
SELECT COUNT(*) FROM sys.columns
WHERE object_id=OBJECT_ID(N'dbo.administrators') AND name IN (N'email', N'display_name', N'role')`).Scan(&columns); err != nil {
		t.Fatal(err)
	}
	if columns != 3 {
		t.Fatalf("identity columns present = %d, want 3", columns)
	}
	var incomplete int
	if err = pool.QueryRowContext(ctx, `
SELECT COUNT(*) FROM dbo.administrators
WHERE email IS NULL OR display_name IS NULL OR role NOT IN (N'admin', N'superadmin')`).Scan(&incomplete); err != nil {
		t.Fatal(err)
	}
	if incomplete != 0 {
		t.Fatalf("%d administrator rows were not backfilled", incomplete)
	}
	var admins int
	if err = pool.QueryRowContext(ctx, `SELECT COUNT(*) FROM dbo.administrators`).Scan(&admins); err != nil {
		t.Fatal(err)
	}
	if admins > 0 {
		var superadmins int
		if err = pool.QueryRowContext(ctx, `SELECT COUNT(*) FROM dbo.administrators WHERE role=N'superadmin'`).Scan(&superadmins); err != nil {
			t.Fatal(err)
		}
		if superadmins == 0 {
			t.Fatal("migration left administrators without a superadmin")
		}
	}

	s := New(pool)
	email := fmt.Sprintf("admin-identity-test-%s@example.test", strings.ReplaceAll(protocol.NewUUID(), "-", ""))
	const passwordHash = "$2a$12$test-only-hash-not-used-for-login"
	defer func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cleanupCancel()
		_, _ = pool.ExecContext(cleanupCtx, `DELETE FROM dbo.admin_sessions WHERE admin_id IN (SELECT admin_id FROM dbo.administrators WHERE email=@p1)`, email)
		_, _ = pool.ExecContext(cleanupCtx, `DELETE FROM dbo.administrators WHERE email=@p1`, email)
	}()

	id, err := s.UpsertAdmin(ctx, email, "Тестовый А. Б.", AdminRoleAdmin, passwordHash)
	if err != nil {
		t.Fatal(err)
	}
	if id <= 0 {
		t.Fatalf("UpsertAdmin returned id %d", id)
	}
	account, err := s.AdminByEmail(ctx, "  "+strings.ToUpper(email)+"  ")
	if err != nil {
		t.Fatal(err)
	}
	if account.ID != id || account.Email != email || account.DisplayName != "Тестовый А. Б." || account.Role != AdminRoleAdmin || account.Disabled {
		t.Fatalf("AdminByEmail returned %+v", account)
	}
	var legacyUsername string
	if err = pool.QueryRowContext(ctx, `SELECT username FROM dbo.administrators WHERE admin_id=@p1`, id).Scan(&legacyUsername); err != nil {
		t.Fatal(err)
	}
	if legacyUsername == "" {
		t.Fatal("legacy username column was not populated")
	}

	if _, err = pool.ExecContext(ctx, `UPDATE dbo.administrators SET disabled=1 WHERE admin_id=@p1`, id); err != nil {
		t.Fatal(err)
	}
	updatedID, err := s.UpsertAdmin(ctx, strings.ToUpper(email), "Тестовый В. Г.", AdminRoleSuperAdmin, passwordHash)
	if err != nil {
		t.Fatal(err)
	}
	if updatedID != id {
		t.Fatalf("upsert by normalized email changed id: got %d, want %d", updatedID, id)
	}
	updated, err := s.AdminByEmail(ctx, email)
	if err != nil {
		t.Fatal(err)
	}
	if updated.DisplayName != "Тестовый В. Г." || updated.Role != AdminRoleSuperAdmin || updated.Disabled {
		t.Fatalf("upsert did not update identity: %+v", updated)
	}

	tx, err := pool.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, `UPDATE dbo.administrators SET role=N'owner' WHERE admin_id=@p1`, id); err == nil {
		t.Fatal("role check constraint accepted an unknown role")
	}
}
