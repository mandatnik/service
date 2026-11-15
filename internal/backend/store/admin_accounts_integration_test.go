package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"mandatnik/internal/backend/config"
	"mandatnik/internal/backend/db"
	"mandatnik/internal/protocol"
)

func TestAdminAccountsSQLServer(t *testing.T) {
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
	s := New(pool)
	suffix := strings.ReplaceAll(protocol.NewUUID(), "-", "")[:12]
	email := "admin-accounts-" + suffix + "@example.test"
	updatedEmail := "admin-accounts-updated-" + suffix + "@example.test"
	superEmail := "admin-accounts-super-" + suffix + "@example.test"
	const passwordHash = "$2a$12$test-only-hash-not-used-for-login"
	var superID, targetID int64
	t.Cleanup(func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cleanupCancel()
		for _, id := range []int64{superID, targetID} {
			if id > 0 {
				_, _ = pool.ExecContext(cleanupCtx, `DELETE FROM dbo.admin_sessions WHERE admin_id=@p1`, id)
			}
		}
		_, _ = pool.ExecContext(cleanupCtx, `DELETE FROM dbo.administrators WHERE email IN (@p1,@p2,@p3)`, email, updatedEmail, superEmail)
		_, _ = pool.ExecContext(cleanupCtx, `DELETE FROM dbo.events WHERE kind LIKE N'admin_%' AND details_json LIKE @p1`, "%"+suffix+"%")
	})

	record, err := s.CreateAdminAccount(ctx, email, "Тестовый администратор", passwordHash, "super@test")
	if err != nil {
		t.Fatal(err)
	}
	targetID = record.ID
	if record.Role != AdminRoleAdmin || record.Disabled || !strings.EqualFold(record.Email, email) {
		t.Fatalf("created record = %+v", record)
	}
	if raw, _ := json.Marshal(record); strings.Contains(strings.ToLower(string(raw)), "password") || strings.Contains(string(raw), passwordHash) {
		t.Fatalf("admin record exposed credential material: %s", raw)
	}

	sessionToken := "session-" + suffix
	if _, err := s.CreateAdminSession(ctx, targetID, TokenHash(sessionToken), time.Hour); err != nil {
		t.Fatal(err)
	}
	if session, err := s.ValidateAdminSession(ctx, TokenHash(sessionToken)); err != nil || session.AdminID != targetID {
		t.Fatalf("initial session: %+v %v", session, err)
	}

	updated, err := s.UpdateAdminAccount(ctx, targetID, updatedEmail, "Изменённый администратор", passwordHash, "super@test")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.EqualFold(updated.Email, updatedEmail) || updated.DisplayName != "Изменённый администратор" || updated.Role != AdminRoleAdmin {
		t.Fatalf("updated record = %+v", updated)
	}
	if _, err := s.ValidateAdminSession(ctx, TokenHash(sessionToken)); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("credential change left the old session valid: %v", err)
	}

	// A fresh session must stop working as soon as the account is frozen.
	freshToken := "frozen-" + suffix
	if _, err := s.CreateAdminSession(ctx, targetID, TokenHash(freshToken), time.Hour); err != nil {
		t.Fatal(err)
	}
	frozen, err := s.SetAdminDisabled(ctx, targetID, true, "super@test")
	if err != nil {
		t.Fatal(err)
	}
	if !frozen.Disabled {
		t.Fatalf("freeze did not set disabled: %+v", frozen)
	}
	if _, err := s.ValidateAdminSession(ctx, TokenHash(freshToken)); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("freeze left the session valid: %v", err)
	}
	unfrozen, err := s.SetAdminDisabled(ctx, targetID, false, "super@test")
	if err != nil {
		t.Fatal(err)
	}
	if unfrozen.Disabled {
		t.Fatalf("unfreeze did not clear disabled: %+v", unfrozen)
	}
	if _, err := s.ValidateAdminSession(ctx, TokenHash(freshToken)); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("unfreeze restored a revoked session: %v", err)
	}

	superID, err = s.UpsertAdmin(ctx, superEmail, "Защищённый суперадмин", AdminRoleSuperAdmin, passwordHash)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.UpdateAdminAccount(ctx, superID, superEmail, "Нельзя менять", "", "super@test"); !errors.Is(err, ErrAdminAccountProtected) {
		t.Fatalf("superadmin update error = %v", err)
	}
	if _, err := s.SetAdminDisabled(ctx, superID, true, "super@test"); !errors.Is(err, ErrAdminAccountProtected) {
		t.Fatalf("superadmin freeze error = %v", err)
	}
	if err := s.DeleteAdminAccount(ctx, superID, "super@test"); !errors.Is(err, ErrAdminAccountProtected) {
		t.Fatalf("superadmin delete error = %v", err)
	}

	if _, err := s.CreateAdminAccount(ctx, updatedEmail, "Дубликат", passwordHash, "super@test"); !errors.Is(err, ErrAdminEmailConflict) {
		t.Fatalf("duplicate email error = %v", err)
	}

	if err := s.DeleteAdminAccount(ctx, targetID, "super@test"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.AdminByEmail(ctx, updatedEmail); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("deleted account still resolves: %v", err)
	}
	var sessions int
	if err := pool.QueryRowContext(ctx, `SELECT COUNT(1) FROM dbo.admin_sessions WHERE admin_id=@p1`, targetID).Scan(&sessions); err != nil || sessions != 0 {
		t.Fatalf("deleted account sessions=%d err=%v", sessions, err)
	}
	var audit int
	if err := pool.QueryRowContext(ctx, `
SELECT COUNT(1) FROM dbo.events WHERE kind='admin_deleted' AND details_json LIKE @p1`, fmt.Sprintf("%%%d%%", targetID)).Scan(&audit); err != nil || audit == 0 {
		t.Fatalf("delete audit rows=%d err=%v", audit, err)
	}
}
