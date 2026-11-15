// Superadministrator lifecycle for the setup wizard and the local recovery
// command: creation of the first superadmin and password reset without knowing
// the old one, with session revocation and a secret-free audit record.
package setup

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"mandatnik/internal/backend/store"
)

// AdminEntry is a minimal superadministrator descriptor for interactive use.
type AdminEntry struct {
	ID          int64
	Email       string
	DisplayName string
	Role        string
	Disabled    bool
}

// ListSuperadmins returns the superadministrators in canonical email order.
func ListSuperadmins(ctx context.Context, pool *sql.DB) ([]AdminEntry, error) {
	rows, err := pool.QueryContext(ctx, `
SELECT admin_id, email, display_name, role, disabled
FROM dbo.administrators WHERE role=N'superadmin' ORDER BY email`)
	if err != nil {
		return nil, fmt.Errorf("список суперадминистраторов: %w", err)
	}
	defer rows.Close()
	var out []AdminEntry
	for rows.Next() {
		var entry AdminEntry
		if err := rows.Scan(&entry.ID, &entry.Email, &entry.DisplayName, &entry.Role, &entry.Disabled); err != nil {
			return nil, err
		}
		out = append(out, entry)
	}
	return out, rows.Err()
}

// ResolveSuperadmin finds exactly one superadministrator by email, or the only
// existing one when the email is empty.
func ResolveSuperadmin(ctx context.Context, pool *sql.DB, email string) (*AdminEntry, error) {
	list, err := ListSuperadmins(ctx, pool)
	if err != nil {
		return nil, err
	}
	if len(list) == 0 {
		return nil, errors.New("в системе нет суперадминистраторов")
	}
	email = strings.ToLower(strings.TrimSpace(email))
	if email == "" {
		if len(list) > 1 {
			return nil, errors.New("суперадминистраторов несколько; укажите email")
		}
		return &list[0], nil
	}
	for i := range list {
		if list[i].Email == email {
			return &list[i], nil
		}
	}
	return nil, fmt.Errorf("суперадминистратор с email %s не найден", email)
}

// ResetSuperadminPassword sets a new password hash for the selected
// superadministrator, revokes their sessions and writes an audit record.
// The old hash is never read back or displayed.
func ResetSuperadminPassword(ctx context.Context, pool *sql.DB, adminID int64, newHash string) error {
	if strings.TrimSpace(newHash) == "" {
		return errors.New("новый пароль не задан")
	}
	persistence := store.New(pool)
	tx, err := pool.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var email, displayName string
	if err := tx.QueryRowContext(ctx, `SELECT email, display_name FROM dbo.administrators WHERE admin_id=@p1 AND role=N'superadmin'`, adminID).
		Scan(&email, &displayName); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return errors.New("суперадминистратор не найден")
		}
		return err
	}
	now := time.Now().UTC()
	if _, err := tx.ExecContext(ctx, `
UPDATE dbo.administrators SET password_hash=@p1, disabled=0 WHERE admin_id=@p2`, newHash, adminID); err != nil {
		return fmt.Errorf("обновляю пароль: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `
UPDATE dbo.admin_sessions SET revoked_at=@p1 WHERE admin_id=@p2 AND revoked_at IS NULL`, now, adminID); err != nil {
		return fmt.Errorf("отменя сессии: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `
INSERT INTO dbo.events (machine_id, registration_id, report_id, request_id, kind, severity, message, details_json, created_at)
VALUES (NULL, NULL, NULL, NULL, N'admin_password_reset', N'warning',
        N'локально восстановлен доступ суперадминистратора', @p3, @p4)`,
		fmt.Sprintf(`{"admin_id":%d,"email":%q}`, adminID, email), now); err != nil {
		return fmt.Errorf("запись аудита: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	_ = persistence
	return nil
}
