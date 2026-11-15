package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
)

var (
	// ErrAdminAccountNotFound is returned when the addressed administrator
	// does not exist.
	ErrAdminAccountNotFound = errors.New("administrator account not found")
	// ErrAdminAccountProtected prevents this API from changing or deleting
	// superadmin accounts. Superadmin credentials are managed only by the
	// local bootstrap path.
	ErrAdminAccountProtected = errors.New("superadmin accounts cannot be changed through administrator management")
	// ErrAdminEmailConflict is returned when another administrator already
	// uses the requested email.
	ErrAdminEmailConflict = errors.New("administrator email is already in use")
)

// AdminRecord is the safe administrator projection returned to the admin UI.
// It intentionally has no password hash field.
type AdminRecord struct {
	ID          int64     `json:"id"`
	Email       string    `json:"email"`
	DisplayName string    `json:"display_name"`
	Role        string    `json:"role"`
	Disabled    bool      `json:"disabled"`
	CreatedAt   time.Time `json:"created_at"`
}

func (s *Store) ListAdminAccounts(ctx context.Context) ([]AdminRecord, error) {
	rows, err := s.DB.QueryContext(ctx, `
SELECT admin_id, email, display_name, role, disabled, created_at
FROM dbo.administrators
ORDER BY CASE WHEN role=N'superadmin' THEN 0 ELSE 1 END, display_name, admin_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []AdminRecord{}
	for rows.Next() {
		var item AdminRecord
		if err := rows.Scan(&item.ID, &item.Email, &item.DisplayName, &item.Role, &item.Disabled, &item.CreatedAt); err != nil {
			return nil, err
		}
		item.CreatedAt = item.CreatedAt.UTC()
		out = append(out, item)
	}
	return out, rows.Err()
}

func (s *Store) CreateAdminAccount(ctx context.Context, email, displayName, passwordHash, actor string) (*AdminRecord, error) {
	email, err := NormalizeAdminEmail(email)
	if err != nil {
		return nil, err
	}
	displayName, err = NormalizeAdminDisplayName(displayName)
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(passwordHash) == "" {
		return nil, fmt.Errorf("administrator password hash is required")
	}
	now := s.now()
	tx, err := s.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	var id int64
	err = tx.QueryRowContext(ctx, `
INSERT INTO dbo.administrators(username,email,display_name,role,password_hash,disabled,created_at)
OUTPUT INSERTED.admin_id
VALUES(LEFT(@p1,128),@p1,@p2,N'admin',@p3,0,@p4)`, email, displayName, passwordHash, now).Scan(&id)
	if err != nil {
		if isDuplicateKey(err) {
			return nil, ErrAdminEmailConflict
		}
		return nil, fmt.Errorf("create administrator: %w", err)
	}
	record, err := adminRecordTx(ctx, tx, id)
	if err != nil {
		return nil, err
	}
	if err := insertEvent(ctx, tx, nil, nil, nil, nil, "admin_created", "info",
		"superadmin created an administrator account",
		map[string]any{"actor": actor, "target_admin_id": id, "target_email": email, "display_name": displayName}, now); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return record, nil
}

// UpdateAdminAccount changes email, display name and optionally the password
// of a regular administrator. Role and disabled state are deliberately not
// writable here. Changing login data revokes existing sessions so a stolen
// session cannot outlive the old credentials.
func (s *Store) UpdateAdminAccount(ctx context.Context, id int64, email, displayName, passwordHash, actor string) (*AdminRecord, error) {
	email, err := NormalizeAdminEmail(email)
	if err != nil {
		return nil, err
	}
	displayName, err = NormalizeAdminDisplayName(displayName)
	if err != nil {
		return nil, err
	}
	now := s.now()
	tx, err := s.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	var currentEmail, role string
	if err := tx.QueryRowContext(ctx, `
SELECT email,role FROM dbo.administrators WITH (UPDLOCK,HOLDLOCK) WHERE admin_id=@p1`, id).Scan(&currentEmail, &role); errors.Is(err, sql.ErrNoRows) {
		return nil, ErrAdminAccountNotFound
	} else if err != nil {
		return nil, err
	}
	if role != AdminRoleAdmin {
		return nil, ErrAdminAccountProtected
	}
	passwordChanged := strings.TrimSpace(passwordHash) != ""
	if passwordChanged {
		_, err = tx.ExecContext(ctx, `
UPDATE dbo.administrators SET email=@p1,display_name=@p2,password_hash=@p3 WHERE admin_id=@p4 AND role=N'admin'`,
			email, displayName, passwordHash, id)
	} else {
		_, err = tx.ExecContext(ctx, `
UPDATE dbo.administrators SET email=@p1,display_name=@p2 WHERE admin_id=@p3 AND role=N'admin'`,
			email, displayName, id)
	}
	if err != nil {
		if isDuplicateKey(err) {
			return nil, ErrAdminEmailConflict
		}
		return nil, fmt.Errorf("update administrator: %w", err)
	}
	emailChanged := !strings.EqualFold(currentEmail, email)
	if emailChanged || passwordChanged {
		if _, err := tx.ExecContext(ctx, `
UPDATE dbo.admin_sessions SET revoked_at=@p1 WHERE admin_id=@p2 AND revoked_at IS NULL`, now, id); err != nil {
			return nil, err
		}
	}
	record, err := adminRecordTx(ctx, tx, id)
	if err != nil {
		return nil, err
	}
	if err := insertEvent(ctx, tx, nil, nil, nil, nil, "admin_updated", "warning",
		"superadmin changed an administrator account",
		map[string]any{"actor": actor, "target_admin_id": id, "old_email": currentEmail, "new_email": email,
			"display_name": displayName, "email_changed": emailChanged, "password_changed": passwordChanged,
			"sessions_revoked": emailChanged || passwordChanged}, now); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return record, nil
}

func (s *Store) SetAdminDisabled(ctx context.Context, id int64, disabled bool, actor string) (*AdminRecord, error) {
	now := s.now()
	tx, err := s.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	var email, displayName, role string
	if err := tx.QueryRowContext(ctx, `
SELECT email,display_name,role FROM dbo.administrators WITH (UPDLOCK,HOLDLOCK) WHERE admin_id=@p1`, id).
		Scan(&email, &displayName, &role); errors.Is(err, sql.ErrNoRows) {
		return nil, ErrAdminAccountNotFound
	} else if err != nil {
		return nil, err
	}
	if role != AdminRoleAdmin {
		return nil, ErrAdminAccountProtected
	}
	if _, err := tx.ExecContext(ctx, `
UPDATE dbo.administrators SET disabled=@p1 WHERE admin_id=@p2 AND role=N'admin'`, disabled, id); err != nil {
		return nil, fmt.Errorf("set administrator state: %w", err)
	}
	if disabled {
		if _, err := tx.ExecContext(ctx, `
UPDATE dbo.admin_sessions SET revoked_at=@p1 WHERE admin_id=@p2 AND revoked_at IS NULL`, now, id); err != nil {
			return nil, err
		}
	}
	record, err := adminRecordTx(ctx, tx, id)
	if err != nil {
		return nil, err
	}
	kind := "admin_unfrozen"
	message := "superadmin unfroze an administrator account"
	if disabled {
		kind = "admin_frozen"
		message = "superadmin froze an administrator account and revoked its sessions"
	}
	if err := insertEvent(ctx, tx, nil, nil, nil, nil, kind, "warning", message,
		map[string]any{"actor": actor, "target_admin_id": id, "target_email": email, "display_name": displayName}, now); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return record, nil
}

// DeleteAdminAccount removes a regular administrator after deleting its
// sessions. Audit rows and task/license author strings are not foreign keys,
// so the historical actor identity remains readable after deletion.
func (s *Store) DeleteAdminAccount(ctx context.Context, id int64, actor string) error {
	now := s.now()
	tx, err := s.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var email, displayName, role string
	if err := tx.QueryRowContext(ctx, `
SELECT email,display_name,role FROM dbo.administrators WITH (UPDLOCK,HOLDLOCK) WHERE admin_id=@p1`, id).
		Scan(&email, &displayName, &role); errors.Is(err, sql.ErrNoRows) {
		return ErrAdminAccountNotFound
	} else if err != nil {
		return err
	}
	if role != AdminRoleAdmin {
		return ErrAdminAccountProtected
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM dbo.admin_sessions WHERE admin_id=@p1`, id); err != nil {
		return err
	}
	result, err := tx.ExecContext(ctx, `DELETE FROM dbo.administrators WHERE admin_id=@p1 AND role=N'admin'`, id)
	if err != nil {
		return err
	}
	affected, _ := result.RowsAffected()
	if affected != 1 {
		return ErrAdminAccountNotFound
	}
	if err := insertEvent(ctx, tx, nil, nil, nil, nil, "admin_deleted", "warning",
		"superadmin deleted an administrator account and terminated its sessions",
		map[string]any{"actor": actor, "target_admin_id": id, "target_email": email, "display_name": displayName}, now); err != nil {
		return err
	}
	return tx.Commit()
}

// RevokeAdminSessions terminates every existing browser session for one
// administrator. Freeze, delete and credential changes call it inline; it is
// also useful for operational tests and future security actions.
func (s *Store) RevokeAdminSessions(ctx context.Context, adminID int64) error {
	_, err := s.DB.ExecContext(ctx, `
UPDATE dbo.admin_sessions SET revoked_at=@p1 WHERE admin_id=@p2 AND revoked_at IS NULL`, s.now(), adminID)
	return err
}

func adminRecordTx(ctx context.Context, tx *sql.Tx, id int64) (*AdminRecord, error) {
	var record AdminRecord
	if err := tx.QueryRowContext(ctx, `
SELECT admin_id,email,display_name,role,disabled,created_at FROM dbo.administrators WHERE admin_id=@p1`, id).
		Scan(&record.ID, &record.Email, &record.DisplayName, &record.Role, &record.Disabled, &record.CreatedAt); errors.Is(err, sql.ErrNoRows) {
		return nil, ErrAdminAccountNotFound
	} else if err != nil {
		return nil, err
	}
	record.CreatedAt = record.CreatedAt.UTC()
	return &record, nil
}
