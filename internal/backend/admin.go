package backend

import (
	"context"
	"fmt"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
	"telehack2026/internal/backend/config"
	"telehack2026/internal/backend/db"
	"telehack2026/internal/backend/store"
)

// HashAdminPassword produces the bcrypt hash format used by the
// administrators table. The plaintext is never persisted or logged.
func HashAdminPassword(password string) (string, error) {
	if len(password) < 12 {
		return "", fmt.Errorf("administrator password must contain at least 12 characters")
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), 12)
	if err != nil {
		return "", fmt.Errorf("hash administrator password: %w", err)
	}
	return string(hash), nil
}

// CreateOrUpdateAdmin is the supported local bootstrap path. It connects with
// the runtime SQL login and writes only a bcrypt hash. Administrators can also
// be inserted directly with the documented SQL and hash-password command.
func CreateOrUpdateAdmin(configPath, username, password string) error {
	username = strings.TrimSpace(username)
	if len(username) < 3 {
		return fmt.Errorf("username must contain at least 3 characters")
	}
	hash, err := HashAdminPassword(password)
	if err != nil {
		return err
	}
	cfg, err := config.Load(configPath)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	pool, err := db.Open(ctx, cfg.DB)
	if err != nil {
		return err
	}
	defer pool.Close()
	persistence := store.New(pool)
	id, err := persistence.UpsertAdmin(ctx, username, hash)
	if err != nil {
		return err
	}
	fmt.Printf("administrator %q is ready (id=%d)\n", username, id)
	return nil
}
