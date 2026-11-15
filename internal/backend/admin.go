package backend

import (
	"context"
	"fmt"
	"time"

	"mandatnik/internal/backend/adminauth"
	"mandatnik/internal/backend/config"
	"mandatnik/internal/backend/db"
	"mandatnik/internal/backend/store"
)

// HashAdminPassword produces the bcrypt hash format used by the
// administrators table. The plaintext is never persisted or logged.
func HashAdminPassword(password string) (string, error) {
	return adminauth.Hash(password)
}

// CreateOrUpdateAdmin is the supported local bootstrap path. It connects with
// the runtime SQL login and writes only a bcrypt hash. Administrators can also
// be inserted directly with the documented SQL and hash-password command.
func CreateOrUpdateAdmin(configPath, email, displayName, role, password string) error {
	email, err := store.NormalizeAdminEmail(email)
	if err != nil {
		return err
	}
	displayName, err = store.NormalizeAdminDisplayName(displayName)
	if err != nil {
		return err
	}
	role, err = store.NormalizeAdminRole(role)
	if err != nil {
		return err
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
	id, err := persistence.UpsertAdmin(ctx, email, displayName, role, hash)
	if err != nil {
		return err
	}
	fmt.Printf("administrator %q (%s, %s) is ready (id=%d)\n", displayName, email, role, id)
	return nil
}
