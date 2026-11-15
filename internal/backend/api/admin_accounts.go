package api

import (
	"errors"
	"net/http"
	"strconv"
	"time"

	"mandatnik/internal/backend/adminauth"
	"mandatnik/internal/backend/store"
)

type adminAccountBody struct {
	Email       string `json:"email"`
	DisplayName string `json:"display_name"`
	Password    string `json:"password"`
}

// adminAccounts is the superadmin-only administrator-management API. The
// role check happens before the body or the target row is read, so an
// ordinary administrator cannot use this section at all. The request body has
// no role field; DisallowUnknownFields rejects attempts to smuggle one in.
func (s *Server) adminAccounts(w http.ResponseWriter, r *http.Request, session *store.AdminSession, parts []string) {
	if !s.requireAdminRole(w, session, store.AdminRoleSuperAdmin) {
		return
	}
	switch {
	case len(parts) == 1 && r.Method == http.MethodGet:
		s.adminListAccounts(w, r)
	case len(parts) == 1 && r.Method == http.MethodPost:
		s.adminCreateAccount(w, r, session)
	case len(parts) == 2 && r.Method == http.MethodPut:
		id, ok := adminAccountID(w, parts[1])
		if !ok {
			return
		}
		s.adminUpdateAccount(w, r, session, id)
	case len(parts) == 2 && r.Method == http.MethodDelete:
		id, ok := adminAccountID(w, parts[1])
		if !ok {
			return
		}
		s.adminDeleteAccount(w, r, session, id)
	case len(parts) == 3 && r.Method == http.MethodPost && parts[2] == "freeze":
		id, ok := adminAccountID(w, parts[1])
		if !ok {
			return
		}
		s.adminSetAccountFrozen(w, r, session, id, true)
	case len(parts) == 3 && r.Method == http.MethodPost && parts[2] == "unfreeze":
		id, ok := adminAccountID(w, parts[1])
		if !ok {
			return
		}
		s.adminSetAccountFrozen(w, r, session, id, false)
	default:
		writeAdminError(w, http.StatusNotFound, "not_found", "not found")
	}
}

func adminAccountID(w http.ResponseWriter, raw string) (int64, bool) {
	id, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || id <= 0 {
		writeAdminError(w, http.StatusBadRequest, "invalid_admin", "invalid administrator identifier")
		return 0, false
	}
	return id, true
}

func (s *Server) adminListAccounts(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := contextWithTimeout(r, 15*time.Second)
	defer cancel()
	items, err := s.store.ListAdminAccounts(ctx)
	if err != nil {
		s.logf("admin accounts list failed: %v", err)
		writeAdminError(w, http.StatusServiceUnavailable, "database_error", "could not load administrators")
		return
	}
	writeAdminJSON(w, http.StatusOK, map[string]any{"items": items})
}

func (s *Server) adminCreateAccount(w http.ResponseWriter, r *http.Request, session *store.AdminSession) {
	var input adminAccountBody
	if err := readAdminJSON(w, r, &input); err != nil {
		writeAdminError(w, http.StatusBadRequest, "invalid_json", err.Error())
		return
	}
	email, err := store.NormalizeAdminEmail(input.Email)
	if err != nil {
		writeAdminError(w, http.StatusUnprocessableEntity, "invalid_admin", err.Error())
		return
	}
	displayName, err := store.NormalizeAdminDisplayName(input.DisplayName)
	if err != nil {
		writeAdminError(w, http.StatusUnprocessableEntity, "invalid_admin", err.Error())
		return
	}
	passwordHash, err := adminauth.Hash(input.Password)
	if err != nil {
		writeAdminError(w, http.StatusUnprocessableEntity, "invalid_admin", err.Error())
		return
	}
	ctx, cancel := contextWithTimeout(r, 15*time.Second)
	defer cancel()
	record, err := s.store.CreateAdminAccount(ctx, email, displayName, passwordHash, session.Email)
	if err != nil {
		s.writeAdminAccountError(w, err, "could not create administrator")
		return
	}
	writeAdminJSON(w, http.StatusCreated, record)
}

func (s *Server) adminUpdateAccount(w http.ResponseWriter, r *http.Request, session *store.AdminSession, id int64) {
	var input adminAccountBody
	if err := readAdminJSON(w, r, &input); err != nil {
		writeAdminError(w, http.StatusBadRequest, "invalid_json", err.Error())
		return
	}
	email, err := store.NormalizeAdminEmail(input.Email)
	if err != nil {
		writeAdminError(w, http.StatusUnprocessableEntity, "invalid_admin", err.Error())
		return
	}
	displayName, err := store.NormalizeAdminDisplayName(input.DisplayName)
	if err != nil {
		writeAdminError(w, http.StatusUnprocessableEntity, "invalid_admin", err.Error())
		return
	}
	passwordHash := ""
	if input.Password != "" {
		passwordHash, err = adminauth.Hash(input.Password)
		if err != nil {
			writeAdminError(w, http.StatusUnprocessableEntity, "invalid_admin", err.Error())
			return
		}
	}
	ctx, cancel := contextWithTimeout(r, 15*time.Second)
	defer cancel()
	record, err := s.store.UpdateAdminAccount(ctx, id, email, displayName, passwordHash, session.Email)
	if err != nil {
		s.writeAdminAccountError(w, err, "could not update administrator")
		return
	}
	writeAdminJSON(w, http.StatusOK, record)
}

func (s *Server) adminSetAccountFrozen(w http.ResponseWriter, r *http.Request, session *store.AdminSession, id int64, disabled bool) {
	ctx, cancel := contextWithTimeout(r, 15*time.Second)
	defer cancel()
	record, err := s.store.SetAdminDisabled(ctx, id, disabled, session.Email)
	if err != nil {
		s.writeAdminAccountError(w, err, "could not change administrator state")
		return
	}
	writeAdminJSON(w, http.StatusOK, record)
}

func (s *Server) adminDeleteAccount(w http.ResponseWriter, r *http.Request, session *store.AdminSession, id int64) {
	ctx, cancel := contextWithTimeout(r, 15*time.Second)
	defer cancel()
	if err := s.store.DeleteAdminAccount(ctx, id, session.Email); err != nil {
		s.writeAdminAccountError(w, err, "could not delete administrator")
		return
	}
	writeAdminJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) writeAdminAccountError(w http.ResponseWriter, err error, message string) {
	switch {
	case errors.Is(err, store.ErrAdminAccountNotFound):
		writeAdminError(w, http.StatusNotFound, "not_found", "administrator not found")
	case errors.Is(err, store.ErrAdminAccountProtected):
		writeAdminError(w, http.StatusForbidden, "forbidden", "superadmin accounts are protected")
	case errors.Is(err, store.ErrAdminEmailConflict):
		writeAdminError(w, http.StatusConflict, "email_conflict", "administrator email is already in use")
	default:
		s.logf("administrator management failed: %v", err)
		writeAdminError(w, http.StatusServiceUnavailable, "database_error", message)
	}
}
