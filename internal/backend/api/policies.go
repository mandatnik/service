package api

import (
	"database/sql"
	"errors"
	"github.com/microsoft/go-mssqldb"
	"net/http"
	"telehack2026/internal/backend/store"
	"time"
)

func (s *Server) adminInventory(w http.ResponseWriter, r *http.Request, session *store.AdminSession, parts []string) {
	ctx, cancel := contextWithTimeout(r, 20*time.Second)
	defer cancel()
	fail := func(err error) {
		if errors.Is(err, sql.ErrNoRows) {
			writeAdminError(w, 404, "not_found", "Группа или политика не найдена")
			return
		}
		var dbErr mssql.Error
		if errors.As(err, &dbErr) {
			switch dbErr.Number {
			case 2627, 2601:
				writeAdminError(w, 409, "name_conflict", "Такое название уже используется")
			case 547:
				writeAdminError(w, 400, "invalid_assignment", "Машина или группа назначения не найдена")
			default:
				s.logf("inventory settings: %v", err)
				writeAdminError(w, 500, "database_error", "Не удалось сохранить настройки")
			}
			return
		}
		writeAdminError(w, 400, "invalid_settings", err.Error())
	}
	if len(parts) == 1 && parts[0] == "inventory-settings" && r.Method == http.MethodGet {
		out, err := s.store.InventorySettings(ctx)
		if err != nil {
			s.logf("inventory settings: %v", err)
			writeAdminError(w, 500, "database_error", "Не удалось загрузить группы и политики")
			return
		}
		writeAdminJSON(w, 200, out)
		return
	}
	if len(parts) == 3 && parts[0] == "groups" && parts[2] == "members" && r.Method == http.MethodPost {
		var input struct {
			MachineIDs []string `json:"machine_ids"`
		}
		if err := readAdminJSON(w, r, &input); err != nil {
			fail(err)
			return
		}
		if err := s.store.AddGroupMembers(ctx, parts[1], input.MachineIDs, session.Email); err != nil {
			fail(err)
			return
		}
		writeAdminJSON(w, 200, map[string]bool{"saved": true})
		return
	}
	create := len(parts) == 1 && r.Method == http.MethodPost
	update := len(parts) == 2 && r.Method == http.MethodPut
	if (create || update) && parts[0] == "groups" {
		var input store.MachineGroup
		if err := readAdminJSON(w, r, &input); err != nil {
			fail(err)
			return
		}
		if update {
			input.ID = parts[1]
		}
		id, err := s.store.SaveGroup(ctx, input, create, session.Email)
		if err != nil {
			fail(err)
			return
		}
		writeAdminJSON(w, 200, map[string]string{"id": id})
		return
	}
	if (create || update) && parts[0] == "folder-policies" {
		var input store.FolderPolicy
		if err := readAdminJSON(w, r, &input); err != nil {
			fail(err)
			return
		}
		if update {
			input.ID = parts[1]
		}
		id, err := s.store.SaveFolderPolicy(ctx, input, create, session.Email)
		if err != nil {
			fail(err)
			return
		}
		writeAdminJSON(w, 200, map[string]string{"id": id})
		return
	}
	if len(parts) == 2 && r.Method == http.MethodDelete && (parts[0] == "groups" || parts[0] == "folder-policies") {
		if err := s.store.DeleteInventoryItem(ctx, parts[0], parts[1], session.Email); err != nil {
			fail(err)
			return
		}
		writeAdminJSON(w, 200, map[string]bool{"deleted": true})
		return
	}
	writeAdminError(w, 404, "not_found", "not found")
}
