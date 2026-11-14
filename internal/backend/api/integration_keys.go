package api

import (
	"database/sql"
	"errors"
	"net/http"
	"strings"
	"time"

	"telehack2026/internal/backend/store"
	"telehack2026/internal/protocol"
)

type adminIntegrationKey struct {
	store.IntegrationKey
	Status string `json:"status"`
}

func (s *Server) adminAPIKeys(w http.ResponseWriter, r *http.Request, session *store.AdminSession, parts []string) {
	ctx, cancel := contextWithTimeout(r, 10*time.Second)
	defer cancel()
	switch {
	case len(parts) == 1 && r.Method == http.MethodGet:
		keys, err := s.store.ListIntegrationKeys(ctx)
		if err != nil {
			s.logf("admin API keys list failed: %v", err)
			writeAdminError(w, http.StatusServiceUnavailable, "database_error", "Не удалось загрузить API-ключи")
			return
		}
		items := make([]adminIntegrationKey, 0, len(keys))
		for _, key := range keys {
			items = append(items, adminIntegrationKey{IntegrationKey: key, Status: key.Status()})
		}
		writeAdminJSON(w, http.StatusOK, map[string]any{"items": items})
	case len(parts) == 1 && r.Method == http.MethodPost:
		var input struct {
			Name       string   `json:"name"`
			AllowedIPs []string `json:"allowed_ips"`
		}
		if err := readAdminJSON(w, r, &input); err != nil {
			writeAdminError(w, http.StatusBadRequest, "invalid_json", "Неверный JSON: "+err.Error())
			return
		}
		name, err := validIntegrationKeyName(input.Name)
		if err != nil {
			writeAdminError(w, http.StatusBadRequest, "invalid_name", err.Error())
			return
		}
		allowed, err := store.NormalizeAllowedIPs(input.AllowedIPs)
		if err != nil {
			writeAdminError(w, http.StatusBadRequest, "invalid_ip", "Неверный IP/CIDR: "+err.Error())
			return
		}
		if len(allowed) == 0 {
			writeAdminError(w, http.StatusBadRequest, "invalid_ip", "Нужен хотя бы один IP/CIDR")
			return
		}
		token, prefix, err := newIntegrationToken()
		if err != nil {
			writeAdminError(w, http.StatusInternalServerError, "internal_error", "Не удалось создать ключ")
			return
		}
		keyID := protocol.NewUUID()
		if err := s.store.CreateIntegrationKey(ctx, keyID, name, store.TokenHash(token), prefix, allowed, session.Username); err != nil {
			s.logf("admin API key create failed: %v", err)
			writeAdminError(w, http.StatusServiceUnavailable, "database_error", "Не удалось сохранить API-ключ")
			return
		}
		s.store.InsertAdminEvent(ctx, nil, "api_key_created", "info", "administrator created an integration API key", map[string]any{
			"key_id": keyID, "name": name, "allowed_ips": allowed, "admin": session.Username,
		})
		writeAdminJSON(w, http.StatusCreated, map[string]any{
			"key_id": keyID, "name": name, "token": token, "token_prefix": prefix,
			"allowed_ips": allowed, "status": "active", "created_by": session.Username,
			"created_at": time.Now().UTC().Format(time.RFC3339Nano),
		})
	case len(parts) == 2 && (r.Method == http.MethodPut || r.Method == http.MethodDelete):
		keyID, err := protocol.NormalizeUUID(parts[1])
		if err != nil {
			writeAdminError(w, http.StatusBadRequest, "invalid_key", "Неверный идентификатор ключа")
			return
		}
		if r.Method == http.MethodDelete {
			if err := s.store.RevokeIntegrationKey(ctx, keyID, session.Username); err != nil {
				if errors.Is(err, sql.ErrNoRows) {
					writeAdminError(w, http.StatusNotFound, "not_found", "API-ключ не найден")
					return
				}
				s.logf("admin API key revoke failed: %v", err)
				writeAdminError(w, http.StatusServiceUnavailable, "database_error", "Не удалось отозвать API-ключ")
				return
			}
			s.store.InsertAdminEvent(ctx, nil, "api_key_revoked", "warning", "administrator revoked an integration API key", map[string]any{
				"key_id": keyID, "admin": session.Username,
			})
			writeAdminJSON(w, http.StatusOK, map[string]bool{"ok": true})
			return
		}
		var input struct {
			Name       *string   `json:"name"`
			AllowedIPs *[]string `json:"allowed_ips"`
		}
		if err := readAdminJSON(w, r, &input); err != nil {
			writeAdminError(w, http.StatusBadRequest, "invalid_json", "Неверный JSON: "+err.Error())
			return
		}
		if input.Name == nil && input.AllowedIPs == nil {
			writeAdminError(w, http.StatusBadRequest, "invalid_request", "Нужно передать name или allowed_ips")
			return
		}
		existing, err := s.store.IntegrationKeyByID(ctx, keyID)
		if errors.Is(err, sql.ErrNoRows) {
			writeAdminError(w, http.StatusNotFound, "not_found", "API-ключ не найден")
			return
		}
		if err != nil {
			s.logf("admin API key lookup failed: %v", err)
			writeAdminError(w, http.StatusServiceUnavailable, "database_error", "Не удалось загрузить API-ключ")
			return
		}
		name := existing.Name
		if input.Name != nil {
			name, err = validIntegrationKeyName(*input.Name)
			if err != nil {
				writeAdminError(w, http.StatusBadRequest, "invalid_name", err.Error())
				return
			}
		}
		allowed := existing.AllowedIPs
		allowedChanged := false
		if input.AllowedIPs != nil {
			allowed, err = store.NormalizeAllowedIPs(*input.AllowedIPs)
			if err != nil {
				writeAdminError(w, http.StatusBadRequest, "invalid_ip", "Неверный IP/CIDR: "+err.Error())
				return
			}
			allowedChanged = true
		}
		if err := s.store.UpdateIntegrationKey(ctx, keyID, name, allowed); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				writeAdminError(w, http.StatusNotFound, "not_found", "API-ключ не найден или отозван")
				return
			}
			s.logf("admin API key update failed: %v", err)
			writeAdminError(w, http.StatusServiceUnavailable, "database_error", "Не удалось изменить API-ключ")
			return
		}
		s.store.InsertAdminEvent(ctx, nil, "api_key_updated", "info", "administrator updated an integration API key", map[string]any{
			"key_id": keyID, "name": name, "allowed_ips": allowed, "allowed_ips_changed": allowedChanged, "admin": session.Username,
		})
		writeAdminJSON(w, http.StatusOK, map[string]bool{"ok": true})
	default:
		writeAdminError(w, http.StatusNotFound, "not_found", "not found")
	}
}

func validIntegrationKeyName(value string) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" || len([]rune(value)) > 200 || strings.ContainsAny(value, "\r\n\x00") {
		return "", errors.New("название ключа должно содержать 1..200 символов без переводов строк")
	}
	return value, nil
}
