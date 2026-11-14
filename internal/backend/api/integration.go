package api

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	mssql "github.com/microsoft/go-mssqldb"
	"telehack2026/internal/backend/store"
	"telehack2026/internal/protocol"
)

const (
	integrationAPIPrefix = "/api/integration/v1/"
	integrationTokenTTL  = 2 * time.Second
)

// IntegrationHandler returns the integration listener handler. It is a separate
// HTTP surface from the agent and admin APIs and uses bearer API keys.
func (s *Server) IntegrationHandler() http.Handler {
	return http.HandlerFunc(s.handleIntegration)
}

func (s *Server) handleIntegration(w http.ResponseWriter, r *http.Request) {
	started := time.Now()
	recorder := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
	defer func() {
		if recovered := recover(); recovered != nil {
			s.logf("panic serving integration %s %s: %v", r.Method, r.URL.Path, recovered)
			if !recorder.wrote {
				writeIntegrationError(recorder, http.StatusInternalServerError, protocol.CodeInternal, "internal error")
			}
		}
		s.logf("integration %s %s status=%d duration=%s remote=%s", r.Method, r.URL.Path, recorder.status, time.Since(started).Round(time.Millisecond), remoteHost(r))
	}()
	key, ok := s.authenticateIntegration(recorder, r)
	if !ok {
		return
	}
	path := strings.TrimPrefix(r.URL.Path, integrationAPIPrefix)
	if path == r.URL.Path || path == "" {
		writeIntegrationError(recorder, http.StatusNotFound, protocol.CodeNotFound, "unknown integration endpoint")
		return
	}
	parts := strings.Split(strings.Trim(path, "/"), "/")
	switch parts[0] {
	case "machines":
		s.integrationMachines(recorder, r, parts, key)
	case "groups":
		s.integrationGroups(recorder, r, parts, key)
	case "folder-policies":
		s.integrationPolicies(recorder, r, parts, key)
	case "certificates":
		s.integrationCertificates(recorder, r, parts)
	case "licensing":
		s.integrationLicenses(recorder, r, parts)
	case "events":
		s.integrationEvents(recorder, r, parts)
	case "scan-jobs":
		s.integrationJobs(recorder, r, parts, key)
	default:
		writeIntegrationError(recorder, http.StatusNotFound, protocol.CodeNotFound, "unknown integration endpoint")
	}
}

func (s *Server) authenticateIntegration(w http.ResponseWriter, r *http.Request) (*store.IntegrationKey, bool) {
	header := strings.TrimSpace(r.Header.Get("Authorization"))
	if header == "" {
		writeIntegrationError(w, http.StatusUnauthorized, protocol.CodeUnauthorized, "API key is required")
		return nil, false
	}
	scheme, value, found := strings.Cut(header, " ")
	if !found || !strings.EqualFold(scheme, "Bearer") {
		writeIntegrationError(w, http.StatusUnauthorized, protocol.CodeUnauthorized, "Authorization header must use Bearer")
		return nil, false
	}
	token := strings.TrimSpace(value)
	if !validIntegrationToken(token) {
		writeIntegrationError(w, http.StatusUnauthorized, protocol.CodeUnauthorized, "invalid API key format")
		return nil, false
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	key, err := s.store.IntegrationKeyByHash(ctx, store.TokenHash(token))
	if errors.Is(err, sql.ErrNoRows) {
		writeIntegrationError(w, http.StatusUnauthorized, protocol.CodeUnauthorized, "unknown API key")
		return nil, false
	}
	if err != nil {
		s.logf("integration key lookup failed: %v", err)
		writeIntegrationError(w, http.StatusServiceUnavailable, protocol.CodeDatabase, "could not validate API key")
		return nil, false
	}
	if key.RevokedAt != nil {
		writeIntegrationError(w, http.StatusUnauthorized, protocol.CodeUnauthorized, "API key is revoked")
		return nil, false
	}
	ip := sourceIP(r)
	if !key.AllowsIP(ip) {
		writeIntegrationError(w, http.StatusForbidden, protocol.CodeIPNotAllowed, "source IP is not allowed for this API key")
		return nil, false
	}
	touchCtx, touchCancel := context.WithTimeout(context.Background(), integrationTokenTTL)
	defer touchCancel()
	if err := s.store.TouchIntegrationKey(touchCtx, key.KeyID, ip); err != nil {
		s.logf("integration key touch failed: %v", err)
	}
	return key, true
}

func validIntegrationToken(token string) bool {
	if len(token) != len("mndk_")+64 && len(token) != len("thak_")+64 {
		return false
	}
	if !strings.HasPrefix(token, "mndk_") && !strings.HasPrefix(token, "thak_") {
		return false
	}
	_, err := hex.DecodeString(token[5:])
	return err == nil
}

func integrationActor(key *store.IntegrationKey) string {
	if key == nil {
		return ""
	}
	if strings.TrimSpace(key.Name) != "" {
		return key.Name
	}
	return "api-key:" + key.KeyID
}

func writeIntegrationJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", protocol.ContentTypeJSON)
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func writeIntegrationError(w http.ResponseWriter, status int, code, message string) {
	writeIntegrationJSON(w, status, protocol.ErrorResponse{Error: protocol.APIError{Code: code, Message: message}})
}

func (s *Server) integrationFunctionError(w http.ResponseWriter, err error, operation string) {
	switch {
	case errors.Is(err, sql.ErrNoRows):
		writeIntegrationError(w, http.StatusNotFound, protocol.CodeNotFound, "entity not found")
	case errors.Is(err, store.ErrInvalidRules):
		writeIntegrationError(w, http.StatusUnprocessableEntity, protocol.CodeInvalidRules, err.Error())
	case errors.Is(err, store.ErrUnknownMachine):
		writeIntegrationError(w, http.StatusBadRequest, protocol.CodeInvalidRequest, err.Error())
	case errors.Is(err, store.ErrGroupNotFound):
		writeIntegrationError(w, http.StatusNotFound, protocol.CodeNotFound, "group not found")
	default:
		var dbErr mssql.Error
		if errors.As(err, &dbErr) {
			switch dbErr.Number {
			case 2627, 2601:
				writeIntegrationError(w, http.StatusConflict, protocol.CodeDuplicateName, "name is already in use")
				return
			case 547:
				writeIntegrationError(w, http.StatusBadRequest, protocol.CodeInvalidRequest, "referenced machine or group does not exist")
				return
			}
		}
		s.logf("integration %s failed: %v", operation, err)
		writeIntegrationError(w, http.StatusInternalServerError, protocol.CodeDatabase, "database operation failed")
	}
}

func readIntegrationJSON(w http.ResponseWriter, r *http.Request, target any) *protocol.APIError {
	r.Body = http.MaxBytesReader(w, r.Body, 256*1024)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		if errors.Is(err, io.EOF) {
			return &protocol.APIError{Code: protocol.CodeInvalidJSON, Message: "empty request body"}
		}
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			return &protocol.APIError{Code: protocol.CodePayloadTooLarge, Message: "request body exceeds limit"}
		}
		return &protocol.APIError{Code: protocol.CodeInvalidJSON, Message: "invalid JSON: " + err.Error()}
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return &protocol.APIError{Code: protocol.CodeInvalidJSON, Message: "request body contains trailing JSON"}
	}
	return nil
}

func ensureIntegrationJSON(w http.ResponseWriter, r *http.Request) bool {
	if !strings.HasPrefix(strings.ToLower(r.Header.Get("Content-Type")), protocol.ContentTypeJSON) {
		writeIntegrationError(w, http.StatusBadRequest, protocol.CodeInvalidJSON, "Content-Type must be application/json")
		return false
	}
	return true
}

func integrationPage(r *http.Request) (int, int, *protocol.APIError) {
	page := 1
	pageSize := 50
	if raw := strings.TrimSpace(r.URL.Query().Get("page")); raw != "" {
		value, err := strconv.Atoi(raw)
		if err != nil || value < 1 {
			return 0, 0, &protocol.APIError{Code: protocol.CodeInvalidFilter, Message: "page must be an integer >= 1"}
		}
		page = value
	}
	if raw := strings.TrimSpace(r.URL.Query().Get("page_size")); raw != "" {
		value, err := strconv.Atoi(raw)
		if err != nil || value < 1 || value > 500 {
			return 0, 0, &protocol.APIError{Code: protocol.CodeInvalidFilter, Message: "page_size must be between 1 and 500"}
		}
		pageSize = value
	}
	return page, pageSize, nil
}

func integrationBool(r *http.Request, name string) (*bool, *protocol.APIError) {
	raw := strings.TrimSpace(r.URL.Query().Get(name))
	if raw == "" {
		return nil, nil
	}
	value, err := strconv.ParseBool(raw)
	if err != nil {
		return nil, &protocol.APIError{Code: protocol.CodeInvalidFilter, Message: name + " must be true or false"}
	}
	return &value, nil
}

func integrationInt(r *http.Request, name string, fallback, minimum, maximum int) (int, *protocol.APIError) {
	raw := strings.TrimSpace(r.URL.Query().Get(name))
	if raw == "" {
		return fallback, nil
	}
	value, err := strconv.Atoi(raw)
	if err != nil || value < minimum || value > maximum {
		return 0, &protocol.APIError{Code: protocol.CodeInvalidFilter, Message: fmt.Sprintf("%s must be between %d and %d", name, minimum, maximum)}
	}
	return value, nil
}

func integrationEnum(r *http.Request, name string, allowed map[string]bool) (string, *protocol.APIError) {
	raw := strings.TrimSpace(r.URL.Query().Get(name))
	if raw == "" {
		return "", nil
	}
	if !allowed[raw] {
		return "", &protocol.APIError{Code: protocol.CodeInvalidFilter, Message: "invalid " + name}
	}
	return raw, nil
}

func integrationUUID(r *http.Request, name string) (string, *protocol.APIError) {
	raw := strings.TrimSpace(r.URL.Query().Get(name))
	if raw == "" {
		return "", nil
	}
	value, err := protocol.NormalizeUUID(raw)
	if err != nil {
		return "", &protocol.APIError{Code: protocol.CodeInvalidFilter, Message: "invalid " + name}
	}
	return value, nil
}

func integrationTimestamp(r *http.Request, name string) (*time.Time, *protocol.APIError) {
	raw := strings.TrimSpace(r.URL.Query().Get(name))
	if raw == "" {
		return nil, nil
	}
	value, err := time.Parse(time.RFC3339Nano, raw)
	if err != nil {
		return nil, &protocol.APIError{Code: protocol.CodeInvalidFilter, Message: "invalid " + name}
	}
	value = value.UTC()
	return &value, nil
}

func integrationPathUUID(value string, field string) (string, *protocol.APIError) {
	normalized, err := protocol.NormalizeUUID(value)
	if err != nil {
		return "", &protocol.APIError{Code: protocol.CodeInvalidRequest, Message: "invalid " + field}
	}
	return normalized, nil
}

func integrationName(value string, field string) (string, *protocol.APIError) {
	value = strings.TrimSpace(value)
	if value == "" || len([]rune(value)) > 200 || strings.ContainsAny(value, "\r\n\x00") {
		return "", &protocol.APIError{Code: protocol.CodeInvalidRequest, Message: field + " must contain 1..200 characters without line breaks"}
	}
	return value, nil
}

func integrationIDs(values []string, field string) ([]string, *protocol.APIError) {
	result := make([]string, 0, len(values))
	seen := make(map[string]bool, len(values))
	for _, raw := range values {
		value, err := protocol.NormalizeUUID(raw)
		if err != nil {
			return nil, &protocol.APIError{Code: protocol.CodeInvalidRequest, Message: "invalid " + field}
		}
		if !seen[value] {
			seen[value] = true
			result = append(result, value)
		}
	}
	return result, nil
}

func paginate[T any](items []T, page, pageSize int) ([]T, int) {
	total := len(items)
	start := (page - 1) * pageSize
	if start >= total {
		return []T{}, total
	}
	end := start + pageSize
	if end > total {
		end = total
	}
	return items[start:end], total
}

func (s *Server) integrationMachines(w http.ResponseWriter, r *http.Request, parts []string, _ *store.IntegrationKey) {
	if len(parts) == 2 && r.Method == http.MethodGet {
		machineID, apiErr := integrationPathUUID(parts[1], "machine_id")
		if apiErr != nil {
			writeIntegrationAPIError(w, apiErr)
			return
		}
		ctx, cancel := contextWithTimeout(r, 15*time.Second)
		defer cancel()
		detail, err := s.store.IntegrationMachineDetail(ctx, machineID)
		if err != nil {
			s.integrationFunctionError(w, err, "machine detail")
			return
		}
		writeIntegrationJSON(w, http.StatusOK, detail)
		return
	}
	if len(parts) != 1 || r.Method != http.MethodGet {
		writeIntegrationError(w, http.StatusMethodNotAllowed, protocol.CodeMethodNotAllowed, "method not allowed")
		return
	}
	page, pageSize, apiErr := integrationPage(r)
	if apiErr != nil {
		writeIntegrationAPIError(w, apiErr)
		return
	}
	threshold, apiErr := integrationInt(r, "online_threshold_minutes", 30, 1, 1440)
	if apiErr != nil {
		writeIntegrationAPIError(w, apiErr)
		return
	}
	online, apiErr := integrationBool(r, "online")
	if apiErr != nil {
		writeIntegrationAPIError(w, apiErr)
		return
	}
	licenseStatus, apiErr := integrationEnum(r, "license_status", map[string]bool{
		"active": true, "expired": true, "not_installed": true, "error": true, "unknown": true,
	})
	if apiErr != nil {
		writeIntegrationAPIError(w, apiErr)
		return
	}
	groupID, apiErr := integrationUUID(r, "group_id")
	if apiErr != nil {
		writeIntegrationAPIError(w, apiErr)
		return
	}
	hostname := strings.TrimSpace(r.URL.Query().Get("hostname"))
	if len(hostname) > 253 {
		writeIntegrationError(w, http.StatusBadRequest, protocol.CodeInvalidFilter, "hostname is too long")
		return
	}
	ctx, cancel := contextWithTimeout(r, 20*time.Second)
	defer cancel()
	result, err := s.store.ListIntegrationMachines(ctx, store.IntegrationMachineFilter{
		Online: online, OnlineThresholdMinutes: threshold, LicenseStatus: licenseStatus,
		Hostname: hostname, GroupID: groupID, Page: page, PageSize: pageSize,
	})
	if err != nil {
		s.integrationFunctionError(w, err, "machines list")
		return
	}
	writeIntegrationJSON(w, http.StatusOK, result)
}

func (s *Server) integrationGroups(w http.ResponseWriter, r *http.Request, parts []string, key *store.IntegrationKey) {
	ctx, cancel := contextWithTimeout(r, 20*time.Second)
	defer cancel()
	if len(parts) == 1 && r.Method == http.MethodGet {
		settings, err := s.store.InventorySettings(ctx)
		if err != nil {
			s.integrationFunctionError(w, err, "groups list")
			return
		}
		items := make([]integrationGroup, 0, len(settings.Groups))
		for _, group := range settings.Groups {
			items = append(items, integrationGroup{
				GroupID: group.ID, Name: group.Name, MachineCount: len(group.MachineIDs), MachineIDs: group.MachineIDs,
			})
		}
		page, pageSize, apiErr := integrationPage(r)
		if apiErr != nil {
			writeIntegrationAPIError(w, apiErr)
			return
		}
		pageItems, total := paginate(items, page, pageSize)
		writeIntegrationJSON(w, http.StatusOK, store.Page[integrationGroup]{Items: pageItems, Page: page, PageSize: pageSize, Total: total})
		return
	}
	if len(parts) == 1 && r.Method == http.MethodPost {
		if !ensureIntegrationJSON(w, r) {
			return
		}
		var input integrationGroupUpsert
		if apiErr := readIntegrationJSON(w, r, &input); apiErr != nil {
			writeIntegrationAPIError(w, apiErr)
			return
		}
		name, apiErr := integrationName(input.Name, "name")
		if apiErr != nil {
			writeIntegrationAPIError(w, apiErr)
			return
		}
		machineIDs, apiErr := integrationIDs(input.MachineIDs, "machine_id")
		if apiErr != nil {
			writeIntegrationAPIError(w, apiErr)
			return
		}
		id, err := s.store.SaveGroup(ctx, store.MachineGroup{Name: name, MachineIDs: machineIDs}, true, integrationActor(key))
		if err != nil {
			s.integrationFunctionError(w, err, "group create")
			return
		}
		writeIntegrationJSON(w, http.StatusCreated, map[string]string{"group_id": id})
		return
	}
	if len(parts) == 2 {
		groupID, apiErr := integrationPathUUID(parts[1], "group_id")
		if apiErr != nil {
			writeIntegrationAPIError(w, apiErr)
			return
		}
		switch r.Method {
		case http.MethodGet:
			settings, err := s.store.InventorySettings(ctx)
			if err != nil {
				s.integrationFunctionError(w, err, "group detail")
				return
			}
			var group *store.MachineGroup
			for index := range settings.Groups {
				if strings.EqualFold(settings.Groups[index].ID, groupID) {
					group = &settings.Groups[index]
					break
				}
			}
			if group == nil {
				writeIntegrationError(w, http.StatusNotFound, protocol.CodeNotFound, "group not found")
				return
			}
			machines, err := s.integrationMachinesByIDs(ctx, group.MachineIDs)
			if err != nil {
				s.integrationFunctionError(w, err, "group machines")
				return
			}
			item := integrationGroup{GroupID: group.ID, Name: group.Name, MachineCount: len(group.MachineIDs), MachineIDs: group.MachineIDs, Machines: machines}
			writeIntegrationJSON(w, http.StatusOK, map[string]any{"group": item, "machines": machines})
			return
		case http.MethodPut:
			if !ensureIntegrationJSON(w, r) {
				return
			}
			var input integrationGroupUpsert
			if apiErr := readIntegrationJSON(w, r, &input); apiErr != nil {
				writeIntegrationAPIError(w, apiErr)
				return
			}
			name, apiErr := integrationName(input.Name, "name")
			if apiErr != nil {
				writeIntegrationAPIError(w, apiErr)
				return
			}
			machineIDs, apiErr := integrationIDs(input.MachineIDs, "machine_id")
			if apiErr != nil {
				writeIntegrationAPIError(w, apiErr)
				return
			}
			if _, err := s.store.SaveGroup(ctx, store.MachineGroup{ID: groupID, Name: name, MachineIDs: machineIDs}, false, integrationActor(key)); err != nil {
				s.integrationFunctionError(w, err, "group update")
				return
			}
			writeIntegrationJSON(w, http.StatusOK, map[string]bool{"ok": true})
			return
		case http.MethodDelete:
			if err := s.store.DeleteInventoryItem(ctx, "groups", groupID, integrationActor(key)); err != nil {
				s.integrationFunctionError(w, err, "group delete")
				return
			}
			writeIntegrationJSON(w, http.StatusOK, map[string]bool{"ok": true})
			return
		}
	}
	if len(parts) == 3 && parts[2] == "members" && (r.Method == http.MethodPost || r.Method == http.MethodDelete) {
		groupID, apiErr := integrationPathUUID(parts[1], "group_id")
		if apiErr != nil {
			writeIntegrationAPIError(w, apiErr)
			return
		}
		if !ensureIntegrationJSON(w, r) {
			return
		}
		var input integrationMachineIDs
		if apiErr := readIntegrationJSON(w, r, &input); apiErr != nil {
			writeIntegrationAPIError(w, apiErr)
			return
		}
		machineIDs, apiErr := integrationIDs(input.MachineIDs, "machine_id")
		if apiErr != nil {
			writeIntegrationAPIError(w, apiErr)
			return
		}
		if len(machineIDs) == 0 {
			writeIntegrationError(w, http.StatusBadRequest, protocol.CodeInvalidRequest, "machine_ids must not be empty")
			return
		}
		var err error
		if r.Method == http.MethodPost {
			err = s.store.AddGroupMembers(ctx, groupID, machineIDs, integrationActor(key))
		} else {
			err = s.store.RemoveGroupMembers(ctx, groupID, machineIDs, integrationActor(key))
		}
		if err != nil {
			s.integrationFunctionError(w, err, "group members")
			return
		}
		writeIntegrationJSON(w, http.StatusOK, map[string]bool{"ok": true})
		return
	}
	writeIntegrationError(w, http.StatusMethodNotAllowed, protocol.CodeMethodNotAllowed, "method not allowed")
}

func (s *Server) integrationMachinesByIDs(ctx context.Context, ids []string) ([]store.IntegrationMachine, error) {
	result := []store.IntegrationMachine{}
	for start := 0; start < len(ids); start += 500 {
		end := start + 500
		if end > len(ids) {
			end = len(ids)
		}
		page, err := s.store.ListIntegrationMachines(ctx, store.IntegrationMachineFilter{
			MachineIDs: ids[start:end], OnlineThresholdMinutes: 30, Page: 1, PageSize: 500,
		})
		if err != nil {
			return nil, err
		}
		result = append(result, page.Items...)
	}
	return result, nil
}

func (s *Server) integrationPolicies(w http.ResponseWriter, r *http.Request, parts []string, key *store.IntegrationKey) {
	ctx, cancel := contextWithTimeout(r, 20*time.Second)
	defer cancel()
	if len(parts) == 1 && r.Method == http.MethodGet {
		settings, err := s.store.InventorySettings(ctx)
		if err != nil {
			s.integrationFunctionError(w, err, "policies list")
			return
		}
		items := make([]integrationPolicy, 0, len(settings.Policies))
		for _, policy := range settings.Policies {
			items = append(items, integrationPolicy{
				PolicyID: policy.ID, Name: policy.Name, Rules: policy.Rules,
				MachineIDs: policy.MachineIDs, GroupIDs: policy.GroupIDs,
			})
		}
		page, pageSize, apiErr := integrationPage(r)
		if apiErr != nil {
			writeIntegrationAPIError(w, apiErr)
			return
		}
		pageItems, total := paginate(items, page, pageSize)
		writeIntegrationJSON(w, http.StatusOK, store.Page[integrationPolicy]{Items: pageItems, Page: page, PageSize: pageSize, Total: total})
		return
	}
	if len(parts) == 1 && r.Method == http.MethodPost {
		if !ensureIntegrationJSON(w, r) {
			return
		}
		var input integrationPolicyUpsert
		if apiErr := readIntegrationJSON(w, r, &input); apiErr != nil {
			writeIntegrationAPIError(w, apiErr)
			return
		}
		name, apiErr := integrationName(input.Name, "name")
		if apiErr != nil {
			writeIntegrationAPIError(w, apiErr)
			return
		}
		if strings.TrimSpace(input.Rules) == "" {
			writeIntegrationError(w, http.StatusUnprocessableEntity, protocol.CodeInvalidRules, "rules must not be empty")
			return
		}
		machineIDs, apiErr := integrationIDs(input.MachineIDs, "machine_id")
		if apiErr != nil {
			writeIntegrationAPIError(w, apiErr)
			return
		}
		groupIDs, apiErr := integrationIDs(input.GroupIDs, "group_id")
		if apiErr != nil {
			writeIntegrationAPIError(w, apiErr)
			return
		}
		id, err := s.store.SaveFolderPolicy(ctx, store.FolderPolicy{Name: name, Rules: input.Rules, MachineIDs: machineIDs, GroupIDs: groupIDs}, true, integrationActor(key))
		if err != nil {
			s.integrationFunctionError(w, err, "policy create")
			return
		}
		writeIntegrationJSON(w, http.StatusCreated, map[string]string{"policy_id": id})
		return
	}
	if len(parts) == 2 {
		policyID, apiErr := integrationPathUUID(parts[1], "policy_id")
		if apiErr != nil {
			writeIntegrationAPIError(w, apiErr)
			return
		}
		switch r.Method {
		case http.MethodGet:
			settings, err := s.store.InventorySettings(ctx)
			if err != nil {
				s.integrationFunctionError(w, err, "policy detail")
				return
			}
			for _, policy := range settings.Policies {
				if strings.EqualFold(policy.ID, policyID) {
					writeIntegrationJSON(w, http.StatusOK, integrationPolicy{
						PolicyID: policy.ID, Name: policy.Name, Rules: policy.Rules,
						MachineIDs: policy.MachineIDs, GroupIDs: policy.GroupIDs,
					})
					return
				}
			}
			writeIntegrationError(w, http.StatusNotFound, protocol.CodeNotFound, "policy not found")
			return
		case http.MethodPut:
			if !ensureIntegrationJSON(w, r) {
				return
			}
			var input integrationPolicyUpsert
			if apiErr := readIntegrationJSON(w, r, &input); apiErr != nil {
				writeIntegrationAPIError(w, apiErr)
				return
			}
			name, apiErr := integrationName(input.Name, "name")
			if apiErr != nil {
				writeIntegrationAPIError(w, apiErr)
				return
			}
			machineIDs, apiErr := integrationIDs(input.MachineIDs, "machine_id")
			if apiErr != nil {
				writeIntegrationAPIError(w, apiErr)
				return
			}
			groupIDs, apiErr := integrationIDs(input.GroupIDs, "group_id")
			if apiErr != nil {
				writeIntegrationAPIError(w, apiErr)
				return
			}
			if _, err := s.store.SaveFolderPolicy(ctx, store.FolderPolicy{ID: policyID, Name: name, Rules: input.Rules, MachineIDs: machineIDs, GroupIDs: groupIDs}, false, integrationActor(key)); err != nil {
				s.integrationFunctionError(w, err, "policy update")
				return
			}
			writeIntegrationJSON(w, http.StatusOK, map[string]bool{"ok": true})
			return
		case http.MethodDelete:
			if err := s.store.DeleteInventoryItem(ctx, "folder-policies", policyID, integrationActor(key)); err != nil {
				s.integrationFunctionError(w, err, "policy delete")
				return
			}
			writeIntegrationJSON(w, http.StatusOK, map[string]bool{"ok": true})
			return
		}
	}
	if len(parts) == 3 && (parts[2] == "machines" || parts[2] == "groups") && (r.Method == http.MethodPost || r.Method == http.MethodDelete) {
		policyID, apiErr := integrationPathUUID(parts[1], "policy_id")
		if apiErr != nil {
			writeIntegrationAPIError(w, apiErr)
			return
		}
		if !ensureIntegrationJSON(w, r) {
			return
		}
		var machineIDs []string
		var groupIDs []string
		if parts[2] == "machines" {
			var input integrationMachineIDs
			if apiErr := readIntegrationJSON(w, r, &input); apiErr != nil {
				writeIntegrationAPIError(w, apiErr)
				return
			}
			machineIDs, apiErr = integrationIDs(input.MachineIDs, "machine_id")
		} else {
			var input integrationGroupIDs
			if apiErr := readIntegrationJSON(w, r, &input); apiErr != nil {
				writeIntegrationAPIError(w, apiErr)
				return
			}
			groupIDs, apiErr = integrationIDs(input.GroupIDs, "group_id")
		}
		if apiErr != nil {
			writeIntegrationAPIError(w, apiErr)
			return
		}
		if len(machineIDs) == 0 && len(groupIDs) == 0 {
			writeIntegrationError(w, http.StatusBadRequest, protocol.CodeInvalidRequest, "assignment list must not be empty")
			return
		}
		var err error
		if parts[2] == "machines" {
			if r.Method == http.MethodPost {
				err = s.store.AddPolicyMachines(ctx, policyID, machineIDs, integrationActor(key))
			} else {
				err = s.store.RemovePolicyMachines(ctx, policyID, machineIDs, integrationActor(key))
			}
		} else {
			if r.Method == http.MethodPost {
				err = s.store.AddPolicyGroups(ctx, policyID, groupIDs, integrationActor(key))
			} else {
				err = s.store.RemovePolicyGroups(ctx, policyID, groupIDs, integrationActor(key))
			}
		}
		if err != nil {
			s.integrationFunctionError(w, err, "policy assignments")
			return
		}
		writeIntegrationJSON(w, http.StatusOK, map[string]bool{"ok": true})
		return
	}
	writeIntegrationError(w, http.StatusMethodNotAllowed, protocol.CodeMethodNotAllowed, "method not allowed")
}

func (s *Server) integrationCertificates(w http.ResponseWriter, r *http.Request, parts []string) {
	ctx, cancel := contextWithTimeout(r, 20*time.Second)
	defer cancel()
	if len(parts) == 2 && r.Method == http.MethodGet {
		if len(parts[1]) != 64 {
			writeIntegrationError(w, http.StatusBadRequest, protocol.CodeInvalidRequest, "invalid certificate fingerprint")
			return
		}
		if _, err := hex.DecodeString(parts[1]); err != nil {
			writeIntegrationError(w, http.StatusBadRequest, protocol.CodeInvalidRequest, "invalid certificate fingerprint")
			return
		}
		detail, err := s.store.CertificateDetail(ctx, strings.ToLower(parts[1]))
		if err != nil {
			s.integrationFunctionError(w, err, "certificate detail")
			return
		}
		writeIntegrationJSON(w, http.StatusOK, detail)
		return
	}
	if len(parts) != 1 || r.Method != http.MethodGet {
		writeIntegrationError(w, http.StatusMethodNotAllowed, protocol.CodeMethodNotAllowed, "method not allowed")
		return
	}
	page, pageSize, apiErr := integrationPage(r)
	if apiErr != nil {
		writeIntegrationAPIError(w, apiErr)
		return
	}
	machineID, apiErr := integrationUUID(r, "machine_id")
	if apiErr != nil {
		writeIntegrationAPIError(w, apiErr)
		return
	}
	validity, apiErr := integrationEnum(r, "validity", map[string]bool{"valid": true, "expired": true, "future": true})
	if apiErr != nil {
		writeIntegrationAPIError(w, apiErr)
		return
	}
	subject := strings.TrimSpace(r.URL.Query().Get("subject"))
	if len(subject) > 512 {
		writeIntegrationError(w, http.StatusBadRequest, protocol.CodeInvalidFilter, "subject is too long")
		return
	}
	serial := strings.TrimSpace(r.URL.Query().Get("serial"))
	if len(serial) > 256 {
		writeIntegrationError(w, http.StatusBadRequest, protocol.CodeInvalidFilter, "serial is too long")
		return
	}
	result, err := s.store.ListIntegrationCertificates(ctx, store.IntegrationCertificateFilter{
		MachineID: machineID, Subject: subject, Serial: serial, Validity: validity, Page: page, PageSize: pageSize,
	})
	if err != nil {
		s.integrationFunctionError(w, err, "certificates list")
		return
	}
	writeIntegrationJSON(w, http.StatusOK, result)
}

func (s *Server) integrationLicenses(w http.ResponseWriter, r *http.Request, parts []string) {
	ctx, cancel := contextWithTimeout(r, 20*time.Second)
	defer cancel()
	if len(parts) == 2 && r.Method == http.MethodGet {
		if len(parts[1]) != 64 {
			writeIntegrationError(w, http.StatusBadRequest, protocol.CodeInvalidRequest, "invalid license_id")
			return
		}
		if _, err := hex.DecodeString(parts[1]); err != nil {
			writeIntegrationError(w, http.StatusBadRequest, protocol.CodeInvalidRequest, "invalid license_id")
			return
		}
		license, err := s.store.GetIntegrationLicense(ctx, strings.ToLower(parts[1]))
		if err != nil {
			s.integrationFunctionError(w, err, "license detail")
			return
		}
		writeIntegrationJSON(w, http.StatusOK, license)
		return
	}
	if len(parts) != 1 || r.Method != http.MethodGet {
		writeIntegrationError(w, http.StatusMethodNotAllowed, protocol.CodeMethodNotAllowed, "method not allowed")
		return
	}
	page, pageSize, apiErr := integrationPage(r)
	if apiErr != nil {
		writeIntegrationAPIError(w, apiErr)
		return
	}
	machineID, apiErr := integrationUUID(r, "machine_id")
	if apiErr != nil {
		writeIntegrationAPIError(w, apiErr)
		return
	}
	product, apiErr := integrationEnum(r, "product", map[string]bool{"csp": true, "ocsp": true, "tsp": true})
	if apiErr != nil {
		writeIntegrationAPIError(w, apiErr)
		return
	}
	productCode, apiErr := integrationInt(r, "product_code", -1, 0, 2)
	if apiErr != nil {
		writeIntegrationAPIError(w, apiErr)
		return
	}
	kindRaw := strings.TrimSpace(r.URL.Query().Get("license_kind"))
	if kindRaw == "" {
		kindRaw = strings.TrimSpace(r.URL.Query().Get("type"))
	}
	kind, apiErr := integrationEnumValue(kindRaw, "license_kind", map[string]bool{"client": true, "server": true, "unknown": true})
	if apiErr != nil {
		writeIntegrationAPIError(w, apiErr)
		return
	}
	stateRaw := strings.TrimSpace(r.URL.Query().Get("license_state"))
	if stateRaw == "" {
		stateRaw = strings.TrimSpace(r.URL.Query().Get("status"))
	}
	state, apiErr := integrationEnumValue(stateRaw, "license_state", map[string]bool{"active": true, "expired": true, "not_installed": true, "unknown": true, "error": true})
	if apiErr != nil {
		writeIntegrationAPIError(w, apiErr)
		return
	}
	isTrialRaw := strings.TrimSpace(r.URL.Query().Get("is_trial"))
	isTrial := ""
	if isTrialRaw != "" {
		value, err := strconv.ParseBool(isTrialRaw)
		if err != nil {
			writeIntegrationError(w, http.StatusBadRequest, protocol.CodeInvalidFilter, "is_trial must be true or false")
			return
		}
		if value {
			isTrial = "true"
		} else {
			isTrial = "false"
		}
	}
	cspVersion := strings.TrimSpace(r.URL.Query().Get("csp_version"))
	if len(cspVersion) > 128 {
		writeIntegrationError(w, http.StatusBadRequest, protocol.CodeInvalidFilter, "csp_version is too long")
		return
	}
	result, err := s.store.ListIntegrationLicenses(ctx, store.IntegrationLicenseFilter{
		MachineID: machineID, Product: product, ProductCode: productCode, LicenseKind: kind,
		IsTrial: isTrial, LicenseState: state, CSPVersion: cspVersion, Page: page, PageSize: pageSize,
	})
	if err != nil {
		s.integrationFunctionError(w, err, "licenses list")
		return
	}
	writeIntegrationJSON(w, http.StatusOK, result)
}

func (s *Server) integrationEvents(w http.ResponseWriter, r *http.Request, parts []string) {
	if len(parts) != 1 || r.Method != http.MethodGet {
		writeIntegrationError(w, http.StatusMethodNotAllowed, protocol.CodeMethodNotAllowed, "method not allowed")
		return
	}
	page, pageSize, apiErr := integrationPage(r)
	if apiErr != nil {
		writeIntegrationAPIError(w, apiErr)
		return
	}
	severity, apiErr := integrationEnum(r, "severity", map[string]bool{"info": true, "warning": true, "error": true})
	if apiErr != nil {
		writeIntegrationAPIError(w, apiErr)
		return
	}
	eventType := strings.TrimSpace(r.URL.Query().Get("type"))
	if eventType == "" {
		eventType = strings.TrimSpace(r.URL.Query().Get("kind"))
	}
	if len(eventType) > 64 {
		writeIntegrationError(w, http.StatusBadRequest, protocol.CodeInvalidFilter, "type is too long")
		return
	}
	machineID, apiErr := integrationUUID(r, "machine_id")
	if apiErr != nil {
		writeIntegrationAPIError(w, apiErr)
		return
	}
	since, apiErr := integrationTimestamp(r, "since")
	if apiErr != nil {
		writeIntegrationAPIError(w, apiErr)
		return
	}
	until, apiErr := integrationTimestamp(r, "until")
	if apiErr != nil {
		writeIntegrationAPIError(w, apiErr)
		return
	}
	if since != nil && until != nil && since.After(*until) {
		writeIntegrationError(w, http.StatusBadRequest, protocol.CodeInvalidFilter, "since must not be later than until")
		return
	}
	ctx, cancel := contextWithTimeout(r, 20*time.Second)
	defer cancel()
	result, err := s.store.ListIntegrationEvents(ctx, store.IntegrationEventFilter{
		Severity: severity, Type: eventType, MachineID: machineID,
		Since: since, Until: until, Page: page, PageSize: pageSize,
	})
	if err != nil {
		s.integrationFunctionError(w, err, "events list")
		return
	}
	writeIntegrationJSON(w, http.StatusOK, result)
}

func (s *Server) integrationJobs(w http.ResponseWriter, r *http.Request, parts []string, key *store.IntegrationKey) {
	ctx, cancel := contextWithTimeout(r, 20*time.Second)
	defer cancel()
	if len(parts) == 1 && r.Method == http.MethodPost {
		if !ensureIntegrationJSON(w, r) {
			return
		}
		var input integrationScanRequest
		if apiErr := readIntegrationJSON(w, r, &input); apiErr != nil {
			writeIntegrationAPIError(w, apiErr)
			return
		}
		machineIDs, apiErr := integrationIDs(input.MachineIDs, "machine_id")
		if apiErr != nil {
			writeIntegrationAPIError(w, apiErr)
			return
		}
		groupID := ""
		if input.GroupID != "" {
			normalized, err := protocol.NormalizeUUID(input.GroupID)
			if err != nil {
				writeIntegrationError(w, http.StatusBadRequest, protocol.CodeInvalidRequest, "invalid group_id")
				return
			}
			groupID = normalized
		}
		if len(machineIDs) == 0 && groupID == "" {
			writeIntegrationError(w, http.StatusBadRequest, protocol.CodeInvalidRequest, "machine_ids or group_id is required")
			return
		}
		result, err := s.store.CreateIntegrationScanJobs(ctx, machineIDs, groupID, integrationActor(key))
		if err != nil {
			s.integrationFunctionError(w, err, "scan jobs create")
			return
		}
		status := http.StatusAccepted
		if len(result.Skipped) > 0 {
			status = http.StatusMultiStatus
		}
		writeIntegrationJSON(w, status, result)
		return
	}
	if len(parts) == 1 && r.Method == http.MethodGet {
		page, pageSize, apiErr := integrationPage(r)
		if apiErr != nil {
			writeIntegrationAPIError(w, apiErr)
			return
		}
		machineID, apiErr := integrationUUID(r, "machine_id")
		if apiErr != nil {
			writeIntegrationAPIError(w, apiErr)
			return
		}
		statusRaw := strings.TrimSpace(r.URL.Query().Get("status"))
		if statusRaw == "" {
			statusRaw = strings.TrimSpace(r.URL.Query().Get("state"))
		}
		status, apiErr := integrationEnumValue(statusRaw, "status", map[string]bool{
			"pending": true, "delivered": true, "completed": true, "failed": true, "report_evicted": true, "canceled": true,
		})
		if apiErr != nil {
			writeIntegrationAPIError(w, apiErr)
			return
		}
		result, err := s.store.ListIntegrationJobs(ctx, store.IntegrationJobFilter{
			MachineID: machineID, Status: status, Page: page, PageSize: pageSize,
		})
		if err != nil {
			s.integrationFunctionError(w, err, "jobs list")
			return
		}
		writeIntegrationJSON(w, http.StatusOK, result)
		return
	}
	if len(parts) == 2 && r.Method == http.MethodGet {
		jobID, apiErr := integrationPathUUID(parts[1], "job_id")
		if apiErr != nil {
			writeIntegrationAPIError(w, apiErr)
			return
		}
		job, err := s.store.GetIntegrationJob(ctx, jobID)
		if err != nil {
			s.integrationFunctionError(w, err, "job detail")
			return
		}
		writeIntegrationJSON(w, http.StatusOK, job)
		return
	}
	writeIntegrationError(w, http.StatusMethodNotAllowed, protocol.CodeMethodNotAllowed, "method not allowed")
}

func integrationEnumValue(raw, name string, allowed map[string]bool) (string, *protocol.APIError) {
	if raw == "" {
		return "", nil
	}
	if !allowed[raw] {
		return "", &protocol.APIError{Code: protocol.CodeInvalidFilter, Message: "invalid " + name}
	}
	return raw, nil
}

func writeIntegrationAPIError(w http.ResponseWriter, apiErr *protocol.APIError) {
	if apiErr == nil {
		writeIntegrationError(w, http.StatusInternalServerError, protocol.CodeInternal, "internal error")
		return
	}
	status := http.StatusBadRequest
	switch apiErr.Code {
	case protocol.CodeUnauthorized:
		status = http.StatusUnauthorized
	case protocol.CodeIPNotAllowed:
		status = http.StatusForbidden
	case protocol.CodeNotFound:
		status = http.StatusNotFound
	case protocol.CodeInvalidRules:
		status = http.StatusUnprocessableEntity
	case protocol.CodePayloadTooLarge:
		status = http.StatusRequestEntityTooLarge
	case protocol.CodeDatabase, protocol.CodeInternal:
		status = http.StatusInternalServerError
	}
	writeIntegrationError(w, status, apiErr.Code, apiErr.Message)
}

type integrationGroup struct {
	GroupID      string                     `json:"group_id"`
	Name         string                     `json:"name"`
	MachineCount int                        `json:"machine_count"`
	MachineIDs   []string                   `json:"machine_ids"`
	Machines     []store.IntegrationMachine `json:"machines,omitempty"`
}

type integrationGroupUpsert struct {
	Name       string   `json:"name"`
	MachineIDs []string `json:"machine_ids"`
}

type integrationMachineIDs struct {
	MachineIDs []string `json:"machine_ids"`
}

type integrationGroupIDs struct {
	GroupIDs []string `json:"group_ids"`
}

type integrationPolicy struct {
	PolicyID   string   `json:"policy_id"`
	Name       string   `json:"name"`
	Rules      string   `json:"rules"`
	MachineIDs []string `json:"machine_ids"`
	GroupIDs   []string `json:"group_ids"`
}

type integrationPolicyUpsert struct {
	Name       string   `json:"name"`
	Rules      string   `json:"rules"`
	MachineIDs []string `json:"machine_ids"`
	GroupIDs   []string `json:"group_ids"`
}

type integrationScanRequest struct {
	MachineIDs []string `json:"machine_ids"`
	GroupID    string   `json:"group_id"`
}

// newIntegrationToken generates mndk_<64 lowercase hex>. The token is returned
// to the administrator once; only its SHA-256 is stored.
func newIntegrationToken() (string, string, error) {
	buffer := make([]byte, 32)
	if _, err := rand.Read(buffer); err != nil {
		return "", "", err
	}
	token := "mndk_" + hex.EncodeToString(buffer)
	prefix := token[:len("mndk_")+8]
	return token, prefix, nil
}
