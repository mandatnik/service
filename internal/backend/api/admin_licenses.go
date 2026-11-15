package api

import (
	"net/http"
	"time"

	"mandatnik/internal/backend/store"
	"mandatnik/internal/protocol"
)

func (s *Server) adminLicensesAndTasks(w http.ResponseWriter, r *http.Request, session *store.AdminSession, parts []string) {
	ctx, cancel := contextWithTimeout(r, 20*time.Second)
	defer cancel()
	// Remote activation is outside the current product scope. Preserve SQL
	// history, but do not expose pools, key import or activation previews.
	if parts[0] == "license-pools" || parts[0] == "licenses" || (parts[0] == "tasks" && len(parts) > 1 && parts[1] == "activation-preview") {
		writeAdminError(w, http.StatusNotFound, protocol.CodeNotFound, "not found")
		return
	}
	switch {
	case parts[0] == "tasks" && len(parts) == 1 && r.Method == http.MethodGet:
		page, err := s.store.ListTasks(ctx, store.TaskFilter{
			Kind: r.URL.Query().Get("kind"), State: r.URL.Query().Get("state"),
			MachineID: r.URL.Query().Get("machine_id"), From: r.URL.Query().Get("from"), To: r.URL.Query().Get("to"),
			Page: queryInt(r, "page", 1), PageSize: queryInt(r, "page_size", 25),
		})
		if err != nil {
			s.logf("list tasks failed: %v", err)
			writeAdminError(w, http.StatusServiceUnavailable, protocol.CodeDatabase, "could not load tasks")
			return
		}
		writeAdminJSON(w, http.StatusOK, page)
	case parts[0] == "tasks" && len(parts) == 1 && r.Method == http.MethodPost:
		var input struct {
			Kind           string   `json:"kind"`
			PoolID         string   `json:"pool_id"`
			PreviewID      string   `json:"preview_id"`
			MachineIDs     []string `json:"machine_ids"`
			GroupIDs       []string `json:"group_ids"`
			IdempotencyKey string   `json:"idempotency_key"`
		}
		if err := readAdminJSON(w, r, &input); err != nil {
			writeAdminError(w, http.StatusBadRequest, protocol.CodeInvalidJSON, err.Error())
			return
		}
		switch input.Kind {
		case protocol.TaskKindScan:
			detail, apiErr := s.store.CreateScanTask(ctx, store.CreateScanTaskInput{
				MachineIDs: input.MachineIDs, GroupIDs: input.GroupIDs, IdempotencyKey: input.IdempotencyKey,
			}, session.Email)
			if apiErr != nil {
				writeStoreAPIError(w, apiErr)
				return
			}
			writeAdminJSON(w, http.StatusAccepted, detail)
		default:
			writeAdminError(w, http.StatusUnprocessableEntity, protocol.CodeConfigInvalid, "only scan tasks are supported")
		}
	case parts[0] == "tasks" && len(parts) == 2 && r.Method == http.MethodGet:
		detail, apiErr := s.store.TaskDetail(ctx, parts[1])
		if apiErr != nil {
			writeStoreAPIError(w, apiErr)
			return
		}
		writeAdminJSON(w, http.StatusOK, detail)
	case parts[0] == "tasks" && len(parts) == 3 && parts[2] == "items" && r.Method == http.MethodGet:
		detail, apiErr := s.store.TaskDetail(ctx, parts[1])
		if apiErr != nil {
			writeStoreAPIError(w, apiErr)
			return
		}
		writeAdminJSON(w, http.StatusOK, map[string]any{"items": detail.Items, "next_after": nil})
	case parts[0] == "tasks" && len(parts) == 3 && parts[2] == "cancel" && r.Method == http.MethodPost:
		detail, apiErr := s.store.CancelTask(ctx, parts[1], session.Email)
		if apiErr != nil {
			writeStoreAPIError(w, apiErr)
			return
		}
		writeAdminJSON(w, http.StatusOK, detail)
	case parts[0] == "task-items" && len(parts) == 3 && parts[2] == "events" && r.Method == http.MethodGet:
		events, apiErr := s.store.TaskItemEvents(ctx, parts[1])
		if apiErr != nil {
			writeStoreAPIError(w, apiErr)
			return
		}
		writeAdminJSON(w, http.StatusOK, map[string]any{"items": events})
	case parts[0] == "task-items" && len(parts) == 3 && parts[2] == "cancel" && r.Method == http.MethodPost:
		detail, apiErr := s.store.CancelTaskItem(ctx, parts[1], session.Email)
		if apiErr != nil {
			writeStoreAPIError(w, apiErr)
			return
		}
		writeAdminJSON(w, http.StatusOK, detail)
	case parts[0] == "task-items" && len(parts) == 3 && parts[2] == "reconcile" && r.Method == http.MethodPost:
		detail, apiErr := s.store.RequestReconcile(ctx, parts[1], session.Email)
		if apiErr != nil {
			writeStoreAPIError(w, apiErr)
			return
		}
		writeAdminJSON(w, http.StatusOK, detail)
	default:
		writeAdminError(w, http.StatusNotFound, protocol.CodeNotFound, "not found")
	}
}

func writeStoreAPIError(w http.ResponseWriter, apiErr *protocol.APIError) {
	if apiErr == nil {
		writeAdminError(w, http.StatusInternalServerError, protocol.CodeInternal, "internal error")
		return
	}
	status := http.StatusUnprocessableEntity
	switch apiErr.Code {
	case protocol.CodeNotFound, protocol.CodeTaskNotFound:
		status = http.StatusNotFound
	case protocol.CodePreviewStale, protocol.CodePreviewInvalid, protocol.CodeLicenseDeficit,
		protocol.CodeMachineBusy, protocol.CodeConflict, protocol.CodeIdempotencyConflict:
		status = http.StatusConflict
	case protocol.CodeLicenseUnavailable, protocol.CodeAgentKeyUnavailable:
		status = http.StatusServiceUnavailable
	case protocol.CodeDatabase, protocol.CodeInternal:
		status = http.StatusInternalServerError
	}
	writeAdminJSON(w, status, protocol.ErrorResponse{Error: *apiErr})
}
