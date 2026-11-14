package api

import (
	"net/http"
	"time"

	"telehack2026/internal/backend/store"
	"telehack2026/internal/protocol"
)

func (s *Server) adminLicensesAndTasks(w http.ResponseWriter, r *http.Request, session *store.AdminSession, parts []string) {
	ctx, cancel := contextWithTimeout(r, 20*time.Second)
	defer cancel()
	switch {
	case parts[0] == "license-pools" && len(parts) == 1 && r.Method == http.MethodGet:
		pools, err := s.store.ListPools(ctx)
		if err != nil {
			s.logf("list license pools failed: %v", err)
			writeAdminError(w, http.StatusServiceUnavailable, protocol.CodeDatabase, "could not load license pools")
			return
		}
		writeAdminJSON(w, http.StatusOK, map[string]any{"items": pools})
	case parts[0] == "license-pools" && len(parts) == 1 && r.Method == http.MethodPost:
		var input store.PoolInput
		if err := readAdminJSON(w, r, &input); err != nil {
			writeAdminError(w, http.StatusBadRequest, protocol.CodeInvalidJSON, err.Error())
			return
		}
		pool, apiErr := s.store.CreatePool(ctx, input, session.Email)
		if apiErr != nil {
			writeStoreAPIError(w, apiErr)
			return
		}
		writeAdminJSON(w, http.StatusCreated, pool)
	case parts[0] == "license-pools" && len(parts) == 2 && r.Method == http.MethodGet:
		pool, apiErr := s.store.GetPool(ctx, parts[1])
		if apiErr != nil {
			writeStoreAPIError(w, apiErr)
			return
		}
		writeAdminJSON(w, http.StatusOK, pool)
	case parts[0] == "license-pools" && len(parts) == 2 && r.Method == http.MethodPatch:
		var input struct {
			Name string `json:"name"`
		}
		if err := readAdminJSON(w, r, &input); err != nil {
			writeAdminError(w, http.StatusBadRequest, protocol.CodeInvalidJSON, err.Error())
			return
		}
		pool, apiErr := s.store.GetPool(ctx, parts[1])
		if apiErr != nil {
			writeStoreAPIError(w, apiErr)
			return
		}
		updated, apiErr := s.store.UpdatePool(ctx, pool.ID, store.PoolInput{
			Name: input.Name, CSPMajorVersion: pool.CSPMajorVersion,
			LicenseKind: pool.LicenseKind, Term: pool.Term,
		}, session.Email)
		if apiErr != nil {
			writeStoreAPIError(w, apiErr)
			return
		}
		writeAdminJSON(w, http.StatusOK, updated)
	case parts[0] == "license-pools" && len(parts) == 3 && parts[2] == "archive" && r.Method == http.MethodPost:
		var input struct {
			Archived bool `json:"archived"`
		}
		if err := readAdminJSON(w, r, &input); err != nil {
			writeAdminError(w, http.StatusBadRequest, protocol.CodeInvalidJSON, err.Error())
			return
		}
		pool, apiErr := s.store.SetPoolArchived(ctx, parts[1], input.Archived, session.Email)
		if apiErr != nil {
			writeStoreAPIError(w, apiErr)
			return
		}
		writeAdminJSON(w, http.StatusOK, pool)
	case parts[0] == "license-pools" && len(parts) == 3 && parts[2] == "licenses" && r.Method == http.MethodGet:
		page, err := s.store.ListLicenses(ctx, parts[1], r.URL.Query().Get("state"), queryInt(r, "page", 1), queryInt(r, "page_size", 50))
		if err != nil {
			s.logf("list licenses failed: %v", err)
			writeAdminError(w, http.StatusServiceUnavailable, protocol.CodeDatabase, "could not load licenses")
			return
		}
		writeAdminJSON(w, http.StatusOK, page)
	case parts[0] == "license-pools" && len(parts) == 3 && parts[2] == "history" && r.Method == http.MethodGet:
		items, err := s.store.LicenseHistory(ctx, parts[1], queryInt(r, "limit", 200))
		if err != nil {
			s.logf("license history failed: %v", err)
			writeAdminError(w, http.StatusServiceUnavailable, protocol.CodeDatabase, "could not load license history")
			return
		}
		writeAdminJSON(w, http.StatusOK, map[string]any{"items": items})
	case parts[0] == "license-pools" && len(parts) == 4 && parts[2] == "licenses" && parts[3] == "import" && r.Method == http.MethodPost:
		var input struct {
			Serials []string `json:"serials"`
		}
		if err := readAdminJSON(w, r, &input); err != nil {
			writeAdminError(w, http.StatusBadRequest, protocol.CodeInvalidJSON, "invalid import body")
			return
		}
		// The request body is intentionally never logged or audited.
		result, apiErr := s.store.ImportLicenses(ctx, parts[1], input.Serials, session.Email)
		if apiErr != nil {
			writeStoreAPIError(w, apiErr)
			return
		}
		status := http.StatusOK
		if !result.Accepted {
			status = http.StatusUnprocessableEntity
		}
		writeAdminJSON(w, status, result)
	case parts[0] == "licenses" && len(parts) == 3 && parts[2] == "block" && r.Method == http.MethodPost:
		var input struct {
			Reason string `json:"reason"`
		}
		if err := readAdminJSON(w, r, &input); err != nil {
			writeAdminError(w, http.StatusBadRequest, protocol.CodeInvalidJSON, err.Error())
			return
		}
		if apiErr := s.store.BlockLicense(ctx, parts[1], input.Reason, session.Email); apiErr != nil {
			writeStoreAPIError(w, apiErr)
			return
		}
		writeAdminJSON(w, http.StatusOK, map[string]any{"ok": true})
	case parts[0] == "tasks" && len(parts) == 2 && parts[1] == "activation-preview" && r.Method == http.MethodPost:
		var input store.ActivationPreviewInput
		if err := readAdminJSON(w, r, &input); err != nil {
			writeAdminError(w, http.StatusBadRequest, protocol.CodeInvalidJSON, err.Error())
			return
		}
		response, apiErr := s.store.BuildActivationPreview(ctx, input, session.Email)
		if apiErr != nil {
			writeStoreAPIError(w, apiErr)
			return
		}
		writeAdminJSON(w, http.StatusOK, response)
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
		case protocol.TaskKindInstallLicense:
			detail, apiErr := s.store.CreateInstallTask(ctx, store.CreateInstallTaskInput{
				PoolID: input.PoolID, PreviewID: input.PreviewID, MachineIDs: input.MachineIDs,
				IdempotencyKey: input.IdempotencyKey,
			}, session.Email)
			if apiErr != nil {
				writeStoreAPIError(w, apiErr)
				return
			}
			writeAdminJSON(w, http.StatusAccepted, detail)
		default:
			writeAdminError(w, http.StatusUnprocessableEntity, protocol.CodeConfigInvalid, "task kind must be scan or install_license")
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
