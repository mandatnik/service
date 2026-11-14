package api

import (
	"encoding/json"
	"net/http"
	"time"

	"telehack2026/internal/protocol"
)

func (s *Server) handleCapabilities(w http.ResponseWriter, r *http.Request, body []byte) {
	identity, request, apiErr := s.verifyRequest(r.Context(), body, protocol.PathCapabilities)
	if apiErr != nil {
		writeAPIError(w, apiErr)
		return
	}
	input := protocol.AgentCapabilities{
		Capabilities:        request.Data.Capabilities,
		EncryptionKeyID:     request.Data.EncryptionKeyID,
		EncryptionPublicKey: request.Data.EncryptionPublicKey,
		EncryptionAlgorithm: request.Data.EncryptionAlgorithm,
		EncryptionBits:      request.Data.EncryptionBits,
		EncryptionKeyRotate: request.Data.EncryptionKeyRotate,
	}
	response, apiErr := s.store.RegisterCapabilities(r.Context(), identity, input)
	if apiErr != nil {
		writeAPIError(w, apiErr)
		return
	}
	writeJSON(w, http.StatusOK, response)
}

func (s *Server) handleTaskSync(w http.ResponseWriter, r *http.Request, body []byte) {
	identity, request, apiErr := s.verifyRequest(r.Context(), body, protocol.PathTaskSync)
	if apiErr != nil {
		writeAPIError(w, apiErr)
		return
	}
	if request.Data.TaskQueue != nil {
		var status protocol.TaskQueueStatus
		if err := json.Unmarshal(request.Data.TaskQueue, &status); err == nil && status.JournalCorrupt {
			_ = s.store.RecordTaskDiagnostic(r.Context(), identity, protocol.TaskDiagnostic{
				Code: protocol.CodeJournalCorrupted, Message: status.JournalError,
				OccurredAt: time.Now().UTC().Format(time.RFC3339Nano),
			})
		}
	}
	response, apiErr := s.store.SyncAgentTasks(r.Context(), identity)
	if apiErr != nil {
		writeAPIError(w, apiErr)
		return
	}
	writeJSON(w, http.StatusOK, response)
}

func (s *Server) handleTaskAck(w http.ResponseWriter, r *http.Request, body []byte) {
	identity, request, apiErr := s.verifyRequest(r.Context(), body, protocol.PathTaskAck)
	if apiErr != nil {
		writeAPIError(w, apiErr)
		return
	}
	response, apiErr := s.store.AckTaskDelivery(r.Context(), identity, request.Data.TaskItemID, request.Data.TaskDeliveryVersion)
	if apiErr != nil {
		writeAPIError(w, apiErr)
		return
	}
	writeJSON(w, http.StatusOK, response)
}

func (s *Server) handleTaskClaim(w http.ResponseWriter, r *http.Request, body []byte) {
	identity, request, apiErr := s.verifyRequest(r.Context(), body, protocol.PathTaskClaim)
	if apiErr != nil {
		writeAPIError(w, apiErr)
		return
	}
	response, apiErr := s.store.ClaimTaskItem(r.Context(), identity, request.Data.TaskItemID, request.Data.TaskDeliveryVersion)
	if apiErr != nil {
		writeAPIError(w, apiErr)
		return
	}
	writeJSON(w, http.StatusOK, response)
}

func (s *Server) handleTaskProgress(w http.ResponseWriter, r *http.Request, body []byte) {
	identity, request, apiErr := s.verifyRequest(r.Context(), body, protocol.PathTaskProgress)
	if apiErr != nil {
		writeAPIError(w, apiErr)
		return
	}
	event, err := protocol.DecodeTaskProgressEvent(request.Data.TaskEvent)
	if err != nil {
		writeError(w, http.StatusUnprocessableEntity, protocol.CodeTaskConflict, err.Error())
		return
	}
	if event.ItemID != request.Data.TaskItemID {
		writeError(w, http.StatusUnprocessableEntity, protocol.CodeTaskConflict, "event item does not match the signed item")
		return
	}
	if apiErr := s.store.TaskProgress(r.Context(), identity, *event); apiErr != nil {
		writeAPIError(w, apiErr)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"accepted": true, "server_time": protocol.FormatTaskTime(time.Now().UTC())})
}

func (s *Server) handleTaskResult(w http.ResponseWriter, r *http.Request, body []byte) {
	identity, request, apiErr := s.verifyRequest(r.Context(), body, protocol.PathTaskResult)
	if apiErr != nil {
		writeAPIError(w, apiErr)
		return
	}
	result, err := protocol.DecodeTaskResult(request.Data.TaskResult)
	if err != nil {
		writeError(w, http.StatusUnprocessableEntity, protocol.CodeTaskConflict, err.Error())
		return
	}
	if result.ItemID != request.Data.TaskItemID {
		writeError(w, http.StatusUnprocessableEntity, protocol.CodeTaskConflict, "result item does not match the signed item")
		return
	}
	response, apiErr := s.store.SubmitTaskResult(r.Context(), identity, result)
	if apiErr != nil {
		writeAPIError(w, apiErr)
		return
	}
	writeJSON(w, http.StatusOK, response)
}

func (s *Server) handleTaskDiagnostic(w http.ResponseWriter, r *http.Request, body []byte) {
	identity, request, apiErr := s.verifyRequest(r.Context(), body, protocol.PathTaskDiagnostic)
	if apiErr != nil {
		writeAPIError(w, apiErr)
		return
	}
	diagnostic, err := protocol.DecodeTaskDiagnostic(request.Data.TaskDiagnostic)
	if err != nil {
		writeError(w, http.StatusUnprocessableEntity, protocol.CodeInvalidJSON, err.Error())
		return
	}
	if apiErr := s.store.RecordTaskDiagnostic(r.Context(), identity, *diagnostic); apiErr != nil {
		writeAPIError(w, apiErr)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"accepted": true, "server_time": protocol.FormatTaskTime(time.Now().UTC())})
}
