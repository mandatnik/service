package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"telehack2026/internal/backend/store"
	"testing"
)

func TestRemoteActivationEndpointsDisabled(t *testing.T) {
	for _, tc := range []struct {
		path, method, body string
		status             int
	}{
		{"license-pools", http.MethodGet, "", 404},
		{"license-pools", http.MethodPost, `{"name":"test"}`, 404},
		{"licenses/id/block", http.MethodPost, `{}`, 404},
		{"tasks/activation-preview", http.MethodPost, `{}`, 404},
		{"tasks", http.MethodPost, `{"kind":"install_license"}`, 422},
	} {
		t.Run(tc.path+tc.method, func(t *testing.T) {
			r := httptest.NewRequest(tc.method, "/api/admin/v1/"+tc.path, strings.NewReader(tc.body))
			r.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()
			s := &Server{} // Disabled routes must never touch the database or keyring.
			s.adminLicensesAndTasks(w, r, &store.AdminSession{}, strings.Split(tc.path, "/"))
			if w.Code != tc.status {
				t.Fatalf("status %d, want %d: %s", w.Code, tc.status, w.Body.String())
			}
		})
	}
}
