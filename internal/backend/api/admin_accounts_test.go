package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"mandatnik/internal/backend/store"
)

func TestAdminAccountsRejectsRegularAdministrator(t *testing.T) {
	s := &Server{}
	session := &store.AdminSession{Role: store.AdminRoleAdmin}
	cases := []struct {
		method string
		parts  []string
	}{
		{http.MethodGet, []string{"admins"}},
		{http.MethodPost, []string{"admins"}},
		{http.MethodPut, []string{"admins", "2"}},
		{http.MethodDelete, []string{"admins", "2"}},
		{http.MethodPost, []string{"admins", "2", "freeze"}},
		{http.MethodPost, []string{"admins", "2", "unfreeze"}},
	}
	for _, tc := range cases {
		t.Run(tc.method+" "+strings.Join(tc.parts, "/"), func(t *testing.T) {
			w := httptest.NewRecorder()
			r := httptest.NewRequest(tc.method, "/api/admin/v1/"+strings.Join(tc.parts, "/"), nil)
			s.adminAccounts(w, r, session, tc.parts)
			if w.Code != http.StatusForbidden {
				t.Fatalf("status = %d, want 403; body=%s", w.Code, w.Body.String())
			}
		})
	}
}

func TestAdminAccountBodyCannotCarryRole(t *testing.T) {
	s := &Server{}
	session := &store.AdminSession{Role: store.AdminRoleSuperAdmin}
	body := `{"email":"new@example.test","display_name":"Новый А. Б.","password":"a-long-password","role":"superadmin"}`
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/api/admin/v1/admins", strings.NewReader(body))
	s.adminAccounts(w, r, session, []string{"admins"})
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "unknown field") {
		t.Fatalf("role field was not rejected: %s", w.Body.String())
	}
}

func TestAdminAccountIDValidation(t *testing.T) {
	for _, value := range []string{"", "0", "-1", "not-a-number", "1.5"} {
		w := httptest.NewRecorder()
		if _, ok := adminAccountID(w, value); ok {
			t.Fatalf("adminAccountID(%q) accepted invalid value", value)
		}
		if w.Code != http.StatusBadRequest {
			t.Fatalf("adminAccountID(%q) status = %d, want 400", value, w.Code)
		}
	}
	w := httptest.NewRecorder()
	if id, ok := adminAccountID(w, "42"); !ok || id != 42 {
		t.Fatalf("adminAccountID(42) = %d, %t", id, ok)
	}
}
