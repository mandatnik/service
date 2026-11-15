package api

import (
	"net/http/httptest"
	"testing"
)

func TestAdminPageFallback(t *testing.T) {
	s := &Server{}
	for _, path := range []string{"/arm", "/arm/5297a534-08b3-418c-823c-be2e8ec01160", "/certificates/abcdef", "/groups", "/settings", "/admins", "/hostnames", "/hostnames/old-value"} {
		w := httptest.NewRecorder()
		s.serveAdminStatic(w, httptest.NewRequest("GET", path, nil))
		if w.Code != 200 || w.Header().Get("Content-Type") != "text/html; charset=utf-8" {
			t.Errorf("%s: %d %s", path, w.Code, w.Header().Get("Content-Type"))
		}
	}
	for _, path := range []string{"/missing.js", "/api/missing", "/arm/missing.js", "/unknown", "/settings/extra"} {
		w := httptest.NewRecorder()
		s.serveAdminStatic(w, httptest.NewRequest("GET", path, nil))
		if w.Code != 404 {
			t.Errorf("%s: got %d, want 404", path, w.Code)
		}
	}
}
