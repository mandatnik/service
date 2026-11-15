package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"mandatnik/internal/version"
)

func TestPublishDraftBecomesVisibleOnlyAfterAssets(t *testing.T) {
	uploaded, published := false, false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "token unit-only-token" {
			t.Error("missing auth")
			w.WriteHeader(401)
			return
		}
		path := strings.TrimPrefix(r.URL.Path, "/api/v1/repos/test/project")
		switch {
		case r.Method == "GET" && strings.HasPrefix(path, "/releases/tags/"):
			w.WriteHeader(404)
		case r.Method == "POST" && path == "/releases":
			var input map[string]any
			json.NewDecoder(r.Body).Decode(&input)
			if input["draft"] != true {
				t.Error("incomplete release exposed")
			}
			w.WriteHeader(201)
			fmt.Fprint(w, `{"id":1,"draft":true,"html_url":"http://example.test/release"}`)
		case r.Method == "GET" && path == "/releases/1/assets":
			fmt.Fprint(w, `[]`)
		case r.Method == "POST" && path == "/releases/1/assets":
			file, header, err := r.FormFile("attachment")
			if err != nil {
				t.Error(err)
				w.WriteHeader(400)
				return
			}
			defer file.Close()
			data, _ := io.ReadAll(file)
			if header.Filename != "mandatnik-agent.exe" || string(data) != "test artifact" {
				t.Error("wrong artifact")
			}
			uploaded = true
			w.WriteHeader(201)
			fmt.Fprint(w, `{}`)
		case r.Method == "PATCH" && path == "/releases/1":
			if !uploaded {
				t.Error("published before upload")
			}
			var input map[string]any
			json.NewDecoder(r.Body).Decode(&input)
			if input["draft"] != false {
				t.Error("release stayed draft")
			}
			published = true
			fmt.Fprint(w, `{}`)
		default:
			t.Errorf("unexpected request %s %s", r.Method, path)
			w.WriteHeader(400)
		}
	}))
	defer server.Close()
	t.Setenv("GITEA_SERVER_URL", server.URL)
	t.Setenv("GITEA_REPOSITORY", "test/project")
	t.Setenv("GITEA_TOKEN", "unit-only-token")
	t.Setenv("GITEA_REF_NAME", "v"+version.Version)
	out := t.TempDir()
	if err := os.WriteFile(filepath.Join(out, "mandatnik-agent.exe"), []byte("test artifact"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := publish(options{out: out}); err != nil {
		t.Fatal(err)
	}
	if !published {
		t.Fatal("release not published")
	}
}
