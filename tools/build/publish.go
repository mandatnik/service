package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Tags deliver immutable release assets; deployments to workstations remain an
// administrator's decision. Tokens are read from the environment, never flags.
func publish(o options) error {
	tag := os.Getenv("GITEA_REF_NAME")
	if tag == "" {
		tag = os.Getenv("RELEASE_TAG")
	}
	if !strings.HasPrefix(tag, "v") {
		return fmt.Errorf("publishing requires a vX.Y.Z tag (RELEASE_TAG)")
	}
	normalized, err := normalized(o)
	if err != nil {
		return err
	}
	if strings.TrimPrefix(tag, "v") != normalized.productVersion {
		return fmt.Errorf("tag %s does not match product version %s", tag, normalized.productVersion)
	}
	base := strings.TrimRight(os.Getenv("GITEA_SERVER_URL"), "/")
	repository := os.Getenv("GITEA_REPOSITORY")
	token := os.Getenv("GITEA_TOKEN")
	parsed, err := url.Parse(base)
	if err != nil || parsed.Host == "" || (parsed.Scheme != "http" && parsed.Scheme != "https") || len(strings.Split(repository, "/")) != 2 || strings.ContainsAny(repository, "?# ") || token == "" {
		return fmt.Errorf("GITEA_SERVER_URL, GITEA_REPOSITORY and GITEA_TOKEN are required")
	}
	client := http.Client{Timeout: 5 * time.Minute}
	request := func(method, path string, body io.Reader, contentType string) ([]byte, int, error) {
		req, err := http.NewRequest(method, base+"/api/v1/repos/"+repository+path, body)
		if err != nil {
			return nil, 0, err
		}
		req.Header.Set("Authorization", "token "+token)
		if contentType != "" {
			req.Header.Set("Content-Type", contentType)
		}
		resp, err := client.Do(req)
		if err != nil {
			return nil, 0, err
		}
		defer resp.Body.Close()
		data, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
		return data, resp.StatusCode, err
	}
	type release struct {
		ID      int64  `json:"id"`
		HTMLURL string `json:"html_url"`
	}
	data, status, err := request("GET", "/releases/tags/"+url.PathEscape(tag), nil, "")
	if err != nil {
		return err
	}
	var result release
	if status == 404 {
		payload, _ := json.Marshal(map[string]any{"tag_name": tag, "name": "Telehack 2026 " + tag, "target_commitish": os.Getenv("GITEA_SHA"), "body": "Windows amd64 EXE, MSI, build metadata and SHA-256 checksums. Built and tested through Makefile/Gitea Actions.", "draft": false, "prerelease": false})
		data, status, err = request("POST", "/releases", bytes.NewReader(payload), "application/json")
	}
	if err != nil {
		return err
	}
	if status != 200 && status != 201 {
		return fmt.Errorf("release API returned HTTP %d", status)
	}
	if err = json.Unmarshal(data, &result); err != nil {
		return err
	}
	entries, err := os.ReadDir(o.out)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		ext := strings.ToLower(filepath.Ext(name))
		if ext != ".exe" && ext != ".msi" && name != "SHA256SUMS" && name != "build-info.json" {
			continue
		}
		var buffer bytes.Buffer
		writer := multipart.NewWriter(&buffer)
		part, err := writer.CreateFormFile("attachment", name)
		if err != nil {
			return err
		}
		file, err := os.Open(filepath.Join(o.out, name))
		if err != nil {
			return err
		}
		_, err = io.Copy(part, file)
		file.Close()
		if err != nil {
			return err
		}
		writer.Close()
		_, status, err = request("POST", fmt.Sprintf("/releases/%d/assets?name=%s", result.ID, url.QueryEscape(name)), &buffer, writer.FormDataContentType())
		if err != nil {
			return err
		}
		if status != 201 {
			return fmt.Errorf("asset %s upload returned HTTP %d (published files are never overwritten)", name, status)
		}
		fmt.Println("Published", name)
	}
	fmt.Println("Release:", result.HTMLURL)
	return nil
}
