package api

import (
	"net/http/httptest"
	"strings"
	"testing"
)

func TestValidIntegrationToken(t *testing.T) {
	valid := "mndk_" + strings.Repeat("a1", 32)
	if !validIntegrationToken(valid) {
		t.Fatal("valid mndk token rejected")
	}
	legacy := "thak_" + strings.Repeat("0f", 32)
	if !validIntegrationToken(legacy) {
		t.Fatal("valid legacy token rejected")
	}
	cases := []string{
		"",
		"mndk_",
		"mndk_" + strings.Repeat("a", 63),
		"mndk_" + strings.Repeat("a", 65),
		"mndk_" + strings.Repeat("zz", 32),
		"Bearer " + valid,
	}
	for _, value := range cases {
		if validIntegrationToken(value) {
			t.Fatalf("invalid token accepted: %q", value)
		}
	}
}

func TestNewIntegrationTokenFormat(t *testing.T) {
	token, prefix, err := newIntegrationToken()
	if err != nil {
		t.Fatal(err)
	}
	if !validIntegrationToken(token) {
		t.Fatalf("generated token is invalid: %q", token)
	}
	if len(prefix) != len("mndk_")+8 || !strings.HasPrefix(token, prefix) {
		t.Fatalf("prefix = %q, token = %q", prefix, token)
	}
	second, _, err := newIntegrationToken()
	if err != nil {
		t.Fatal(err)
	}
	if token == second {
		t.Fatal("two generated tokens are equal")
	}
}

func TestIntegrationNameValidation(t *testing.T) {
	if name, err := integrationName("  integration  ", "name"); err != nil || name != "integration" {
		t.Fatalf("valid name: %q, %v", name, err)
	}
	for _, value := range []string{"", "   ", strings.Repeat("x", 201), "line\nbreak", "null\x00byte"} {
		if _, err := integrationName(value, "name"); err == nil {
			t.Fatalf("invalid name accepted: %q", value)
		}
	}
}

func TestIntegrationIDValidation(t *testing.T) {
	ids, apiErr := integrationIDs([]string{
		"CF87543F-5075-4561-807E-C2EB3A959B61",
		"cf87543f-5075-4561-807e-c2eb3a959b61",
	}, "machine_id")
	if apiErr != nil {
		t.Fatal(apiErr.Message)
	}
	if len(ids) != 1 || ids[0] != "cf87543f-5075-4561-807e-c2eb3a959b61" {
		t.Fatalf("ids = %v", ids)
	}
	if _, apiErr := integrationIDs([]string{"not-a-uuid"}, "machine_id"); apiErr == nil {
		t.Fatal("invalid UUID accepted")
	}
	if _, apiErr := integrationIDs([]string{"00000000-0000-0000-0000-000000000000"}, "machine_id"); apiErr == nil {
		t.Fatal("nil UUID accepted")
	}
}

func TestIntegrationPageBounds(t *testing.T) {
	request := httptest.NewRequest("GET", "/machines?page=2&page_size=500", nil)
	page, size, apiErr := integrationPage(request)
	if apiErr != nil || page != 2 || size != 500 {
		t.Fatalf("page=%d size=%d err=%v", page, size, apiErr)
	}
	for _, raw := range []string{"page=0", "page=x", "page_size=0", "page_size=501", "page_size=x"} {
		request := httptest.NewRequest("GET", "/machines?"+raw, nil)
		if _, _, apiErr := integrationPage(request); apiErr == nil {
			t.Fatalf("invalid pagination accepted: %s", raw)
		}
	}
}
