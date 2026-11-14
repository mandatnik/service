package store

import (
	"strings"
	"testing"
)

func TestNormalizeAdminEmail(t *testing.T) {
	cases := []struct {
		name    string
		input   string
		want    string
		wantErr bool
	}{
		{"trims and lowercases", "  Admin@Example.COM  ", "admin@example.com", false},
		{"already canonical", "malygin@example.com", "malygin@example.com", false},
		{"rejects empty", "   ", "", true},
		{"rejects missing @", "admin", "", true},
		{"rejects display-name form", "Малыгин А. Е. <admin@example.com>", "", true},
		{"rejects too long", strings.Repeat("a", 310) + "@example.com", "", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := NormalizeAdminEmail(tc.input)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("NormalizeAdminEmail(%q) = %q, want error", tc.input, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("NormalizeAdminEmail(%q): %v", tc.input, err)
			}
			if got != tc.want {
				t.Fatalf("NormalizeAdminEmail(%q) = %q, want %q", tc.input, got, tc.want)
			}
		})
	}
}

func TestNormalizeAdminDisplayName(t *testing.T) {
	cases := []struct {
		name    string
		input   string
		want    string
		wantErr bool
	}{
		{"trims and keeps Cyrillic", "  Малыгин А. Е.  ", "Малыгин А. Е.", false},
		{"accepts maximum length", strings.Repeat("Ж", 255), strings.Repeat("Ж", 255), false},
		{"rejects empty", " \t ", "", true},
		{"rejects too long", strings.Repeat("Ж", 256), "", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := NormalizeAdminDisplayName(tc.input)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("NormalizeAdminDisplayName(%q) = %q, want error", tc.input, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("NormalizeAdminDisplayName(%q): %v", tc.input, err)
			}
			if got != tc.want {
				t.Fatalf("NormalizeAdminDisplayName(%q) = %q, want %q", tc.input, got, tc.want)
			}
		})
	}
}

func TestNormalizeAdminRole(t *testing.T) {
	cases := []struct {
		input   string
		want    string
		wantErr bool
	}{
		{AdminRoleAdmin, AdminRoleAdmin, false},
		{" SuperAdmin ", AdminRoleSuperAdmin, false},
		{"", "", true},
		{"owner", "", true},
	}
	for _, tc := range cases {
		t.Run(tc.input, func(t *testing.T) {
			got, err := NormalizeAdminRole(tc.input)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("NormalizeAdminRole(%q) = %q, want error", tc.input, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("NormalizeAdminRole(%q): %v", tc.input, err)
			}
			if got != tc.want {
				t.Fatalf("NormalizeAdminRole(%q) = %q, want %q", tc.input, got, tc.want)
			}
		})
	}
}
