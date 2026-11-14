package store

import (
	"strings"
	"testing"
)

func TestNormalizeMachineDisplayName(t *testing.T) {
	valid := []struct{ input, want string }{
		{"  Бухгалтерия-01  ", "Бухгалтерия-01"},
		{"АРМ № 42", "АРМ № 42"},
		{strings.Repeat("я", machineDisplayNameMax), strings.Repeat("я", machineDisplayNameMax)},
	}
	for _, tc := range valid {
		got, err := NormalizeMachineDisplayName(tc.input)
		if err != nil || got != tc.want {
			t.Fatalf("NormalizeMachineDisplayName(%q) = %q, %v; want %q", tc.input, got, err, tc.want)
		}
	}
	invalid := []string{"", "   ", "line\nbreak", "nul\x00byte", strings.Repeat("я", machineDisplayNameMax+1)}
	for _, input := range invalid {
		if _, err := NormalizeMachineDisplayName(input); err == nil {
			t.Fatalf("NormalizeMachineDisplayName(%q) succeeded, want error", input)
		}
	}
}
