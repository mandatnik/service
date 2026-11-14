package protocol

import (
	"strings"
	"testing"
)

func TestJCSKnownVectors(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "key ordering",
			input:    `{"b":1,"a":2,"aa":3}`,
			expected: `{"a":2,"aa":3,"b":1}`,
		},
		{
			name:     "rfc8785 values vector",
			input:    `{"numbers": [333333333.33333329, 1E30, 4.50, 2e-3, 0.000000000000000000000000001], "string": "\u20ac$\u000F\u000aA'\u0042\u0022\u005c\\\"\/", "literals": [null, true, false]}`,
			expected: "{\"literals\":[null,true,false],\"numbers\":[333333333.3333333,1e+30,4.5,0.002,1e-27],\"string\":\"€$\\u000f\\nA'B\\\"\\\\\\\\\\\"/\"}",
		},
		{
			name:     "rfc8785 unicode ordering vector",
			input:    `{"\u20ac": "Euro Sign", "\r": "Carriage Return", "\u000a": "Newline", "1": "One", "\u0080": "Control\u007f", "\ud83d\ude02": "Smiley", "\u00f6": "Latin Small Letter O With Diaeresis", "\ufb33": "Hebrew Letter Dalet With Dagesh", "</script>": "Browser Challenge"}`,
			expected: "{\"\\n\":\"Newline\",\"\\r\":\"Carriage Return\",\"1\":\"One\",\"</script>\":\"Browser Challenge\",\"\u0080\":\"Control\u007f\",\"ö\":\"Latin Small Letter O With Diaeresis\",\"€\":\"Euro Sign\",\"😂\":\"Smiley\",\"\ufb33\":\"Hebrew Letter Dalet With Dagesh\"}",
		},
		{
			name:     "cyrillic",
			input:    `{"имя":"Тест","hostname":"WORKSTATION-1","uuid":"5b0f1c4e-8a4c-4d1e-9f0a-3f0a5d6e7c8b"}`,
			expected: `{"hostname":"WORKSTATION-1","uuid":"5b0f1c4e-8a4c-4d1e-9f0a-3f0a5d6e7c8b","имя":"Тест"}`,
		},
		{
			name:     "escaped characters",
			input:    `{"v":"a\tb\nc\"d\\e\/f"}`,
			expected: `{"v":"a\tb\nc\"d\\e/f"}`,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := Canonicalize([]byte(test.input))
			if err != nil {
				t.Fatalf("Canonicalize: %v", err)
			}
			if string(got) != test.expected {
				t.Fatalf("canonical form mismatch:\n got %q\nwant %q", got, test.expected)
			}
		})
	}
}

func TestJCSRejectsDuplicateKeys(t *testing.T) {
	cases := []string{
		`{"a":1,"a":2}`,
		`{"outer":{"x":1,"x":2}}`,
		`{"arr":[{"k":1,"k":2}]}`,
		`{"a":1,"b":{"c":3},"a":2}`,
	}
	for _, input := range cases {
		if _, err := Canonicalize([]byte(input)); err == nil {
			t.Fatalf("expected duplicate-key rejection for %s", input)
		} else if !strings.Contains(err.Error(), "duplicate JSON object key") {
			t.Fatalf("unexpected error for %s: %v", input, err)
		}
	}
}

func TestJCSRejectsInvalidInput(t *testing.T) {
	cases := [][]byte{
		nil,
		[]byte(``),
		[]byte(`{"a":`),
		[]byte(`{"a":1} trailing`),
		{0x7b, 0x22, 0x61, 0x22, 0x3a, 0x22, 0xff, 0x22, 0x7d},
	}
	for _, input := range cases {
		if _, err := Canonicalize(input); err == nil {
			t.Fatalf("expected rejection for %q", input)
		}
	}
}
