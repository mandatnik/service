package protocol

import (
	"strconv"
	"strings"
	"testing"
)

func TestJSONObjectMemberLimit(t *testing.T) {
	build := func(n int) []byte {
		var b strings.Builder
		b.WriteByte('{')
		for i := 0; i < n; i++ {
			if i > 0 {
				b.WriteByte(',')
			}
			b.WriteString(strconv.Quote("k" + strconv.Itoa(i)))
			b.WriteString(":1")
		}
		b.WriteByte('}')
		return []byte(b.String())
	}
	if err := RejectDuplicateKeys(build(MaxJSONObjectMembers)); err != nil {
		t.Fatalf("%d members rejected: %v", MaxJSONObjectMembers, err)
	}
	if err := RejectDuplicateKeys(build(MaxJSONObjectMembers + 1)); err == nil {
		t.Fatalf("%d members accepted", MaxJSONObjectMembers+1)
	}
}

func TestJSONDepthLimit(t *testing.T) {
	build := func(depth int) []byte {
		return []byte(strings.Repeat("[", depth) + "0" + strings.Repeat("]", depth))
	}
	if err := RejectDuplicateKeys(build(MaxJSONDepth)); err != nil {
		t.Fatalf("depth %d rejected: %v", MaxJSONDepth, err)
	}
	if err := RejectDuplicateKeys(build(MaxJSONDepth + 1)); err == nil {
		t.Fatalf("depth %d accepted", MaxJSONDepth+1)
	}
}

func TestJSONBudgetAllowsReportShape(t *testing.T) {
	// A report contains arrays of many small objects; only the member count of
	// one object is limited, so a realistic report shape stays valid.
	var b strings.Builder
	b.WriteString(`{"report":{"sources":[`)
	for i := 0; i < 2000; i++ {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString(`{"source_type":"user_store","source_key":"S-1-5-21-1-2-3-` + strconv.Itoa(i) + `","complete":true,"certificates":[],"files":[]}`)
	}
	b.WriteString(`]}}`)
	if err := RejectDuplicateKeys([]byte(b.String())); err != nil {
		t.Fatalf("realistic report shape rejected: %v", err)
	}
}
