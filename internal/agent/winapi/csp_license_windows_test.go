//go:build windows

package winapi

import "testing"

func TestMSICompressedGUID(t *testing.T) {
	cases := map[string]string{
		"{50F91F80-D397-437C-B0C8-62128DE3B55E}": "08F19F05793DC7340B8C2621D83E5BE5",
		"{407E5BA7-6406-40BF-A4DC-3654B8F584C1}": "7AB5E7046046FB044ACD63458B5F481C",
	}
	for guid, expected := range cases {
		got, err := msiCompressedGUID(guid)
		if err != nil {
			t.Fatalf("%s: %v", guid, err)
		}
		if got != expected {
			t.Fatalf("%s: got %s, want %s", guid, got, expected)
		}
	}
}

func TestMSICompressedGUIDRejectsMalformedValue(t *testing.T) {
	if _, err := msiCompressedGUID("{not-a-guid}"); err == nil {
		t.Fatal("malformed GUID accepted")
	}
}
