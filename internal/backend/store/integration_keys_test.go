package store

import (
	"net"
	"reflect"
	"testing"
)

func TestNormalizeAllowedIPs(t *testing.T) {
	values, err := NormalizeAllowedIPs([]string{
		"192.168.189.0/24",
		"192.168.189.5",
		" 192.168.189.5 ",
		"2001:db8::/32",
		"2001:DB8:0:0:0:0:0:1",
	})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"192.168.189.0/24", "192.168.189.5", "2001:db8::/32", "2001:db8::1"}
	if !reflect.DeepEqual(values, want) {
		t.Fatalf("normalized = %#v, want %#v", values, want)
	}
	for _, raw := range []string{"", "not-an-ip", "192.168.1.1/33", "10.0.0.0/"} {
		if _, err := NormalizeAllowedIPs([]string{raw}); err == nil {
			t.Fatalf("invalid allowlist entry accepted: %q", raw)
		}
	}
}

func TestIntegrationKeyAllowsIP(t *testing.T) {
	key := IntegrationKey{AllowedIPs: []string{"192.168.189.0/24", "127.0.0.1", "2001:db8::1"}}
	if !key.AllowsIP(net.ParseIP("192.168.189.140")) {
		t.Fatal("CIDR address rejected")
	}
	if !key.AllowsIP(net.ParseIP("127.0.0.1")) {
		t.Fatal("exact address rejected")
	}
	if !key.AllowsIP(net.ParseIP("2001:db8::1")) {
		t.Fatal("IPv6 address rejected")
	}
	if key.AllowsIP(net.ParseIP("192.168.190.1")) {
		t.Fatal("outside address accepted")
	}
	if key.AllowsIP(nil) {
		t.Fatal("nil address accepted")
	}
	empty := IntegrationKey{}
	if empty.AllowsIP(net.ParseIP("127.0.0.1")) {
		t.Fatal("empty allowlist accepted an address")
	}
}

func TestIntegrationKeyAllowsIPRejectsMalformedEntries(t *testing.T) {
	key := IntegrationKey{AllowedIPs: []string{"broken", "10.0.0.0/99", ""}}
	if key.AllowsIP(net.ParseIP("10.0.0.1")) {
		t.Fatal("malformed allowlist matched an address")
	}
}
