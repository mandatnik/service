package api

import (
	"context"
	"net"
	"testing"
	"time"
)

func TestDNSCacheStatusIsNonBlocking(t *testing.T) {
	cache := newDNSCache(time.Minute)
	start := time.Now()
	status := cache.status(context.Background(), "does-not-exist.invalid", net.ParseIP("192.0.2.10"))
	elapsed := time.Since(start)
	if elapsed > 250*time.Millisecond {
		t.Fatalf("dns status blocked for %s", elapsed)
	}
	if status == "" {
		t.Fatal("dns status must not be empty while refreshing")
	}
}

func TestDNSVerificationIsUnknownBeforeLookupFinishes(t *testing.T) {
	cache := newDNSCache(time.Minute)
	verification := cache.verification(context.Background(), "does-not-exist.invalid", net.ParseIP("192.0.2.10"))
	if verification.Forward == "verified" || verification.Reverse == "verified" {
		t.Fatalf("fresh cache must not claim confirmation: %+v", verification)
	}
}

func TestReverseMatchesHostname(t *testing.T) {
	cases := []struct {
		name     string
		names    []string
		hostname string
		want     bool
	}{
		{"exact short name", []string{"ws-1"}, "ws-1", true},
		{"case and trailing dot", []string{"WS-1.EXAMPLE.LOCAL."}, "ws-1.example.local", true},
		{"fqdn ptr for short hostname", []string{"ws-1.example.local."}, "ws-1", true},
		{"fqdn must match exactly", []string{"example.com.evil."}, "example.com", false},
		{"unrelated prefix is not a match", []string{"ws-10.example.local."}, "ws-1", false},
		{"different label", []string{"ws-2.example.local."}, "ws-1", false},
		{"empty hostname", []string{"ws-1.example.local."}, "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := reverseMatchesHostname(tc.names, tc.hostname); got != tc.want {
				t.Fatalf("reverseMatchesHostname(%v, %q) = %v, want %v", tc.names, tc.hostname, got, tc.want)
			}
		})
	}
}
