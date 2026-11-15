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
