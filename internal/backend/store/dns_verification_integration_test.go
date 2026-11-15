package store

import (
	"context"
	"encoding/json"
	"net"
	"os"
	"testing"
	"time"

	"mandatnik/internal/backend/config"
	"mandatnik/internal/backend/db"
	"mandatnik/internal/protocol"
)

func TestDNSVerificationSQLServer(t *testing.T) {
	path := os.Getenv("MANDATNIK_POLICY_TEST_CONFIG")
	if path == "" {
		t.Skip("set MANDATNIK_POLICY_TEST_CONFIG to an authorized SQL Server acceptance config")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var cfg struct {
		DB config.DB `json:"db"`
	}
	if err = json.Unmarshal(raw, &cfg); err != nil {
		t.Fatal(err)
	}
	if err = cfg.DB.Validate(); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	pool, err := db.Open(ctx, cfg.DB)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pool.Close() })
	if err = db.Migrate(ctx, pool, t.Logf); err != nil {
		t.Fatal(err)
	}
	s := New(pool)
	f := newInstallationFixture(t, ctx, pool, s)
	now := time.Now().UTC().Truncate(time.Millisecond)
	s.Now = func() time.Time { return now }
	source := net.ParseIP("192.0.2.10")
	identity, apiErr := s.LookupActiveIdentity(ctx, f.uuid)
	if apiErr != nil {
		t.Fatal(apiErr)
	}
	verify := func(forward, reverse string, at time.Time) {
		t.Helper()
		s.RecordDNSVerification(ctx, f.uuid, DNSVerification{Forward: forward, Reverse: reverse, Hostname: f.hostname, SourceIP: source, CheckedAt: at})
	}
	assertBadge := func(want bool) {
		t.Helper()
		page, err := s.ListMachines(ctx, AdminMachineFilter{MachineID: f.machineID})
		if err != nil || len(page.Items) != 1 {
			t.Fatalf("machine: %+v err=%v", page, err)
		}
		if page.Items[0].DNSVerified != want {
			t.Fatalf("DNSVerified=%v want %v; timestamp=%v", page.Items[0].DNSVerified, want, page.Items[0].DNSVerifiedAt)
		}
	}
	stale := now.Add(-16 * time.Minute)
	verify("verified", "verified", stale)
	assertBadge(false)
	s.UpdateNetworkTrust(ctx, identity, source, "verified")
	assertBadge(false)
	var recorded time.Time
	if err := pool.QueryRowContext(ctx, `SELECT last_dns_mutual_checked_at FROM dbo.registrations WHERE registration_id=@p1`, f.regID).Scan(&recorded); err != nil {
		t.Fatal(err)
	}
	if recorded.Sub(stale) > time.Millisecond || stale.Sub(recorded) > time.Millisecond {
		t.Fatalf("forward-only update refreshed the mutual timestamp: %v", recorded)
	}
	// Neither register nor sync is allowed to refresh stale mutual verification.
	repeated := &protocol.SignedRequest{Data: protocol.SignedData{
		ProtocolVersion: protocol.ProtocolVersion, Operation: protocol.OpRegister,
		RequestID: protocol.NewUUID(), UUID: f.uuid, Hostname: f.hostname,
		Method: protocol.MethodPost, Path: protocol.PathRegister, IssuedAt: protocol.FormatTaskTime(now),
		AgentVersion: "0.5.0-test", OSVersion: "Windows 10 22H2", Architecture: "amd64", PublicKey: identity.PublicKeyPEM,
	}}
	if _, apiErr := s.Register(ctx, repeated, source, "verified"); apiErr != nil {
		t.Fatal(apiErr)
	}
	assertBadge(false)
	if _, apiErr := s.Sync(ctx, identity, &protocol.SignedRequest{Data: protocol.SignedData{RequestID: protocol.NewUUID()}}, source, "verified"); apiErr != nil {
		t.Fatal(apiErr)
	}
	assertBadge(false)
	canceled, stop := context.WithCancel(ctx)
	stop()
	s.RecordDNSVerification(canceled, f.uuid, DNSVerification{Forward: "verified", Reverse: "verified", Hostname: f.hostname, SourceIP: source, CheckedAt: now})
	assertBadge(false)
	// Forward-only status changes cannot combine with the reverse half of a
	// failed mutual result to invent a successful verification.
	verify("mismatch", "verified", now)
	s.UpdateNetworkTrust(ctx, identity, source, "verified")
	assertBadge(false)
	verify("verified", "mismatch", now)
	s.UpdateNetworkTrust(ctx, identity, source, "verified")
	assertBadge(false)
	verify("verified", "verified", now)
	assertBadge(true)
	s.UpdateNetworkTrust(ctx, identity, source, "mismatch")
	assertBadge(false)
	s.UpdateNetworkTrust(ctx, identity, net.ParseIP("192.0.2.11"), "verified")
	assertBadge(false)
	s.UpdateNetworkTrust(ctx, identity, source, "verified")
	assertBadge(true)
	// Legacy rows have no reliable mutual timestamp; do not backfill from a
	// heartbeat timestamp that may already have been refreshed.
	if _, err := pool.ExecContext(ctx, `UPDATE dbo.registrations SET last_dns_mutual_forward_status=NULL,last_dns_mutual_checked_at=NULL WHERE registration_id=@p1`, f.regID); err != nil {
		t.Fatal(err)
	}
	assertBadge(false)
	verify("verified", "verified", now)
	assertBadge(true)
}
