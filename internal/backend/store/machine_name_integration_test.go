package store

import (
	"context"
	"encoding/json"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"mandatnik/internal/backend/config"
	"mandatnik/internal/backend/db"
	"mandatnik/internal/protocol"
)

func TestMachineRenameSQLServer(t *testing.T) {
	file := os.Getenv("MANDATNIK_POLICY_TEST_CONFIG")
	if file == "" {
		t.Skip("set MANDATNIK_POLICY_TEST_CONFIG to an authorized SQL Server acceptance config")
	}
	raw, err := os.ReadFile(file)
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
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
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

	customName := "Бухгалтерия-" + strings.ToUpper(protocol.NewUUID()[:8])
	result, err := s.RenameMachine(ctx, f.machineID, "  "+customName+"  ", "admin@test")
	if err != nil {
		t.Fatalf("rename machine: %v", err)
	}
	if result.DisplayName != customName || !result.DisplayNameCustom || result.MachineID != f.machineID {
		t.Fatalf("rename result = %+v", result)
	}
	detail, err := s.MachineDetail(ctx, f.machineID)
	if err != nil {
		t.Fatal(err)
	}
	if detail.Machine.DisplayName != customName || !detail.Machine.DisplayNameCustom {
		t.Fatalf("detail display name = %q custom=%t", detail.Machine.DisplayName, detail.Machine.DisplayNameCustom)
	}
	if detail.Machine.Hostname != f.hostname || detail.Machine.UUID != f.uuid {
		t.Fatalf("admin rename changed agent identity: hostname=%q uuid=%q", detail.Machine.Hostname, detail.Machine.UUID)
	}
	page, err := s.ListMachines(ctx, AdminMachineFilter{Query: customName, Page: 1, PageSize: 25})
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Items) != 1 || page.Items[0].MachineID != f.machineID {
		t.Fatalf("search by custom name = %+v", page.Items)
	}
	var events int
	if err := pool.QueryRowContext(ctx, `
SELECT COUNT(1) FROM dbo.events WHERE machine_id=@p1 AND kind=N'machine_display_name_changed'`, f.machineID).Scan(&events); err != nil {
		t.Fatal(err)
	}
	if events != 1 {
		t.Fatalf("display-name audit events = %d, want 1", events)
	}
	if _, err := s.RenameMachine(ctx, f.machineID, "line\nbreak", "admin@test"); err == nil {
		t.Fatal("control characters in display name were accepted")
	}
	if _, err := s.RenameMachine(ctx, f.machineID, "   ", "admin@test"); err == nil {
		t.Fatal("empty display name was accepted")
	}

	// A confirmed installation replacement must keep the administrator's name
	// while changing UUID, key and last-seen metadata.
	key, err := protocol.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	pending := f.newPending(t, key, protocol.NewUUID(), "0.5.0-test")
	replacement, apiErr := s.ReplaceInstallation(ctx, InstallationDecisionInput{
		RequestID: pending.RequestID, RequestVersion: pending.RequestVersion,
		KeyFingerprint: pending.KeyFingerprint, MachineID: f.machineID, OldRegistrationID: f.regID,
	}, "admin@test")
	if apiErr != nil {
		t.Fatalf("replace installation: %v", apiErr)
	}
	detail, err = s.MachineDetail(ctx, f.machineID)
	if err != nil {
		t.Fatal(err)
	}
	if detail.Machine.DisplayName != customName || detail.Machine.UUID != replacement.UUID {
		t.Fatalf("replacement overwrote custom name: name=%q uuid=%q", detail.Machine.DisplayName, detail.Machine.UUID)
	}

	// A signed rename of the same installation also keeps the custom name.
	renameKey, err := protocol.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	newUUID := protocol.NewUUID()
	f.uuids = append(f.uuids, newUUID)
	newHostname := f.hostname + "-RENAMED"
	rename := &protocol.SignedRequest{Data: protocol.SignedData{
		ProtocolVersion: protocol.ProtocolVersion, Operation: protocol.OpRename,
		RequestID: protocol.NewUUID(), UUID: replacement.UUID, Hostname: f.hostname,
		Method: protocol.MethodPost, Path: protocol.PathRename,
		IssuedAt: time.Now().UTC().Format(time.RFC3339Nano), AgentVersion: "0.5.0-test",
		OSVersion: "Windows 10 22H2", Architecture: "amd64",
		NewUUID: newUUID, NewHostname: newHostname, NewPublicKey: testPublicPEM(t, &renameKey.PublicKey),
	}}
	if _, apiErr := s.Rename(ctx, rename, net.ParseIP("192.0.2.20"), "verified"); apiErr != nil {
		t.Fatalf("signed rename: %v", apiErr)
	}
	detail, err = s.MachineDetail(ctx, f.machineID)
	if err != nil {
		t.Fatal(err)
	}
	if detail.Machine.DisplayName != customName {
		t.Fatalf("signed rename overwrote custom name: %q", detail.Machine.DisplayName)
	}
	if !strings.EqualFold(detail.Machine.Hostname, newHostname) {
		t.Fatalf("signed rename did not update hostname: %q", detail.Machine.Hostname)
	}

	if _, err := s.RenameMachine(ctx, protocol.NewUUID(), "Новая машина", "admin@test"); err == nil {
		t.Fatal("renaming an unknown machine succeeded")
	}
}
