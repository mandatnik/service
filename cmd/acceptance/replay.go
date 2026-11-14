package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"telehack2026/internal/backend/db"
	"telehack2026/internal/protocol"
)

type replayFile struct {
	UUID      string `json:"uuid"`
	MachineID string `json:"machine_id"`
	Body      string `json:"body_base64"`
}

func prepareReplay(ctx context.Context, cfg acceptanceConfig, path string) error {
	client, err := newClient(cfg.ServerURL, cfg.CAFile, 60*time.Second)
	if err != nil {
		return err
	}
	id, err := newIdentity("ACCEPT-REPLAY-" + strings.ToUpper(protocol.NewUUID()[:8]))
	if err != nil {
		return err
	}
	response, result, err := client.register(ctx, id)
	if err != nil || result.Error != nil {
		return fmt.Errorf("register replay identity: %v %v", result.Error, err)
	}
	data := baseData(protocol.OpSync, protocol.PathSync, id)
	body, err := protocol.BuildSignedEnvelope(id.Key, data)
	if err != nil {
		return err
	}
	result = client.post(ctx, protocol.PathSync, body)
	if result.Error != nil {
		return fmt.Errorf("first sync: %s", result.Error.Message)
	}
	raw, _ := json.MarshalIndent(replayFile{UUID: id.UUID, MachineID: response.MachineID, Body: base64.StdEncoding.EncodeToString(body)}, "", "  ")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		return err
	}
	fmt.Println("replay prepared:", path)
	return nil
}

func checkReplay(ctx context.Context, cfg acceptanceConfig, path string) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var file replayFile
	if err := json.Unmarshal(raw, &file); err != nil {
		return err
	}
	body, err := base64.StdEncoding.DecodeString(file.Body)
	if err != nil {
		return err
	}
	client, err := newClient(cfg.ServerURL, cfg.CAFile, 60*time.Second)
	if err != nil {
		return err
	}
	result := client.post(ctx, protocol.PathSync, body)
	if result.Error == nil || result.Error.Code != protocol.CodeReplay {
		return fmt.Errorf("replay after restart was not rejected: status=%d error=%v", result.Status, result.Error)
	}
	pool, err := db.Open(ctx, cfg.DB)
	if err != nil {
		return err
	}
	defer pool.Close()
	if _, err := pool.ExecContext(ctx, `DELETE FROM dbo.events WHERE machine_id=@p1`, file.MachineID); err != nil {
		return err
	}
	if _, err := pool.ExecContext(ctx, `DELETE FROM dbo.request_ids WHERE identity_uuid=@p1`, file.UUID); err != nil {
		return err
	}
	if _, err := pool.ExecContext(ctx, `UPDATE dbo.registrations SET previous_registration_id=NULL, replaced_by_registration_id=NULL WHERE machine_id=@p1`, file.MachineID); err != nil {
		return err
	}
	if _, err := pool.ExecContext(ctx, `DELETE FROM dbo.hostnames WHERE owner_machine_id=@p1`, file.MachineID); err != nil {
		return err
	}
	if _, err := pool.ExecContext(ctx, `DELETE FROM dbo.registrations WHERE machine_id=@p1`, file.MachineID); err != nil {
		return err
	}
	if _, err := pool.ExecContext(ctx, `DELETE FROM dbo.machines WHERE machine_id=@p1`, file.MachineID); err != nil {
		return err
	}
	fmt.Println("replay after backend restart rejected with", protocol.CodeReplay)
	return nil
}
