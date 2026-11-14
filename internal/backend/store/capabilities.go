package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"sort"
	"strings"

	"telehack2026/internal/protocol"
)

// RegisterCapabilities records the agent's signed task capabilities and
// dedicated RSA-3072 encryption key. The transport identity remains the
// existing ECDSA key that signed this request.
func (s *Store) RegisterCapabilities(ctx context.Context, identity *Identity, input protocol.AgentCapabilities) (*protocol.CapabilitiesResponse, *protocol.APIError) {
	if len(input.Capabilities) == 0 || len(input.Capabilities) > 32 {
		return nil, &protocol.APIError{Code: protocol.CodeInvalidKey, Message: "capability list is invalid"}
	}
	capabilitySet := map[string]bool{}
	for _, capability := range input.Capabilities {
		if capability == "" || len(capability) > 64 {
			return nil, &protocol.APIError{Code: protocol.CodeInvalidKey, Message: "capability is invalid"}
		}
		capabilitySet[capability] = true
	}
	publicKey, err := protocol.ParseTaskPublicKeyPEM(input.EncryptionPublicKey)
	if err != nil {
		return nil, &protocol.APIError{Code: protocol.CodeInvalidKey, Message: err.Error()}
	}
	keyID, err := protocol.TaskPublicKeyID(publicKey)
	if err != nil {
		return nil, &protocol.APIError{Code: protocol.CodeInvalidKey, Message: "compute encryption key id"}
	}
	if keyID != strings.ToLower(input.EncryptionKeyID) {
		return nil, &protocol.APIError{Code: protocol.CodeInvalidKey, Message: "encryption_key_id does not match the public key"}
	}
	if input.EncryptionAlgorithm != protocol.EncryptionAlgorithmV1 {
		return nil, &protocol.APIError{Code: protocol.CodeInvalidKey, Message: "unsupported encryption algorithm"}
	}
	canonicalPEM, err := protocol.MarshalTaskPublicKeyPEM(publicKey)
	if err != nil {
		return nil, &protocol.APIError{Code: protocol.CodeInvalidKey, Message: "normalize encryption public key"}
	}
	now := s.now()
	tx, err := s.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return nil, &protocol.APIError{Code: protocol.CodeDatabase, Message: "begin capability registration"}
	}
	defer tx.Rollback()
	var currentKeyID string
	var currentPEM string
	err = tx.QueryRowContext(ctx, `
SELECT key_id,public_key_pem FROM dbo.agent_encryption_keys WITH (UPDLOCK,HOLDLOCK)
WHERE machine_id=@p1 AND registration_id=@p2 AND active=1 AND revoked_at IS NULL`,
		identity.MachineID, identity.RegistrationID).Scan(&currentKeyID, &currentPEM)
	switch {
	case err == nil:
		if currentKeyID != keyID && !input.EncryptionKeyRotate {
			return nil, &protocol.APIError{Code: protocol.CodeKeyConflict, Message: "a different encryption key is already active; explicit rotation is required"}
		}
		if currentKeyID != keyID {
			if _, err := tx.ExecContext(ctx, `
UPDATE dbo.agent_encryption_keys SET active=0 WHERE machine_id=@p1 AND active=1 AND revoked_at IS NULL`,
				identity.MachineID); err != nil {
				return nil, &protocol.APIError{Code: protocol.CodeDatabase, Message: "deactivate previous encryption key"}
			}
			if _, err := tx.ExecContext(ctx, `
INSERT INTO dbo.agent_encryption_keys(key_id,machine_id,registration_id,public_key_pem,algorithm,bits,active,created_at)
VALUES(@p1,@p2,@p3,@p4,@p5,3072,1,@p6)`,
				keyID, identity.MachineID, identity.RegistrationID, canonicalPEM, protocol.EncryptionAlgorithmV1, now); err != nil {
				if isDuplicateKey(err) {
					return nil, &protocol.APIError{Code: protocol.CodeKeyConflict, Message: "encryption key is already registered"}
				}
				return nil, &protocol.APIError{Code: protocol.CodeDatabase, Message: "register encryption key"}
			}
		}
	case errors.Is(err, sql.ErrNoRows):
		if _, err := tx.ExecContext(ctx, `
INSERT INTO dbo.agent_encryption_keys(key_id,machine_id,registration_id,public_key_pem,algorithm,bits,active,created_at)
VALUES(@p1,@p2,@p3,@p4,@p5,3072,1,@p6)`,
			keyID, identity.MachineID, identity.RegistrationID, canonicalPEM, protocol.EncryptionAlgorithmV1, now); err != nil {
			if isDuplicateKey(err) {
				return nil, &protocol.APIError{Code: protocol.CodeKeyConflict, Message: "encryption key is already registered"}
			}
			return nil, &protocol.APIError{Code: protocol.CodeDatabase, Message: "register encryption key"}
		}
	default:
		return nil, &protocol.APIError{Code: protocol.CodeDatabase, Message: "load current encryption key"}
	}
	sorted := append([]string(nil), input.Capabilities...)
	sort.Strings(sorted)
	capabilitiesJSON, _ := json.Marshal(sorted)
	if _, err := tx.ExecContext(ctx, `
MERGE dbo.agent_capabilities WITH (HOLDLOCK) AS target
USING (SELECT @p1 AS registration_id) AS source
ON target.registration_id=source.registration_id
WHEN MATCHED THEN UPDATE SET capabilities_json=@p2,schedule_v2=@p3,tasks_v1=@p4,install_v1=@p5,updated_at=@p6
WHEN NOT MATCHED THEN INSERT(registration_id,capabilities_json,schedule_v2,tasks_v1,install_v1,updated_at)
VALUES(@p1,@p2,@p3,@p4,@p5,@p6);`,
		identity.RegistrationID, string(capabilitiesJSON), capabilitySet[protocol.TaskCapabilityScheduleV2],
		capabilitySet[protocol.TaskCapabilityV1], capabilitySet[protocol.TaskCapabilityInstallV1], now); err != nil {
		return nil, &protocol.APIError{Code: protocol.CodeDatabase, Message: "store agent capabilities"}
	}
	config, configErr := effectiveConfigTx(ctx, tx, identity.MachineID)
	if configErr != nil {
		return nil, &protocol.APIError{Code: protocol.CodeDatabase, Message: "load configuration for capabilities"}
	}
	if _, err := tx.ExecContext(ctx, `
UPDATE dbo.registrations SET agent_version=@p1,os_version=COALESCE(@p2,os_version),architecture=COALESCE(@p3,architecture),last_seen_at=@p4
WHERE registration_id=@p5`, truncate(identity.AgentVersion, 128), nilIfEmpty(identity.OSVersion), nilIfEmpty(identity.Architecture), now, identity.RegistrationID); err != nil {
		return nil, &protocol.APIError{Code: protocol.CodeDatabase, Message: "update registration capabilities context"}
	}
	if err := tx.Commit(); err != nil {
		return nil, &protocol.APIError{Code: protocol.CodeDatabase, Message: "commit capability registration"}
	}
	cfg := config.Config.WithScheduleDefaults()
	return &protocol.CapabilitiesResponse{
		Accepted: true, ServerTime: protocol.FormatTaskTime(now), EncryptionKeyID: keyID,
		Config: &cfg, ConfigHash: config.Hash,
		PollIntervalSeconds: cfg.PollIntervalSeconds, TaskTTLSeconds: cfg.TaskTTLSeconds,
	}, nil
}
