package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"unicode"
	"unicode/utf16"

	"mandatnik/internal/protocol"
)

const machineDisplayNameMax = 253

// MachineNameResult is returned after an administrator changes the display
// name of a machine card. It never changes hostname, UUID or machine_id.
type MachineNameResult struct {
	MachineID         string `json:"machine_id"`
	DisplayName       string `json:"display_name"`
	DisplayNameCustom bool   `json:"display_name_custom"`
}

// NormalizeMachineDisplayName trims a human-readable ARM name and rejects
// empty names, control characters and values that do not fit NVARCHAR(253).
func NormalizeMachineDisplayName(value string) (string, error) {
	name := strings.TrimSpace(value)
	if name == "" {
		return "", fmt.Errorf("имя АРМ обязательно")
	}
	if len(utf16.Encode([]rune(name))) > machineDisplayNameMax {
		return "", fmt.Errorf("имя АРМ должно быть не длиннее %d символов", machineDisplayNameMax)
	}
	for _, r := range name {
		if r == 0 || unicode.IsControl(r) {
			return "", fmt.Errorf("имя АРМ не должно содержать управляющих символов")
		}
	}
	return name, nil
}

// RenameMachine changes only machines.display_name. The agent hostname,
// registration, UUID and machine_id stay untouched. The custom flag makes the
// name survive later signed renames and installation replacements.
func (s *Store) RenameMachine(ctx context.Context, machineID, displayName, admin string) (*MachineNameResult, error) {
	id, err := protocol.NormalizeUUID(machineID)
	if err != nil {
		return nil, fmt.Errorf("invalid machine identifier")
	}
	name, err := NormalizeMachineDisplayName(displayName)
	if err != nil {
		return nil, err
	}
	tx, err := s.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	var oldName string
	var custom bool
	if err := tx.QueryRowContext(ctx, `
SELECT display_name,display_name_custom FROM dbo.machines WITH (UPDLOCK,HOLDLOCK) WHERE machine_id=@p1`, id).
		Scan(&oldName, &custom); errors.Is(err, sql.ErrNoRows) {
		return nil, sql.ErrNoRows
	} else if err != nil {
		return nil, err
	}
	if oldName == name && custom {
		if err := tx.Commit(); err != nil {
			return nil, err
		}
		return &MachineNameResult{MachineID: id, DisplayName: name, DisplayNameCustom: true}, nil
	}
	now := s.now()
	if _, err := tx.ExecContext(ctx, `
UPDATE dbo.machines SET display_name=@p1,display_name_custom=1,updated_at=@p2 WHERE machine_id=@p3`,
		name, now, id); err != nil {
		return nil, err
	}
	if err := insertEvent(ctx, tx, id, nil, nil, nil, "machine_display_name_changed", "info",
		"administrator changed the machine display name",
		map[string]any{"admin": admin, "old_display_name": oldName, "new_display_name": name}, now); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return &MachineNameResult{MachineID: id, DisplayName: name, DisplayNameCustom: true}, nil
}
