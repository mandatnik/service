package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"

	mssql "github.com/microsoft/go-mssqldb"
	"mandatnik/internal/folderpolicy"
	"mandatnik/internal/protocol"
)

// ErrInvalidRules marks policy rule compilation errors separately from SQL
// failures so the integration API can return 422 instead of 500.
var ErrInvalidRules = errors.New("invalid folder policy rules")

type MachineGroup struct {
	ID         string   `json:"id"`
	Name       string   `json:"name"`
	MachineIDs []string `json:"machine_ids"`
}
type FolderPolicy struct {
	ID         string   `json:"id"`
	Name       string   `json:"name"`
	Rules      string   `json:"rules"`
	MachineIDs []string `json:"machine_ids"`
	GroupIDs   []string `json:"group_ids"`
}
type MachineTarget struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}
type InventorySettings struct {
	Groups   []MachineGroup  `json:"groups"`
	Policies []FolderPolicy  `json:"policies"`
	Machines []MachineTarget `json:"machines"`
}

func effectiveConfigTx(ctx context.Context, tx *sql.Tx, machineID string) (configRow, error) {
	row, err := loadConfigTx(ctx, tx)
	if err != nil {
		return row, err
	}
	var scheduleV2 bool
	err = tx.QueryRowContext(ctx, `
SELECT CASE WHEN EXISTS(
  SELECT 1 FROM dbo.agent_capabilities c
  JOIN dbo.registrations r ON r.registration_id=c.registration_id
  WHERE r.machine_id=@p1 AND r.state=N'active' AND c.schedule_v2=1) THEN 1 ELSE 0 END`, machineID).Scan(&scheduleV2)
	if err != nil {
		return row, err
	}
	if scheduleV2 {
		row.Config = row.Config.WithScheduleDefaults()
	} else {
		row.Config = row.Config.LegacyProjection()
	}
	row.Config.CertDirectories = []string{} // legacy global paths never reach an agent
	rows, err := tx.QueryContext(ctx, `SELECT p.policy_id,p.name,p.rules,
 CASE WHEN EXISTS(SELECT 1 FROM dbo.folder_policy_machines pm WHERE pm.policy_id=p.policy_id AND pm.machine_id=@p1) THEN 'machine' ELSE 'group' END
 FROM dbo.folder_policies p WHERE EXISTS(SELECT 1 FROM dbo.folder_policy_machines pm WHERE pm.policy_id=p.policy_id AND pm.machine_id=@p1)
 OR EXISTS(SELECT 1 FROM dbo.folder_policy_groups pg JOIN dbo.machine_group_members gm ON gm.group_id=pg.group_id WHERE pg.policy_id=p.policy_id AND gm.machine_id=@p1)
 ORDER BY p.policy_id`, machineID)
	if err != nil {
		return row, err
	}
	for rows.Next() {
		var p protocol.FolderPolicy
		var id mssql.UniqueIdentifier
		if err = rows.Scan(&id, &p.Name, &p.Rules, &p.Level); err != nil {
			rows.Close()
			return row, err
		}
		p.ID = uuidString(id)
		row.Config.FolderPolicies = append(row.Config.FolderPolicies, p)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return row, err
	}
	row.Hash, err = protocol.ConfigHash(row.Config)
	return row, err
}

func (s *Store) InventorySettings(ctx context.Context) (InventorySettings, error) {
	out := InventorySettings{Groups: []MachineGroup{}, Policies: []FolderPolicy{}, Machines: []MachineTarget{}}
	// One read transaction avoids a half-deleted policy/group during catalog reads.
	tx, err := s.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return out, err
	}
	defer tx.Rollback()
	rows, err := tx.QueryContext(ctx, `SELECT machine_id,display_name FROM dbo.machines ORDER BY display_name,machine_id`)
	if err != nil {
		return out, err
	}
	for rows.Next() {
		var m MachineTarget
		var id mssql.UniqueIdentifier
		if err = rows.Scan(&id, &m.Name); err != nil {
			rows.Close()
			return out, err
		}
		m.ID = uuidString(id)
		out.Machines = append(out.Machines, m)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return out, err
	}
	rows, err = tx.QueryContext(ctx, `SELECT group_id,name FROM dbo.machine_groups ORDER BY name,group_id`)
	if err != nil {
		return out, err
	}
	for rows.Next() {
		var g MachineGroup
		var id mssql.UniqueIdentifier
		if err = rows.Scan(&id, &g.Name); err != nil {
			rows.Close()
			return out, err
		}
		g.ID = uuidString(id)
		g.MachineIDs = []string{}
		out.Groups = append(out.Groups, g)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return out, err
	}
	rows, err = tx.QueryContext(ctx, `SELECT policy_id,name,rules FROM dbo.folder_policies ORDER BY name,policy_id`)
	if err != nil {
		return out, err
	}
	for rows.Next() {
		var p FolderPolicy
		var id mssql.UniqueIdentifier
		if err = rows.Scan(&id, &p.Name, &p.Rules); err != nil {
			rows.Close()
			return out, err
		}
		p.ID = uuidString(id)
		p.MachineIDs = []string{}
		p.GroupIDs = []string{}
		out.Policies = append(out.Policies, p)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return out, err
	}
	// Load all edges with three bounded queries rather than N+1 queries.
	queries := []string{`SELECT group_id,machine_id FROM dbo.machine_group_members ORDER BY machine_id`, `SELECT policy_id,machine_id FROM dbo.folder_policy_machines ORDER BY machine_id`, `SELECT policy_id,group_id FROM dbo.folder_policy_groups ORDER BY group_id`}
	for kind, q := range queries {
		rows, err = tx.QueryContext(ctx, q)
		if err != nil {
			return out, err
		}
		for rows.Next() {
			var a, b mssql.UniqueIdentifier
			if err = rows.Scan(&a, &b); err != nil {
				rows.Close()
				return out, err
			}
			parent, child := uuidString(a), uuidString(b)
			if kind == 0 {
				for i := range out.Groups {
					if out.Groups[i].ID == parent {
						out.Groups[i].MachineIDs = append(out.Groups[i].MachineIDs, child)
						break
					}
				}
			} else {
				for i := range out.Policies {
					if out.Policies[i].ID == parent {
						if kind == 1 {
							out.Policies[i].MachineIDs = append(out.Policies[i].MachineIDs, child)
						} else {
							out.Policies[i].GroupIDs = append(out.Policies[i].GroupIDs, child)
						}
						break
					}
				}
			}
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return out, err
		}
	}
	return out, tx.Commit()
}
func validateIDs(ids []string) error {
	if len(ids) > 10000 {
		return fmt.Errorf("слишком много назначений")
	}
	seen := map[string]bool{}
	for _, id := range ids {
		if err := validateUUID(id); err != nil {
			return fmt.Errorf("некорректный идентификатор")
		}
		key := strings.ToLower(id)
		if seen[key] {
			return fmt.Errorf("повторное назначение")
		}
		seen[key] = true
	}
	return nil
}
func validName(name string) bool {
	return len([]rune(name)) >= 1 && len([]rune(name)) <= 200 && !strings.ContainsAny(name, "\x00\r\n")
}

func (s *Store) SaveGroup(ctx context.Context, g MachineGroup, create bool, admin string) (string, error) {
	g.Name = strings.TrimSpace(g.Name)
	if !validName(g.Name) {
		return "", fmt.Errorf("название группы должно содержать от 1 до 200 символов")
	}
	if err := validateIDs(g.MachineIDs); err != nil {
		return "", err
	}
	if create {
		g.ID = protocol.NewUUID()
	} else if err := validateUUID(g.ID); err != nil {
		return "", err
	}
	tx, err := s.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return "", err
	}
	defer tx.Rollback()
	if create {
		_, err = tx.ExecContext(ctx, `INSERT INTO dbo.machine_groups(group_id,name) VALUES(@p1,@p2)`, g.ID, g.Name)
	} else {
		var result sql.Result
		result, err = tx.ExecContext(ctx, `UPDATE dbo.machine_groups SET name=@p2,updated_at=SYSUTCDATETIME() WHERE group_id=@p1`, g.ID, g.Name)
		if err == nil {
			n, _ := result.RowsAffected()
			if n == 0 {
				return "", sql.ErrNoRows
			}
		}
	}
	if err != nil {
		return "", err
	}
	if _, err = tx.ExecContext(ctx, `DELETE FROM dbo.machine_group_members WHERE group_id=@p1`, g.ID); err != nil {
		return "", err
	}
	for _, id := range g.MachineIDs {
		if _, err = tx.ExecContext(ctx, `INSERT INTO dbo.machine_group_members(group_id,machine_id) VALUES(@p1,@p2)`, g.ID, id); err != nil {
			return "", err
		}
	}
	if err = insertEvent(ctx, tx, nil, nil, nil, nil, "group_saved", "info", "machine group saved", map[string]any{"id": g.ID, "admin": admin}, s.now()); err != nil {
		return "", err
	}
	return g.ID, tx.Commit()
}
func (s *Store) AddGroupMembers(ctx context.Context, id string, machines []string, admin string) error {
	if err := validateUUID(id); err != nil {
		return err
	}
	if err := validateIDs(machines); err != nil {
		return err
	}
	tx, err := s.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var exists int
	if err = tx.QueryRowContext(ctx, `SELECT 1 FROM dbo.machine_groups WITH(UPDLOCK,HOLDLOCK) WHERE group_id=@p1`, id).Scan(&exists); err != nil {
		return err
	}
	for _, machine := range machines {
		if _, err = tx.ExecContext(ctx, `IF NOT EXISTS(SELECT 1 FROM dbo.machine_group_members WHERE group_id=@p1 AND machine_id=@p2) INSERT INTO dbo.machine_group_members(group_id,machine_id) VALUES(@p1,@p2)`, id, machine); err != nil {
			return err
		}
	}
	if err = insertEvent(ctx, tx, nil, nil, nil, nil, "group_members_added", "info", "machines added to group", map[string]any{"id": id, "machines": machines, "admin": admin}, s.now()); err != nil {
		return err
	}
	return tx.Commit()
}
func (s *Store) SaveFolderPolicy(ctx context.Context, p FolderPolicy, create bool, admin string) (string, error) {
	p.Name = strings.TrimSpace(p.Name)
	if !validName(p.Name) {
		return "", fmt.Errorf("название политики должно содержать от 1 до 200 символов")
	}
	if _, err := folderpolicy.Compile(p.Rules); err != nil {
		return "", fmt.Errorf("%w: %v", ErrInvalidRules, err)
	}
	if err := validateIDs(p.MachineIDs); err != nil {
		return "", err
	}
	if err := validateIDs(p.GroupIDs); err != nil {
		return "", err
	}
	if create {
		p.ID = protocol.NewUUID()
	} else if err := validateUUID(p.ID); err != nil {
		return "", err
	}
	tx, err := s.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return "", err
	}
	defer tx.Rollback()
	if create {
		var count int
		if err = tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM dbo.folder_policies WITH(UPDLOCK,HOLDLOCK)`).Scan(&count); err != nil {
			return "", err
		}
		if count >= 128 {
			return "", fmt.Errorf("допускается не более 128 политик")
		}
		_, err = tx.ExecContext(ctx, `INSERT INTO dbo.folder_policies(policy_id,name,rules) VALUES(@p1,@p2,@p3)`, p.ID, p.Name, p.Rules)
	} else {
		var result sql.Result
		result, err = tx.ExecContext(ctx, `UPDATE dbo.folder_policies SET name=@p2,rules=@p3,updated_at=SYSUTCDATETIME() WHERE policy_id=@p1`, p.ID, p.Name, p.Rules)
		if err == nil {
			n, _ := result.RowsAffected()
			if n == 0 {
				return "", sql.ErrNoRows
			}
		}
	}
	if err != nil {
		return "", err
	}
	for _, table := range []string{"folder_policy_machines", "folder_policy_groups"} {
		if _, err = tx.ExecContext(ctx, `DELETE FROM dbo.`+table+` WHERE policy_id=@p1`, p.ID); err != nil {
			return "", err
		}
	}
	for _, id := range p.MachineIDs {
		if _, err = tx.ExecContext(ctx, `INSERT INTO dbo.folder_policy_machines(policy_id,machine_id) VALUES(@p1,@p2)`, p.ID, id); err != nil {
			return "", err
		}
	}
	for _, id := range p.GroupIDs {
		if _, err = tx.ExecContext(ctx, `INSERT INTO dbo.folder_policy_groups(policy_id,group_id) VALUES(@p1,@p2)`, p.ID, id); err != nil {
			return "", err
		}
	}
	if err = insertEvent(ctx, tx, nil, nil, nil, nil, "folder_policy_saved", "info", "folder policy saved", map[string]any{"id": p.ID, "admin": admin}, s.now()); err != nil {
		return "", err
	}
	return p.ID, tx.Commit()
}
func (s *Store) DeleteInventoryItem(ctx context.Context, kind, id, admin string) error {
	if err := validateUUID(id); err != nil {
		return err
	}
	tx, err := s.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var statements []string
	switch kind {
	case "groups":
		statements = []string{`DELETE FROM dbo.folder_policy_groups WHERE group_id=@p1`, `DELETE FROM dbo.machine_group_members WHERE group_id=@p1`, `DELETE FROM dbo.machine_groups WHERE group_id=@p1`}
	case "folder-policies":
		statements = []string{`DELETE FROM dbo.folder_policy_groups WHERE policy_id=@p1`, `DELETE FROM dbo.folder_policy_machines WHERE policy_id=@p1`, `DELETE FROM dbo.folder_policies WHERE policy_id=@p1`}
	default:
		return fmt.Errorf("unknown kind")
	}
	for i, q := range statements {
		result, e := tx.ExecContext(ctx, q, id)
		if e != nil {
			return e
		}
		if i == len(statements)-1 {
			n, _ := result.RowsAffected()
			if n == 0 {
				return sql.ErrNoRows
			}
		}
	}
	if err = insertEvent(ctx, tx, nil, nil, nil, nil, "inventory_item_deleted", "info", "group or policy deleted", map[string]any{"kind": kind, "id": id, "admin": admin}, s.now()); err != nil {
		return err
	}
	return tx.Commit()
}

func validateUUID(id string) error {
	v, err := protocol.NormalizeUUID(id)
	if err != nil {
		return err
	}
	if !strings.EqualFold(v, id) {
		return fmt.Errorf("нужен канонический UUID")
	}
	return nil
}
