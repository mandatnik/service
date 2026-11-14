package main

import (
	"context"
	"fmt"
	"strings"
)

func (c *contract) cleanup(ctx context.Context) error {
	machines := uniqueStrings(c.machineIDs)
	uuids := uniqueStrings(c.uuids)
	if len(machines) == 0 && len(uuids) == 0 {
		return nil
	}
	tx, err := c.pool.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	deleteWithMachines := func(query string) error {
		if len(machines) == 0 {
			return nil
		}
		args, placeholders := machineArgs(machines)
		_, err := tx.ExecContext(ctx, fmt.Sprintf(query, placeholders), args...)
		return err
	}
	if len(uuids) > 0 {
		args, placeholders := stringArgs(uuids)
		if _, err := tx.ExecContext(ctx, fmt.Sprintf(`DELETE FROM dbo.agent_install_requests WHERE uuid IN (%s)`, placeholders), args...); err != nil {
			return err
		}
	}
	if err := deleteWithMachines(`DELETE FROM dbo.events WHERE machine_id IN (%s)`); err != nil {
		return err
	}
	if err := deleteWithMachines(`
DELETE FROM dbo.machine_user_certificates
WHERE machine_user_id IN (SELECT machine_user_id FROM dbo.machine_users WHERE machine_id IN (%s))`); err != nil {
		return err
	}
	if err := deleteWithMachines(`DELETE FROM dbo.certificate_observation_bindings
WHERE observation_id IN (SELECT observation_id FROM dbo.certificate_observations WHERE machine_id IN (%s))`); err != nil {
		return err
	}
	if err := deleteWithMachines(`DELETE FROM dbo.certificate_observations WHERE machine_id IN (%s)`); err != nil {
		return err
	}
	if err := deleteWithMachines(`DELETE FROM dbo.source_states WHERE machine_id IN (%s)`); err != nil {
		return err
	}
	if err := deleteWithMachines(`DELETE FROM dbo.csp_states WHERE machine_id IN (%s)`); err != nil {
		return err
	}
	// Manual scan jobs now create task items as well. Remove only the
	// synthetic machines' scan tasks before their registrations are deleted.
	if err := deleteWithMachines(`
DECLARE @tasks TABLE (task_id UNIQUEIDENTIFIER PRIMARY KEY);
INSERT INTO @tasks SELECT DISTINCT task_id FROM dbo.task_items WHERE kind=N'scan' AND machine_id IN (%[1]s);
DELETE FROM dbo.task_item_events WHERE item_id IN
 (SELECT item_id FROM dbo.task_items WHERE kind=N'scan' AND machine_id IN (%[1]s));
DELETE FROM dbo.task_items WHERE kind=N'scan' AND machine_id IN (%[1]s);
DELETE FROM dbo.tasks WHERE task_id IN (SELECT task_id FROM @tasks)
 AND NOT EXISTS (SELECT 1 FROM dbo.task_items i WHERE i.task_id=dbo.tasks.task_id);`); err != nil {
		return err
	}
	if err := deleteWithMachines(`DELETE FROM dbo.agent_encryption_keys WHERE machine_id IN (%s)`); err != nil {
		return err
	}
	if err := deleteWithMachines(`DELETE FROM dbo.agent_capabilities WHERE registration_id IN
 (SELECT registration_id FROM dbo.registrations WHERE machine_id IN (%s))`); err != nil {
		return err
	}
	if err := deleteWithMachines(`DELETE FROM dbo.jobs WHERE machine_id IN (%s)`); err != nil {
		return err
	}
	if err := deleteWithMachines(`UPDATE dbo.registrations SET previous_registration_id=NULL, replaced_by_registration_id=NULL WHERE machine_id IN (%s)`); err != nil {
		return err
	}
	if err := deleteWithMachines(`DELETE FROM dbo.hostnames WHERE owner_machine_id IN (%s)`); err != nil {
		return err
	}
	if err := deleteWithMachines(`DELETE FROM dbo.reports WHERE machine_id IN (%s)`); err != nil {
		return err
	}
	if err := deleteWithMachines(`DELETE FROM dbo.registrations WHERE machine_id IN (%s)`); err != nil {
		return err
	}
	if err := deleteWithMachines(`DELETE FROM dbo.machine_users WHERE machine_id IN (%s)`); err != nil {
		return err
	}
	if err := deleteWithMachines(`DELETE FROM dbo.machines WHERE machine_id IN (%s)`); err != nil {
		return err
	}
	if len(uuids) > 0 {
		args, placeholders := stringArgs(uuids)
		if _, err := tx.ExecContext(ctx, fmt.Sprintf(`DELETE FROM dbo.request_ids WHERE identity_uuid IN (%s)`, placeholders), args...); err != nil {
			return err
		}
	}
	if _, err := tx.ExecContext(ctx, `
DELETE c FROM dbo.certificates c
WHERE NOT EXISTS (SELECT 1 FROM dbo.certificate_observations o WHERE o.certificate_sha256=c.sha256)
  AND NOT EXISTS (SELECT 1 FROM dbo.machine_user_certificates m WHERE m.certificate_sha256=c.sha256)`); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	// Verify that the synthetic records are gone.
	if len(machines) > 0 {
		args, placeholders := machineArgs(machines)
		var count int
		if err := c.pool.QueryRowContext(ctx, fmt.Sprintf(`SELECT COUNT(1) FROM dbo.machines WHERE machine_id IN (%s)`, placeholders), args...).Scan(&count); err != nil {
			return err
		}
		if count != 0 {
			return fmt.Errorf("synthetic machines remain: %d", count)
		}
	}
	if len(uuids) > 0 {
		args, placeholders := stringArgs(uuids)
		var count int
		if err := c.pool.QueryRowContext(ctx, fmt.Sprintf(`SELECT COUNT(1) FROM dbo.request_ids WHERE identity_uuid IN (%s)`, placeholders), args...).Scan(&count); err != nil {
			return err
		}
		if count != 0 {
			return fmt.Errorf("synthetic request_ids remain: %d", count)
		}
		if err := c.pool.QueryRowContext(ctx, fmt.Sprintf(`SELECT COUNT(1) FROM dbo.agent_install_requests WHERE uuid IN (%s)`, placeholders), args...).Scan(&count); err != nil {
			return err
		}
		if count != 0 {
			return fmt.Errorf("synthetic installation requests remain: %d", count)
		}
	}
	return nil
}

func machineArgs(values []string) ([]any, string) {
	args := make([]any, len(values))
	placeholders := make([]string, len(values))
	for index, value := range values {
		args[index] = value
		placeholders[index] = fmt.Sprintf("@p%d", index+1)
	}
	return args, strings.Join(placeholders, ",")
}

func stringArgs(values []string) ([]any, string) {
	args := make([]any, len(values))
	placeholders := make([]string, len(values))
	for index, value := range values {
		args[index] = value
		placeholders[index] = fmt.Sprintf("@p%d", index+1)
	}
	return args, strings.Join(placeholders, ",")
}

func uniqueStrings(values []string) []string {
	seen := make(map[string]bool)
	out := make([]string, 0, len(values))
	for _, value := range values {
		key := strings.ToLower(value)
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, value)
	}
	return out
}
