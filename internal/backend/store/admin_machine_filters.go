package store

import (
	"fmt"
	"net"
	"strings"

	"mandatnik/internal/protocol"
)

func ValidateAdminMachineFilter(f AdminMachineFilter) error {
	allowed := func(value string, choices ...string) bool {
		if value == "" {
			return true
		}
		for _, v := range choices {
			if value == v {
				return true
			}
		}
		return false
	}
	if !allowed(f.Status, "active", "offline", "conflict", "archived") ||
		!allowed(f.Connection, "online", "offline") || !allowed(f.CSP, "present", "missing") ||
		!allowed(f.License, "active", "needs", "trial", "expired", "unknown", "perpetual") ||
		!allowed(f.Certificate, "present", "missing", "expired_recent") ||
		!allowed(f.MachineStatus, MachineStatusOK, MachineStatusTrial, MachineStatusCSPMissing, MachineStatusLicenseRequired) {
		return fmt.Errorf("unsupported machine column filter")
	}
	if f.Monitor != "" {
		if _, ok := machineMonitorSQL(f.Monitor); !ok {
			return fmt.Errorf("unsupported monitoring filter")
		}
	}
	if f.GroupID != "" {
		if _, err := protocol.NormalizeUUID(f.GroupID); err != nil {
			return fmt.Errorf("invalid group identifier")
		}
	}
	if f.SourceIP != "" && net.ParseIP(strings.TrimSpace(f.SourceIP)) == nil {
		return fmt.Errorf("invalid source IP address")
	}
	for _, v := range []string{f.Query, f.Name, f.Hostname} {
		if len(v) > 512 {
			return fmt.Errorf("machine search is too long")
		}
	}
	return nil
}

func applyAdminMachineColumns(f AdminMachineFilter, where *[]string, add func(string, ...any)) error {
	if err := ValidateAdminMachineFilter(f); err != nil {
		return err
	}
	appendSQL := func(s string) { *where = append(*where, s) }
	if f.Monitor != "" {
		pred, _ := machineMonitorSQL(f.Monitor)
		appendSQL(currentMonitoringMachineSQL)
		appendSQL("(" + pred + ")")
	}
	if f.Connection != "" {
		pred, _ := machineMonitorSQL(f.Connection)
		appendSQL("r.state='active'")
		appendSQL("(" + pred + ")")
	}
	switch f.CSP {
	case "present":
		appendSQL("c.present=1")
	case "missing":
		appendSQL("COALESCE(c.present,0)=0")
	}
	switch f.License {
	case "active":
		appendSQL(activeLicenseSQL)
	case "needs":
		appendSQL("(" + needsLicenseSQL + ")")
	case "trial":
		appendSQL("c.present=1 AND (" + trialMachineSQL + ")")
	case "expired":
		appendSQL("c.present=1 AND c.license_state=N'expired'")
	case "unknown":
		appendSQL("c.present=1 AND COALESCE(c.license_state,N'unknown') NOT IN (N'active',N'expired',N'not_yet_valid')")
	case "perpetual":
		appendSQL(activeLicenseSQL + " AND c.term_kind IN (N'perpetual',N'unlimited')")
	}
	if f.GroupID != "" {
		add("EXISTS (SELECT 1 FROM dbo.machine_group_members gm WHERE gm.machine_id=m.machine_id AND gm.group_id=@p%d)", f.GroupID)
	}
	switch f.Certificate {
	case "present":
		appendSQL("EXISTS (SELECT 1 FROM dbo.certificate_observations colcert WHERE colcert.machine_id=m.machine_id AND colcert.active=1)")
	case "missing":
		appendSQL("NOT EXISTS (SELECT 1 FROM dbo.certificate_observations colcert WHERE colcert.machine_id=m.machine_id AND colcert.active=1)")
	case "expired_recent":
		appendSQL("(" + expiredMachineSQL + ")")
	}
	if f.MachineStatus != "" {
		add("("+machineStatusSQL+")=@p%d", f.MachineStatus)
	}
	if value := strings.TrimSpace(f.Name); value != "" {
		add("m.display_name LIKE @p%d", "%"+value+"%")
	}
	if value := strings.TrimSpace(f.Hostname); value != "" {
		add("r.hostname LIKE @p%d", "%"+value+"%")
	}
	if f.SourceIP != "" {
		add("r.last_source_ip=@p%d", ipBytes(net.ParseIP(strings.TrimSpace(f.SourceIP))))
	}
	return nil
}
