package store

import (
	"context"
	"database/sql"
	"fmt"
	"time"
)

// The filtered UQ_registrations_one_active index guarantees one current
// registration per logical machine; historical registrations do not join.
const adminMachineLiveJoins = `
FROM dbo.machines m
LEFT JOIN dbo.registrations r ON r.machine_id=m.machine_id AND r.state='active'
LEFT JOIN dbo.csp_states c ON c.machine_id=m.machine_id
`
const currentMonitoringMachineSQL = `m.archived_at IS NULL AND r.state='active'`
const trialMachineSQL = `LOWER(COALESCE(c.is_trial,N'')) IN (N'yes',N'true')`
const uncoveredCertificatesSQL = `EXISTS (
 SELECT 1 FROM dbo.certificate_observations coverage
 JOIN dbo.certificates coverage_cert ON coverage_cert.sha256=coverage.certificate_sha256
 WHERE coverage.machine_id=m.machine_id AND coverage.active=1
 AND coverage.source_type=N'user_store' AND COALESCE(coverage_cert.embedded_license,N'')<>N'present')`
const activeLicenseSQL = `c.present=1 AND c.license_state=N'active'`
const needsLicenseSQL = `c.present=1 AND (` + uncoveredCertificatesSQL + `) AND
 (COALESCE(c.license_state,N'')<>N'active' OR (` + trialMachineSQL + `))`

// Renewal is compared globally by known owner INN, independent of where the
// replacement was found. Missing INN cannot prove that an owner lacks renewal.
const expiredWithoutRenewalSQL = `ce.not_after >= DATEADD(month,-1,@asof) AND ce.not_after < @asof
 AND NULLIF(LTRIM(RTRIM(ce.inn)),N'') IS NOT NULL
 AND NOT EXISTS (SELECT 1 FROM dbo.certificates replacement
 WHERE replacement.inn=ce.inn AND replacement.not_before<=@asof AND replacement.not_after>=@asof)`
const expiredMachineSQL = `EXISTS (SELECT 1 FROM dbo.certificate_observations expired_obs
 JOIN dbo.certificates ce ON ce.sha256=expired_obs.certificate_sha256
 WHERE expired_obs.machine_id=m.machine_id AND expired_obs.active=1 AND (` + expiredWithoutRenewalSQL + `))`
const machineStatusSQL = `CASE WHEN COALESCE(c.present,0)=0 THEN N'csp_missing'
 WHEN (` + needsLicenseSQL + `) THEN CASE WHEN c.license_state=N'active' AND (` + trialMachineSQL + `) THEN N'trial' ELSE N'license_required' END
 ELSE N'ok' END`

// Both dashboard counters and drill-down filters use these exact predicates.
func machineMonitorSQL(key string) (string, bool) {
	switch key {
	case "online":
		return fmt.Sprintf("r.last_seen_at > DATEADD(minute,-%d,@asof)", machineOfflineMinutes), true
	case "offline":
		return fmt.Sprintf("(r.last_seen_at IS NULL OR r.last_seen_at <= DATEADD(minute,-%d,@asof))", machineOfflineMinutes), true
	case "active_license":
		return activeLicenseSQL, true
	case "needs_license":
		return needsLicenseSQL, true
	case "csp_missing":
		return "COALESCE(c.present,0)=0", true
	case "expired_certificates":
		return expiredMachineSQL, true
	}
	return "", false
}

type AdminMonitoring struct {
	AsOf                       time.Time `json:"as_of"`
	OnlineMachines             int       `json:"online_machines"`
	ActiveLicenseMachines      int       `json:"active_license_machines"`
	ActiveLicenseTrialMachines int       `json:"active_license_trial_machines"`
	NeedsLicenseMachines       int       `json:"needs_license_machines"`
	NeedsLicenseTrialMachines  int       `json:"needs_license_trial_machines"`
	MissingCSPMachines         int       `json:"missing_csp_machines"`
	ExpiredCertificates        int       `json:"expired_certificates"`
	ExpiredCertificateMachines int       `json:"expired_certificate_machines"`
}

func (s *Store) adminMonitoring(ctx context.Context, at time.Time) (AdminMonitoring, error) {
	out := AdminMonitoring{AsOf: at}
	online, _ := machineMonitorSQL("online")
	missing, _ := machineMonitorSQL("csp_missing")
	query := `SELECT
 COALESCE(SUM(CASE WHEN ` + online + ` THEN 1 ELSE 0 END),0),
 COALESCE(SUM(CASE WHEN ` + activeLicenseSQL + ` THEN 1 ELSE 0 END),0),
 COALESCE(SUM(CASE WHEN ` + activeLicenseSQL + ` AND (` + trialMachineSQL + `) THEN 1 ELSE 0 END),0),
 COALESCE(SUM(CASE WHEN eligible.needs_license=1 THEN 1 ELSE 0 END),0),
 COALESCE(SUM(CASE WHEN eligible.needs_license=1 AND (` + trialMachineSQL + `) THEN 1 ELSE 0 END),0),
 COALESCE(SUM(CASE WHEN ` + missing + ` THEN 1 ELSE 0 END),0),
 COALESCE(SUM(CASE WHEN eligible.expired_certificate=1 THEN 1 ELSE 0 END),0)
 ` + adminMachineLiveJoins + `
 CROSS APPLY (SELECT CASE WHEN ` + needsLicenseSQL + ` THEN 1 ELSE 0 END AS needs_license,
 CASE WHEN ` + expiredMachineSQL + ` THEN 1 ELSE 0 END AS expired_certificate) eligible
 WHERE ` + currentMonitoringMachineSQL
	// SQL Server does not allow subqueries directly inside SUM(CASE ...).
	err := s.DB.QueryRowContext(ctx, query, sql.Named("asof", at)).Scan(&out.OnlineMachines, &out.ActiveLicenseMachines, &out.ActiveLicenseTrialMachines, &out.NeedsLicenseMachines, &out.NeedsLicenseTrialMachines, &out.MissingCSPMachines, &out.ExpiredCertificateMachines)
	if err != nil {
		return out, err
	}
	err = s.DB.QueryRowContext(ctx, `SELECT COUNT(DISTINCT ce.sha256)
 FROM dbo.certificates ce JOIN dbo.certificate_observations o ON o.certificate_sha256=ce.sha256 AND o.active=1
 JOIN dbo.machines m ON m.machine_id=o.machine_id AND m.archived_at IS NULL
 WHERE EXISTS (SELECT 1 FROM dbo.registrations r WHERE r.machine_id=m.machine_id AND r.state=N'active')
 AND (`+expiredWithoutRenewalSQL+`)`, sql.Named("asof", at)).Scan(&out.ExpiredCertificates)
	return out, err
}
