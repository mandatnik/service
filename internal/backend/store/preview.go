package store

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sort"
	"strconv"
	"strings"
	"time"

	mssql "github.com/microsoft/go-mssqldb"
	"mandatnik/internal/activation"
	"mandatnik/internal/protocol"
)

type ActivationPreviewInput struct {
	PoolID     string   `json:"pool_id"`
	MachineIDs []string `json:"machine_ids"`
	GroupIDs   []string `json:"group_ids"`
}

type ActivationPreviewResponse struct {
	PreviewID     string             `json:"preview_id"`
	ExpiresAt     time.Time          `json:"expires_at"`
	Pool          LicensePool        `json:"pool"`
	Preview       activation.Preview `json:"preview"`
	RequiredKeys  int                `json:"required_keys"`
	AvailableKeys int                `json:"available_keys"`
	Counts        LicenseCounts      `json:"counts"`
	Warnings      []string           `json:"warnings,omitempty"`
}

// ResolveMachineSelection expands explicit machines and group members into a
// stable de-duplicated list. Unknown IDs are rejected rather than silently
// dropped.
func (s *Store) ResolveMachineSelection(ctx context.Context, machineIDs, groupIDs []string) ([]string, *protocol.APIError) {
	for _, id := range machineIDs {
		if _, err := protocol.NormalizeUUID(id); err != nil {
			return nil, &protocol.APIError{Code: protocol.CodeMachineNotEligible, Message: "invalid machine_id"}
		}
	}
	for _, id := range groupIDs {
		if _, err := protocol.NormalizeUUID(id); err != nil {
			return nil, &protocol.APIError{Code: protocol.CodeMachineNotEligible, Message: "invalid group_id"}
		}
	}
	seen := map[string]bool{}
	var result []string
	add := func(id string) {
		id = strings.ToLower(id)
		if id == "" || seen[id] {
			return
		}
		seen[id] = true
		result = append(result, id)
	}
	if len(machineIDs) > 0 {
		rows, err := s.DB.QueryContext(ctx, `
SELECT m.machine_id FROM dbo.machines m
WHERE m.machine_id IN (SELECT CONVERT(UNIQUEIDENTIFIER,value) FROM OPENJSON(@p1))
  AND m.archived_at IS NULL
  AND EXISTS (SELECT 1 FROM dbo.registrations r WHERE r.machine_id=m.machine_id AND r.state=N'active')`, jsonString(machineIDs))
		if err != nil {
			return nil, &protocol.APIError{Code: protocol.CodeDatabase, Message: "load selected machines"}
		}
		found := map[string]bool{}
		for rows.Next() {
			var id mssql.UniqueIdentifier
			if err := rows.Scan(&id); err != nil {
				rows.Close()
				return nil, &protocol.APIError{Code: protocol.CodeDatabase, Message: "decode selected machine"}
			}
			found[uuidString(id)] = true
		}
		rows.Close()
		for _, id := range machineIDs {
			normalized := strings.ToLower(id)
			if !found[normalized] {
				return nil, &protocol.APIError{Code: protocol.CodeMachineNotEligible, Message: "one or more selected machines do not exist or are archived"}
			}
			add(normalized)
		}
	}
	if len(groupIDs) > 0 {
		var count int
		if err := s.DB.QueryRowContext(ctx, `
SELECT COUNT(1) FROM dbo.machine_groups WHERE group_id IN (SELECT CONVERT(UNIQUEIDENTIFIER,value) FROM OPENJSON(@p1))`,
			jsonString(groupIDs)).Scan(&count); err != nil {
			return nil, &protocol.APIError{Code: protocol.CodeDatabase, Message: "load selected groups"}
		}
		if count != len(uniqueStrings(groupIDs)) {
			return nil, &protocol.APIError{Code: protocol.CodeNotFound, Message: "one or more selected groups do not exist"}
		}
		rows, err := s.DB.QueryContext(ctx, `
SELECT gm.machine_id FROM dbo.machine_group_members gm
JOIN dbo.machines m ON m.machine_id=gm.machine_id AND m.archived_at IS NULL
JOIN dbo.registrations r ON r.machine_id=gm.machine_id AND r.state=N'active'
WHERE gm.group_id IN (SELECT CONVERT(UNIQUEIDENTIFIER,value) FROM OPENJSON(@p1))
ORDER BY gm.machine_id`, jsonString(groupIDs))
		if err != nil {
			return nil, &protocol.APIError{Code: protocol.CodeDatabase, Message: "load group members"}
		}
		for rows.Next() {
			var id mssql.UniqueIdentifier
			if err := rows.Scan(&id); err != nil {
				rows.Close()
				return nil, &protocol.APIError{Code: protocol.CodeDatabase, Message: "decode group member"}
			}
			add(uuidString(id))
		}
		rows.Close()
	}
	if len(result) == 0 {
		return nil, &protocol.APIError{Code: protocol.CodeMachineNotEligible, Message: "selection is empty"}
	}
	if len(result) > 5000 {
		return nil, &protocol.APIError{Code: protocol.CodeMachineNotEligible, Message: "too many selected machines"}
	}
	return result, nil
}

func jsonString(values []string) string {
	raw, _ := json.Marshal(values)
	return string(raw)
}

func uniqueStrings(values []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, value := range values {
		value = strings.ToLower(value)
		if !seen[value] {
			seen[value] = true
			out = append(out, value)
		}
	}
	sort.Strings(out)
	return out
}

func (s *Store) BuildActivationPreview(ctx context.Context, input ActivationPreviewInput, admin string) (*ActivationPreviewResponse, *protocol.APIError) {
	poolID, err := protocol.NormalizeUUID(input.PoolID)
	if err != nil {
		return nil, &protocol.APIError{Code: protocol.CodeNotFound, Message: "invalid pool_id"}
	}
	pool, apiErr := s.GetPool(ctx, poolID)
	if apiErr != nil {
		return nil, apiErr
	}
	if pool.ArchivedAt != nil {
		return nil, &protocol.APIError{Code: protocol.CodeConflict, Message: "pool is archived"}
	}
	machines, apiErr := s.ResolveMachineSelection(ctx, input.MachineIDs, input.GroupIDs)
	if apiErr != nil {
		return nil, apiErr
	}
	cfg, _, cfgErr := s.Config(ctx)
	if cfgErr != nil {
		return nil, &protocol.APIError{Code: protocol.CodeDatabase, Message: "load configuration"}
	}
	freshness := cfg.WithScheduleDefaults().InventoryFreshnessSeconds
	if freshness < protocol.MinScheduleSeconds {
		freshness = protocol.DefaultInventoryFreshnessSeconds
	}
	spec := activation.PoolSpec{ID: pool.ID, Name: pool.Name, CSPMajorVersion: pool.CSPMajorVersion, LicenseKind: pool.LicenseKind, Term: pool.Term}
	facts, apiErr := s.loadMachineFacts(ctx, machines, spec, time.Duration(freshness)*time.Second, s.now())
	if apiErr != nil {
		return nil, apiErr
	}
	preview := activation.BuildPreview(facts, spec)
	previewID := protocol.NewUUID()
	expires := s.now().Add(time.Duration(protocol.TaskPreviewTTLSeconds) * time.Second)
	digest := activationPreviewDigest(pool.ID, machines)
	snapshot := previewSnapshot{
		Pool: spec, Machines: preview.Machines, Digest: digest, CreatedAt: s.now(),
	}
	raw, err := json.Marshal(snapshot)
	if err != nil {
		return nil, &protocol.APIError{Code: protocol.CodeInternal, Message: "encode preview"}
	}
	_, err = s.DB.ExecContext(ctx, `
INSERT INTO dbo.previews(preview_id,pool_id,created_by,created_at,expires_at,request_digest,snapshot_json)
VALUES(@p1,@p2,@p3,@p4,@p5,@p6,@p7)`,
		previewID, pool.ID, admin, s.now(), expires, digest, string(raw))
	if err != nil {
		return nil, &protocol.APIError{Code: protocol.CodeDatabase, Message: "store preview"}
	}
	return &ActivationPreviewResponse{
		PreviewID: previewID, ExpiresAt: expires, Pool: *pool, Preview: preview,
		RequiredKeys: preview.RequiredKeys, AvailableKeys: pool.Counts.Available, Counts: pool.Counts,
	}, nil
}

type previewSnapshot struct {
	Pool      activation.PoolSpec         `json:"pool"`
	Machines  []activation.Classification `json:"machines"`
	Digest    string                      `json:"request_digest"`
	CreatedAt time.Time                   `json:"created_at"`
}

type previewRow struct {
	ID         string
	PoolID     string
	ExpiresAt  time.Time
	Digest     string
	Snapshot   previewSnapshot
	ConsumedAt *time.Time
}

func (s *Store) loadPreviewTx(ctx context.Context, tx *sql.Tx, previewID string) (*previewRow, *protocol.APIError) {
	id, err := protocol.NormalizeUUID(previewID)
	if err != nil {
		return nil, &protocol.APIError{Code: protocol.CodePreviewInvalid, Message: "invalid preview_id"}
	}
	var row previewRow
	var previewIDValue, poolIDValue mssql.UniqueIdentifier
	var raw string
	var consumed sql.NullTime
	err = tx.QueryRowContext(ctx, `
SELECT preview_id,pool_id,expires_at,request_digest,snapshot_json,consumed_at
FROM dbo.previews WITH (UPDLOCK,HOLDLOCK) WHERE preview_id=@p1`, id).
		Scan(&previewIDValue, &poolIDValue, &row.ExpiresAt, &row.Digest, &raw, &consumed)
	row.ID = uuidString(previewIDValue)
	row.PoolID = uuidString(poolIDValue)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, &protocol.APIError{Code: protocol.CodePreviewInvalid, Message: "preview not found"}
	}
	if err != nil {
		return nil, &protocol.APIError{Code: protocol.CodeDatabase, Message: "load preview"}
	}
	if consumed.Valid {
		return nil, &protocol.APIError{Code: protocol.CodePreviewStale, Message: "preview was already used"}
	}
	if consumed.Valid {
		value := consumed.Time.UTC()
		row.ConsumedAt = &value
	}
	if err := json.Unmarshal([]byte(raw), &row.Snapshot); err != nil {
		return nil, &protocol.APIError{Code: protocol.CodePreviewInvalid, Message: "preview snapshot is invalid"}
	}
	if row.ConsumedAt != nil {
		return nil, &protocol.APIError{Code: protocol.CodePreviewStale, Message: "preview was already used"}
	}
	return &row, nil
}

func activationPreviewDigest(poolID string, machineIDs []string) string {
	ids := append([]string(nil), machineIDs...)
	sort.Strings(ids)
	raw, _ := json.Marshal(struct {
		Pool     string   `json:"pool_id"`
		Machines []string `json:"machine_ids"`
	}{poolID, ids})
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

func (s *Store) loadMachineFacts(ctx context.Context, machineIDs []string, pool activation.PoolSpec, freshness time.Duration, now time.Time) ([]activation.MachineFacts, *protocol.APIError) {
	freshCutoff := now.Add(-freshness)
	var facts []activation.MachineFacts
	for _, machineID := range machineIDs {
		var machine activation.MachineFacts
		var displayName, hostname, osVersion sql.NullString
		var registrationID sql.NullInt64
		var lastSeen sql.NullTime
		var agentVersion sql.NullString
		var capable bool
		err := s.DB.QueryRowContext(ctx, `
SELECT m.display_name, COALESCE(r.hostname,''), r.registration_id, r.last_seen_at, COALESCE(r.agent_version,''), COALESCE(r.os_version,''),
       CASE WHEN EXISTS(SELECT 1 FROM dbo.agent_capabilities c WHERE c.registration_id=r.registration_id AND c.tasks_v1=1 AND c.install_v1=1) THEN 1 ELSE 0 END
FROM dbo.machines m
LEFT JOIN dbo.registrations r ON r.registration_id = (
  SELECT TOP 1 registration_id FROM dbo.registrations WHERE machine_id=m.machine_id AND state=N'active' ORDER BY created_at DESC)
WHERE m.machine_id=@p1`, machineID).Scan(&displayName, &hostname, &registrationID, &lastSeen, &agentVersion, &osVersion, &capable)
		if errors.Is(err, sql.ErrNoRows) {
			return nil, &protocol.APIError{Code: protocol.CodeNotFound, Message: "machine not found"}
		}
		if err != nil {
			return nil, &protocol.APIError{Code: protocol.CodeDatabase, Message: "load machine facts"}
		}
		machine.MachineID = machineID
		machine.DisplayName = displayName.String
		machine.Hostname = hostname.String
		if registrationID.Valid {
			machine.RegistrationID = registrationID.Int64
		}
		machine.AgentCapable = capable && registrationID.Valid
		machine.AgentVersion = agentVersion.String
		if lastSeen.Valid {
			value := lastSeen.Time.UTC()
			machine.LastSeenAt = &value
		}
		if err := s.loadCSPFacts(ctx, machineID, freshCutoff, &machine); err != nil {
			return nil, err
		}
		if err := s.loadPersonalFacts(ctx, machineID, freshCutoff, &machine); err != nil {
			return nil, err
		}
		if err := s.loadCertificateFacts(ctx, machineID, freshCutoff, now, &machine); err != nil {
			return nil, err
		}
		if machine.CSPEnvironment == "" {
			if strings.Contains(strings.ToLower(osVersion.String), "server") {
				machine.CSPEnvironment = "server"
			} else if osVersion.String != "" {
				machine.CSPEnvironment = "workstation"
			}
		}
		facts = append(facts, machine)
	}
	return facts, nil
}

func (s *Store) loadCSPFacts(ctx context.Context, machineID string, freshCutoff time.Time, machine *activation.MachineFacts) *protocol.APIError {
	var scanned, complete, present bool
	var product, core, environment, kind, state, trial, term, validRaw sql.NullString
	var validUTC, collected sql.NullTime
	var productsJSON sql.NullString
	err := s.DB.QueryRowContext(ctx, `
SELECT scanned,complete,present,product_version,core_version,environment,license_kind,license_state,is_trial,term_kind,valid_to_raw,valid_to_utc,collected_at,products_json
FROM dbo.csp_states WHERE machine_id=@p1`, machineID).Scan(
		&scanned, &complete, &present, &product, &core, &environment, &kind, &state, &trial, &term, &validRaw, &validUTC, &collected, &productsJSON)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return &protocol.APIError{Code: protocol.CodeDatabase, Message: "load CSP facts"}
	}
	machine.CSPComplete = complete
	machine.CSPPresent = present
	machine.ProductVersion = product.String
	machine.CoreVersion = core.String
	machine.LicenseKind = kind.String
	machine.LicenseState = state.String
	machine.LicenseTermKind = term.String
	machine.IsTrial = trial.String
	machine.ValidToRaw = validRaw.String
	if validUTC.Valid {
		machine.ValidToUTC = validUTC.Time.UTC().Format(time.RFC3339Nano)
	}
	if collected.Valid {
		value := collected.Time.UTC()
		machine.CollectedAt = &value
		machine.CSPFresh = scanned && value.After(freshCutoff)
	}
	machine.CSPMajor = parseMajor(product.String)
	if machine.CSPMajor == 0 && productsJSON.String != "" {
		var products []protocol.CSPProduct
		if json.Unmarshal([]byte(productsJSON.String), &products) == nil && len(products) > 0 {
			machine.CSPMajor = parseMajor(products[0].Branch)
			if machine.ProductVersion == "" {
				machine.ProductVersion = products[0].DisplayVersion
			}
		}
	}
	machine.CSPEnvironment = environment.String
	return nil
}

func parseMajor(value string) int {
	value = strings.TrimSpace(value)
	if dot := strings.IndexByte(value, '.'); dot >= 0 {
		value = value[:dot]
	}
	major, err := strconv.Atoi(value)
	if err != nil || major < 1 || major > 99 {
		return 0
	}
	return major
}

func (s *Store) loadPersonalFacts(ctx context.Context, machineID string, freshCutoff time.Time, machine *activation.MachineFacts) *protocol.APIError {
	var payload string
	var profilesComplete sql.NullBool
	var personalComplete sql.NullBool
	var collected time.Time
	err := s.DB.QueryRowContext(ctx, `
SELECT TOP 1 payload_json,profiles_complete,personal_complete,collected_at
FROM dbo.reports WHERE machine_id=@p1 ORDER BY scan_epoch DESC,scan_seq DESC,received_at DESC`, machineID).
		Scan(&payload, &profilesComplete, &personalComplete, &collected)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return &protocol.APIError{Code: protocol.CodeDatabase, Message: "load personal inventory facts"}
	}
	personal := personalComplete.Valid && personalComplete.Bool
	profiles := profilesComplete.Valid && profilesComplete.Bool
	if !personalComplete.Valid || !profilesComplete.Valid {
		var report struct {
			ProfilesComplete bool `json:"profiles_complete"`
			Sources          []struct {
				SourceType string `json:"source_type"`
				Complete   bool   `json:"complete"`
			} `json:"sources"`
		}
		if json.Unmarshal([]byte(payload), &report) == nil {
			profiles = report.ProfilesComplete
			personal = true
			seenPersonal := false
			for _, source := range report.Sources {
				if source.SourceType == "user_store" {
					seenPersonal = true
					if !source.Complete {
						personal = false
					}
				}
			}
			if !seenPersonal && !report.ProfilesComplete {
				personal = false
			}
		}
	}
	machine.ProfilesComplete = profiles
	machine.PersonalComplete = personal
	machine.PersonalFresh = collected.After(freshCutoff)
	if machine.PersonalFresh && machine.PersonalComplete && machine.ProfilesComplete {
		var count int
		_ = s.DB.QueryRowContext(ctx, `SELECT COUNT(1) FROM dbo.source_states WHERE machine_id=@p1 AND source_type=N'user_store'`, machineID).Scan(&count)
		machine.NoPersonalSources = count == 0
	}
	return nil
}

func (s *Store) loadCertificateFacts(ctx context.Context, machineID string, freshCutoff, now time.Time, machine *activation.MachineFacts) *protocol.APIError {
	var suitable, uncertain int
	err := s.DB.QueryRowContext(ctx, `
SELECT
  ISNULL(SUM(CASE WHEN s.suitable=1 THEN 1 ELSE 0 END),0),
  ISNULL(SUM(CASE WHEN s.uncertain=1 THEN 1 ELSE 0 END),0)
FROM (
  SELECT o.observation_id,
    CASE WHEN c.not_before IS NOT NULL AND c.not_after IS NOT NULL
              AND c.not_before<=@p2 AND c.not_after>=@p2
              AND ISNULL(c.embedded_license,N'')<>N'present'
              AND EXISTS (SELECT 1 FROM dbo.certificate_observation_bindings b
                          WHERE b.observation_id=o.observation_id AND b.binding_state=N'present'
                            AND b.provider_owner=N'cryptopro')
         THEN 1 ELSE 0 END AS suitable,
    CASE WHEN c.not_before IS NOT NULL AND c.not_after IS NOT NULL
              AND c.not_before<=@p2 AND c.not_after>=@p2
              AND ISNULL(c.embedded_license,N'')<>N'present'
              AND NOT EXISTS (SELECT 1 FROM dbo.certificate_observation_bindings b
                          WHERE b.observation_id=o.observation_id AND b.binding_state=N'present'
                            AND b.provider_owner IN (N'cryptopro',N'other'))
         THEN 1 ELSE 0 END AS uncertain
  FROM dbo.certificate_observations o
  JOIN dbo.certificates c ON c.sha256=o.certificate_sha256
  WHERE o.machine_id=@p1 AND o.active=1 AND o.source_type=N'user_store' AND o.last_seen_at>=@p3
) s`, machineID, now, freshCutoff).Scan(&suitable, &uncertain)
	if err != nil {
		return &protocol.APIError{Code: protocol.CodeDatabase, Message: "load certificate suitability"}
	}
	machine.SuitableCertificate = suitable > 0
	machine.UnknownCertificate = suitable == 0 && uncertain > 0
	return nil
}

func (s *Store) previewMachine(classification []activation.Classification, machineID string) (activation.Classification, bool) {
	for _, item := range classification {
		if item.MachineID == machineID {
			return item, true
		}
	}
	return activation.Classification{}, false
}

// sameProtectionBasis compares only the facts that determine whether a write
// is allowed. Presentation-only fields are ignored.
func sameProtectionBasis(a, b activation.Classification) bool {
	return a.Category == b.Category &&
		a.Subtype == b.Subtype &&
		a.Compatible == b.Compatible &&
		a.Selectable == b.Selectable &&
		a.TrialActive == b.TrialActive &&
		a.LicenseState == b.LicenseState &&
		a.IsTrial == b.IsTrial &&
		a.LicenseKind == b.LicenseKind &&
		a.SuitableCertificate == b.SuitableCertificate &&
		a.UnknownCertificate == b.UnknownCertificate &&
		a.CSPMajor == b.CSPMajor &&
		a.Environment == b.Environment
}
