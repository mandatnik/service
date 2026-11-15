// Package activation implements the four-list compatibility and license-need
// classification. It is deliberately pure so the same rules can be tested
// without SQL Server or Windows.
package activation

import (
	"fmt"
	"sort"
	"time"

	"mandatnik/internal/protocol"
)

// MachineFacts is the evidence used for one machine. Every "fresh" or
// "complete" flag describes personal inventory/CSP only; failures in optional
// folders are intentionally not represented here.
type MachineFacts struct {
	MachineID           string
	DisplayName         string
	Hostname            string
	RegistrationID      int64
	AgentCapable        bool
	AgentVersion        string
	LastSeenAt          *time.Time
	CSPFresh            bool
	CSPComplete         bool
	CSPPresent          bool
	CSPMajor            int
	CSPEnvironment      string
	ProductVersion      string
	CoreVersion         string
	LicenseKind         string
	LicenseState        string
	LicenseTermKind     string
	IsTrial             string
	ValidToRaw          string
	ValidToUTC          string
	CollectedAt         *time.Time
	PersonalFresh       bool
	PersonalComplete    bool
	ProfilesComplete    bool
	SuitableCertificate bool
	UnknownCertificate  bool
	NoPersonalSources   bool
}

// PoolSpec is the immutable compatibility part of a pool.
type PoolSpec struct {
	ID              string
	Name            string
	CSPMajorVersion int
	LicenseKind     string
	Term            string
}

type Classification struct {
	MachineID           string `json:"machine_id"`
	DisplayName         string `json:"display_name"`
	Hostname            string `json:"hostname"`
	Category            string `json:"category"`
	Subtype             string `json:"subtype,omitempty"`
	Selectable          bool   `json:"selectable"`
	DefaultSelected     bool   `json:"default_selected"`
	ReasonCode          string `json:"reason_code"`
	ReasonText          string `json:"reason_text"`
	Compatible          bool   `json:"compatible"`
	Incompatible        bool   `json:"incompatible"`
	TrialActive         bool   `json:"trial_active"`
	LicenseKind         string `json:"license_kind,omitempty"`
	LicenseState        string `json:"license_state,omitempty"`
	IsTrial             string `json:"is_trial,omitempty"`
	TermKind            string `json:"term_kind,omitempty"`
	ValidToRaw          string `json:"valid_to_raw,omitempty"`
	ValidToUTC          string `json:"valid_to_utc,omitempty"`
	Environment         string `json:"environment,omitempty"`
	CSPMajor            int    `json:"csp_major_version,omitempty"`
	ProductVersion      string `json:"product_version,omitempty"`
	CoreVersion         string `json:"core_version,omitempty"`
	CollectedAt         string `json:"collected_at,omitempty"`
	SuitableCertificate bool   `json:"suitable_certificate"`
	UnknownCertificate  bool   `json:"unknown_certificate"`
}

type Preview struct {
	Machines          []Classification `json:"machines"`
	Incompatible      []Classification `json:"incompatible"`
	Activation        []Classification `json:"activation"`
	Optional          []Classification `json:"optional"`
	AlreadyActivated  []Classification `json:"already_activated"`
	NeedsCheck        []Classification `json:"needs_check"`
	DefaultSelected   []string         `json:"default_selected"`
	RequiredKeys      int              `json:"required_keys"`
	Compatible        int              `json:"compatible"`
	IncompatibleCount int              `json:"incompatible_count"`
}

var categoryOrder = map[string]int{
	protocol.TaskCategoryActivated:  3,
	protocol.TaskCategoryNeedsCheck: 4,
	protocol.TaskCategoryOptional:   2,
	protocol.TaskCategoryActivation: 1,
}

// Classify applies the agreed decision order. Active purchased licenses win
// over stale certificate data; unknown trialness never becomes permission.
func Classify(facts MachineFacts, pool PoolSpec) Classification {
	result := Classification{
		MachineID: facts.MachineID, DisplayName: facts.DisplayName, Hostname: facts.Hostname,
		Compatible: true, LicenseKind: facts.LicenseKind, LicenseState: facts.LicenseState,
		IsTrial: facts.IsTrial, TermKind: facts.LicenseTermKind, ValidToRaw: facts.ValidToRaw,
		ValidToUTC: facts.ValidToUTC, Environment: facts.CSPEnvironment, CSPMajor: facts.CSPMajor,
		ProductVersion: facts.ProductVersion, CoreVersion: facts.CoreVersion,
		SuitableCertificate: facts.SuitableCertificate, UnknownCertificate: facts.UnknownCertificate,
	}
	if facts.CollectedAt != nil {
		result.CollectedAt = facts.CollectedAt.UTC().Format(time.RFC3339Nano)
	}
	fail := func(category, subtype, code, text string, selectable, selected bool) Classification {
		result.Category, result.Subtype = category, subtype
		result.ReasonCode, result.ReasonText = code, text
		result.Selectable, result.DefaultSelected = selectable, selected
		result.TrialActive = facts.LicenseState == "active" && facts.IsTrial == "true"
		return result
	}
	incompatible := func(code, text string) Classification {
		result.Compatible = false
		result.Incompatible = true
		result.Selectable, result.DefaultSelected = false, false
		result.ReasonCode, result.ReasonText = code, text
		result.Category = "incompatible"
		return result
	}
	needsCheck := func(code, text string) Classification {
		return fail(protocol.TaskCategoryNeedsCheck, "", code, text, false, false)
	}

	if !facts.AgentCapable {
		return incompatible("agent_update_required", "Агент не поддерживает задания установки; требуется обновление агента.")
	}
	if !facts.CSPFresh {
		return needsCheck("inventory_stale", "Нет свежих сведений о CSP; требуется повторный сбор.")
	}
	if !facts.CSPComplete {
		return needsCheck("csp_incomplete", "Сбор CSP неполный; состояние лицензии нельзя считать достоверным.")
	}
	if !facts.CSPPresent {
		return incompatible("csp_not_installed", "КриптоПро CSP не установлен; лицензия не расходуется.")
	}
	if facts.CSPMajor != 4 && facts.CSPMajor != 5 {
		return needsCheck("csp_version_unknown", "Версия КриптоПро CSP не определена.")
	}
	if facts.CSPMajor != pool.CSPMajorVersion {
		return incompatible("csp_major_mismatch", fmt.Sprintf("Нужен пул для CSP %d, на машине CSP %d.", pool.CSPMajorVersion, facts.CSPMajor))
	}
	switch facts.CSPEnvironment {
	case "workstation", "server":
	case "":
		return needsCheck("environment_unknown", "Тип окружения Windows не определён.")
	default:
		return needsCheck("environment_unknown", "Тип окружения Windows не определён.")
	}
	if pool.LicenseKind == protocol.PoolKindServer && facts.CSPEnvironment != "server" {
		return incompatible("server_pool_requires_server", "Серверный пул нельзя назначать рабочей станции.")
	}
	if pool.LicenseKind == protocol.PoolKindClient && facts.CSPEnvironment != "workstation" {
		return incompatible("client_pool_requires_workstation", "Клиентский пул нельзя назначать Windows Server.")
	}

	// A fresh confirmed purchased license is protected regardless of
	// certificate metadata. It is list 3 and its ID must be absent from POST.
	if facts.LicenseState == "active" && facts.IsTrial == "false" {
		if facts.LicenseKind != "client" && facts.LicenseKind != "server" {
			return needsCheck("license_kind_unknown", "Действует лицензия неизвестного типа; нужна проверка.")
		}
		return fail(protocol.TaskCategoryActivated, "", "already_licensed", "Действует приобретённая лицензия; замена запрещена.", false, false)
	}
	if facts.LicenseState == "active" && (facts.IsTrial == "" || facts.IsTrial == "unknown") {
		return needsCheck("license_mode_unknown", "Лицензия действует, но пробность не подтверждена; замена запрещена.")
	}
	if facts.LicenseState == "active" && facts.IsTrial == "true" && (facts.LicenseKind != "client" && facts.LicenseKind != "server") {
		return needsCheck("license_kind_unknown", "Действует пробная лицензия неизвестного типа.")
	}
	if facts.LicenseState == "unknown" || facts.LicenseState == "error" || facts.LicenseState == "" {
		return needsCheck("license_state_unknown", "Состояние лицензии CSP не определено; запись запрещена.")
	}
	if !facts.PersonalFresh || !facts.PersonalComplete || !facts.ProfilesComplete {
		return needsCheck("personal_inventory_incomplete", "Личные хранилища собраны неполно или устарели; назначение небезопасно.")
	}
	if facts.SuitableCertificate {
		if facts.LicenseState == "active" && facts.IsTrial == "true" {
			return fail(protocol.TaskCategoryActivation, protocol.TaskCategoryActivationTrial,
				"trial_active", "Действует пробная лицензия; включите вручную для подтверждённой замены.", true, false)
		}
		return fail(protocol.TaskCategoryActivation, protocol.TaskCategoryActivationNoLicense,
			"license_required", "Нет действующей лицензии, есть подходящий личный сертификат.", true, true)
	}
	if facts.UnknownCertificate {
		return needsCheck("certificate_provider_unknown", "У сертификата нет подтверждённой привязки к провайдеру КриптоПро; нужна диагностика.")
	}
	// No suitable certificate and no uncertainty. A trial still does not make
	// activation necessary; it is an optional admin choice.
	return fail(protocol.TaskCategoryOptional, "", "no_suitable_certificate",
		"Нет подходящего личного сертификата; активация не требуется.", true, false)
}

// BuildPreview classifies all machines, preserving input order, and computes
// the four visual lists. Duplicate machine IDs are collapsed by the caller.
func BuildPreview(facts []MachineFacts, pool PoolSpec) Preview {
	preview := Preview{
		Activation: []Classification{}, Optional: []Classification{}, AlreadyActivated: []Classification{},
		NeedsCheck: []Classification{}, Incompatible: []Classification{}, DefaultSelected: []string{},
	}
	for _, machine := range facts {
		classification := Classify(machine, pool)
		preview.Machines = append(preview.Machines, classification)
		if classification.Incompatible {
			preview.Incompatible = append(preview.Incompatible, classification)
			continue
		}
		preview.Compatible++
		switch classification.Category {
		case protocol.TaskCategoryActivation:
			preview.Activation = append(preview.Activation, classification)
		case protocol.TaskCategoryOptional:
			preview.Optional = append(preview.Optional, classification)
		case protocol.TaskCategoryActivated:
			preview.AlreadyActivated = append(preview.AlreadyActivated, classification)
		case protocol.TaskCategoryNeedsCheck:
			preview.NeedsCheck = append(preview.NeedsCheck, classification)
		}
		if classification.DefaultSelected {
			preview.DefaultSelected = append(preview.DefaultSelected, classification.MachineID)
			preview.RequiredKeys++
		}
	}
	sort.SliceStable(preview.DefaultSelected, func(i, j int) bool { return preview.DefaultSelected[i] < preview.DefaultSelected[j] })
	preview.IncompatibleCount = len(preview.Incompatible)
	return preview
}

// SelectionAllowed returns whether an explicit admin selection of this machine
// is legal. List 3 (already licensed) and list 4 (needs check) are never legal.
func SelectionAllowed(classification Classification) bool {
	if classification.Incompatible || !classification.Selectable {
		return false
	}
	return classification.Category == protocol.TaskCategoryActivation || classification.Category == protocol.TaskCategoryOptional
}

// AllowTrialReplacement is true only when the classification proves a current
// trial AND the machine was explicitly selected. The caller stores the flag in
// the encrypted item parameters.
func AllowTrialReplacement(classification Classification) bool {
	return classification.TrialActive && SelectionAllowed(classification)
}
