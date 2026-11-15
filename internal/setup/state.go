// Package setup implements the interactive installation/configuration wizard
// of the Windows backend («Мандатник»): resumable drafts, certificate
// validation and issuance, SQL Server probing, the service account, the first
// superadministrator, the recovery bundle and the completed-install marker.
//
// The wizard never prints secrets and never accepts them on a command line.
package setup

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"mandatnik/internal/platform"
)

// Draft and marker files live in a protected subdirectory of BackendDir.
const (
	DraftDirName        = "setup"
	MarkerFileName      = "install-state.json"
	DraftFileName       = "draft.json"
	DraftSecretsName    = "draft-secrets.bin"
	SetupSecretsName    = "runtime-secrets.bin"
	PasswordFileName    = "db-password.bin"
	BundleFileName      = "recovery.mndk"
	BundleReadmeName    = "recovery-README.txt"
	BackupDirName       = "config-backups"
	stateVersion        = 1
	draftExpiryDuration = 30 * 24 * time.Hour
)

// Step names in execution order.
const (
	StepIntro       = "intro"
	StepRights      = "rights"
	StepListening   = "listening"
	StepCerts       = "certificates"
	StepDatabase    = "database"
	StepServiceAcct = "service_account"
	StepSuperadmin  = "superadmin"
	StepApply       = "apply"
	StepService     = "service"
	StepBundle      = "bundle"
	StepFinish      = "finish"
)

// StepOrder is the canonical order of wizard steps.
var StepOrder = []string{
	StepIntro, StepRights, StepListening, StepCerts, StepDatabase,
	StepServiceAcct, StepSuperadmin, StepApply, StepService, StepBundle, StepFinish,
}

// Step statuses.
const (
	StatusPending = "pending"
	StatusDone    = "done"
	StatusFailed  = "failed"
)

// StepState records progress of one wizard step.
type StepState struct {
	Status   string `json:"status"`
	Note     string `json:"note,omitempty"`
	At       string `json:"at,omitempty"`
	Attempts int    `json:"attempts,omitempty"`
}

// Interface addresses and TLS assignments.
type Interface struct {
	Role        string   `json:"role"` // agent|admin|integration
	Listen      string   `json:"listen"`
	ClientNames []string `json:"client_names"` // DNS names or IPs used by clients
}

// TLSGroup couples one certificate with one or more interfaces.
type TLSGroup struct {
	ID          string   `json:"id"`
	Interfaces  []string `json:"interfaces"` // role list
	Mode        string   `json:"mode"`       // import|csr|ca
	CertFile    string   `json:"cert_file,omitempty"`
	KeyFile     string   `json:"key_file,omitempty"`
	CSRFile     string   `json:"csr_file,omitempty"`
	CAFile      string   `json:"ca_file,omitempty"`
	CAPrivateID string   `json:"ca_private_id,omitempty"` // id into CA store, not a path
	WaitingCSR  bool     `json:"waiting_csr,omitempty"`
	Validated   bool     `json:"validated"`
}

// ServiceAccount plan.
type ServiceAccount struct {
	Mode           string `json:"mode"` // create|existing
	Account        string `json:"account,omitempty"`
	PasswordSealed bool   `json:"password_sealed,omitempty"`
}

// Superadmin plan.
type Superadmin struct {
	Email          string `json:"email"`
	DisplayName    string `json:"display_name"`
	PasswordSealed bool   `json:"password_sealed,omitempty"`
	Created        bool   `json:"created,omitempty"`
}

// DBPlan mirrors config.DB minus the password (kept in the sealed store).
type DBPlan struct {
	Server            string `json:"server"`
	Port              int    `json:"port"`
	Database          string `json:"database"`
	User              string `json:"user"`
	Encrypt           bool   `json:"encrypt"`
	ServerName        string `json:"server_name,omitempty"`
	CAFile            string `json:"ca_file,omitempty"`
	TrustServerCert   bool   `json:"trust_server_certificate,omitempty"`
	InsecureConfirmed bool   `json:"insecure_confirmed,omitempty"`
	EmptyVerified     bool   `json:"empty_verified,omitempty"`
	Migrated          bool   `json:"migrated,omitempty"`
}

// Draft is the full resumable installation draft. Secrets are never stored
// here; they live in the sealed blob referenced by the draft.
type Draft struct {
	Version           int                  `json:"version"`
	CreatedAt         string               `json:"created_at"`
	UpdatedAt         string               `json:"updated_at"`
	Mode              string               `json:"mode"` // install|adopt
	Steps             map[string]StepState `json:"steps"`
	ModeChoice        string               `json:"mode_choice,omitempty"` // simple|advanced
	Interfaces        []Interface          `json:"interfaces,omitempty"`
	TLSGroups         []TLSGroup           `json:"tls_groups,omitempty"`
	DB                DBPlan               `json:"db"`
	ServiceAcct       ServiceAccount       `json:"service_account"`
	Superadmin        Superadmin           `json:"superadmin"`
	BundlePath        string               `json:"bundle_path,omitempty"`
	BundleCAKey       bool                 `json:"bundle_contains_ca_key,omitempty"`
	LicenseInited     bool                 `json:"license_inited,omitempty"`
	AppliedMigrations []int                `json:"applied_migrations,omitempty"`
	Secrets           map[string]string    `json:"-"` // sealed ids, filled by Save
}

// Marker states.
const (
	MarkerNone      = "none"
	MarkerDraft     = "draft"
	MarkerCompleted = "completed"
)

// Marker is the completed-installation record.
type Marker struct {
	Version     int    `json:"version"`
	Status      string `json:"status"` // draft|completed
	Mode        string `json:"mode"`   // install|adopt
	CompletedAt string `json:"completed_at,omitempty"`
	BackendExe  string `json:"backend_exe,omitempty"`
}

// Paths returns the setup file paths for the given backend directory.
type Paths struct {
	Root          string // Backend\setup
	Marker        string
	Draft         string
	DraftSealed   string
	RuntimeSealed string
	Password      string
	Bundle        string
	BundleReadme  string
	Backups       string
}

// NewPaths builds setup paths from the backend data directory.
func NewPaths(backendDir string) Paths {
	root := filepath.Join(backendDir, DraftDirName)
	return Paths{
		Root:          root,
		Marker:        filepath.Join(root, MarkerFileName),
		Draft:         filepath.Join(root, DraftFileName),
		DraftSealed:   filepath.Join(root, DraftSecretsName),
		RuntimeSealed: filepath.Join(root, SetupSecretsName),
		Password:      filepath.Join(backendDir, PasswordFileName),
		Bundle:        filepath.Join(root, BundleFileName),
		BundleReadme:  filepath.Join(root, BundleReadmeName),
		Backups:       filepath.Join(root, BackupDirName),
	}
}

// DefaultPaths uses the standard ProgramData backend directory.
func DefaultPaths() Paths { return NewPaths(platform.BackendDir()) }

// MarkerStatus classifies the installation state, including explicit legacy
// compatibility: an installation without the marker is not silently blocked.
func MarkerStatus(p Paths) string {
	raw, err := os.ReadFile(p.Marker)
	if err != nil {
		return MarkerNone
	}
	var m Marker
	if err := json.Unmarshal(raw, &m); err != nil {
		return MarkerNone
	}
	if m.Status == MarkerCompleted {
		return MarkerCompleted
	}
	return MarkerDraft
}

// LoadDraft reads the resumable draft. A missing draft is not an error.
func LoadDraft(p Paths) (*Draft, error) {
	raw, err := os.ReadFile(p.Draft)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("читаю черновик настройки: %w", err)
	}
	var d Draft
	if err := json.Unmarshal(raw, &d); err != nil {
		return nil, fmt.Errorf("черновик настройки повреждён (%s): %w", p.Draft, err)
	}
	if d.Version != stateVersion {
		return nil, fmt.Errorf("черновик настройки имеет несовместимую версию %d (ожидается %d)", d.Version, stateVersion)
	}
	if d.Steps == nil {
		d.Steps = map[string]StepState{}
	}
	return &d, nil
}

// Save atomically writes the draft.
func (d *Draft) Save(p Paths) error {
	d.Version = stateVersion
	d.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
	if d.CreatedAt == "" {
		d.CreatedAt = d.UpdatedAt
	}
	if d.Steps == nil {
		d.Steps = map[string]StepState{}
	}
	raw, err := json.MarshalIndent(d, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(p.Root, 0o700); err != nil {
		return fmt.Errorf("создаю каталог черновика: %w", err)
	}
	tmp := p.Draft + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return fmt.Errorf("пишу черновик: %w", err)
	}
	if err := secureFile(tmp); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("защищаю черновик: %w", err)
	}
	if err := os.Rename(tmp, p.Draft); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("сохраняю черновик: %w", err)
	}
	return secureFile(p.Draft)
}

// Delete removes draft and sealed draft secrets, keeping the marker intact.
func DeleteDraft(p Paths) error {
	errs := []error{}
	for _, path := range []string{p.Draft, p.DraftSealed, p.Draft + ".tmp"} {
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// DraftExpired reports whether a stale draft is older than the retention
// window and should be offered for explicit deletion.
func (d *Draft) DraftExpired(now time.Time) bool {
	if d == nil {
		return false
	}
	created, err := time.Parse(time.RFC3339, d.CreatedAt)
	if err != nil {
		return false
	}
	return now.Sub(created) > draftExpiryDuration
}

// SetStep records a step outcome.
func (d *Draft) SetStep(step, status, note string) {
	d.Steps[step] = StepState{Status: status, Note: note, At: time.Now().UTC().Format(time.RFC3339)}
}

// IsDone reports step completion.
func (d *Draft) IsDone(step string) bool {
	s, ok := d.Steps[step]
	return ok && s.Status == StatusDone
}

// PendingSteps returns unfinished step names in execution order.
func (d *Draft) PendingSteps() []string {
	out := []string{}
	for _, step := range StepOrder {
		if !d.IsDone(step) {
			out = append(out, step)
		}
	}
	return out
}

// StepNames returns Russian step titles in the same order.
func StepNames() []string {
	return []string{
		"Введение и выбор режима адресов",
		"Проверка прав администратора",
		"Адреса, интерфейсы и порты",
		"Сертификаты TLS",
		"Подключение к SQL Server",
		"Учётная запись службы Windows",
		"Первый суперадминистратор",
		"Применение настроек",
		"Служба Windows и проверка работы",
		"Комплект восстановления",
		"Завершение установки",
	}
}

// SaveMarker atomically writes the install-state marker.
func SaveMarker(p Paths, marker Marker) error {
	marker.Version = stateVersion
	if marker.CompletedAt == "" && marker.Status == MarkerCompleted {
		marker.CompletedAt = time.Now().UTC().Format(time.RFC3339)
	}
	raw, err := json.MarshalIndent(marker, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(p.Root, 0o700); err != nil {
		return fmt.Errorf("создаю каталог состояния установки: %w", err)
	}
	tmp := p.Marker + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, p.Marker); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return secureFile(p.Marker)
}

// StartupGate implements the ordinary-run gate. It never launches the wizard
// implicitly; it only reports what the administrator must do.
func StartupGate(p Paths) error {
	switch MarkerStatus(p) {
	case MarkerCompleted:
		return nil
	case MarkerDraft:
		return errors.New("установка не завершена: обнаружен незавершённый черновик настройки; выполните «mandatnik-backend setup», чтобы продолжить, или удалите черновик по подсказке мастера")
	default:
		// No marker: an existing pre-wizard installation is allowed to run as
		// before; new installs must run setup explicitly.
		if cfgPath := platform.BackendConfigPath(); cfgPath != "" {
			if _, err := os.Stat(cfgPath); err == nil {
				// Legacy installation keeps running; the marker can be added
				// with «setup --adopt» without recreating any data.
				return nil
			}
		}
		return errors.New("первоначальная настройка не выполнена; запустите «mandatnik-backend setup»")
	}
}

// Utility path helpers ---------------------------------------------------

// dirOf returns the directory part of a path.
func dirOf(path string) string {
	return filepath.Dir(path)
}

// SortedKeys returns sorted map keys for deterministic output.
func SortedKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// TrimSpace helper for prompts.
func Clean(value string) string { return strings.TrimSpace(value) }
