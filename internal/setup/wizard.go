// Wizard orchestration: the step machine used by both setup and configure.
// The UI is injected so the core stays testable; interactive prompts, hidden
// password input and all Russian texts live in the cmd layer.
package setup

import (
	"errors"
	"fmt"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"
)

// UI abstracts the interactive console.
type UI interface {
	Sayf(format string, args ...any)
	Ask(label, current string) (string, error)
	AskSecret(label string) (string, error)
	Confirm(label string) (bool, error)
	Choose(label string, options []string) (int, error)
}

// Wizard carries the mutable draft, stores and paths.
type Wizard struct {
	Paths          Paths
	Draft          *Draft
	DraftSecrets   SecretStore
	RuntimeSecrets SecretStore
	UI             UI
	BackendExe     string
}

// NewWizard loads (or creates) the draft and its secret store.
func NewWizard(p Paths, ui UI, backendExe string) (*Wizard, error) {
	draft, err := LoadDraft(p)
	if err != nil {
		return nil, err
	}
	if draft == nil {
		draft = &Draft{Steps: map[string]StepState{}}
	}
	secrets, err := NewDraftSecrets(p)
	if err != nil {
		return nil, err
	}
	runtime, err := NewRuntimeSecrets(p)
	if err != nil {
		return nil, err
	}
	return &Wizard{Paths: p, Draft: draft, DraftSecrets: secrets, RuntimeSecrets: runtime, UI: ui, BackendExe: backendExe}, nil
}

// CheckAdministratorRights fails fast on non-Windows or non-elevated sessions.
func CheckAdministratorRights() error {
	if err := requireAdmin(); err != nil {
		return err
	}
	return nil
}

// CheckPorts validates the requested listeners: address parsing, distinct
// ports and the ability to bind each of them.
func CheckPorts(listens []string) error {
	ports := map[int]string{}
	for _, listen := range listens {
		host, portText, err := net.SplitHostPort(strings.TrimSpace(listen))
		if err != nil {
			return fmt.Errorf("адрес %q должен иметь вид host:порт: %w", listen, err)
		}
		port, err := strconv.Atoi(portText)
		if err != nil || port < 0 || port > 65535 {
			return fmt.Errorf("адрес %q: некорректный порт", listen)
		}
		if other, clash := ports[port]; clash && port != 0 && other == strings.ToLower(host) {
			return fmt.Errorf("адрес %q повторяется", listen)
		}
		ports[port] = strings.ToLower(host)
		ln, err := net.Listen("tcp", listen)
		if err != nil {
			return fmt.Errorf("не удалось открыть порт на адресе %q: %w", listen, err)
		}
		_ = ln.Close()
	}
	return nil
}

// ValidateDraftConfig runs the final pre-apply validation of the collected
// draft: interfaces, TLS assignment, DB plan and service account.
func (w *Wizard) ValidateDraftConfig() error {
	d := w.Draft
	if len(d.Interfaces) == 0 {
		return errors.New("не заданы адреса и порты интерфейсов")
	}
	roles := map[string]string{}
	listens := []string{}
	for _, i := range d.Interfaces {
		if _, ok := roles[i.Role]; ok {
			return fmt.Errorf("интерфейс %s задан дважды", i.Role)
		}
		roles[i.Role] = i.Listen
		listens = append(listens, i.Listen)
		if len(i.ClientNames) == 0 {
			return fmt.Errorf("интерфейс %s: не указан адрес, которым будут пользоваться клиенты", i.Role)
		}
	}
	if err := CheckPorts(listens); err != nil {
		return err
	}
	covered := map[string]bool{}
	for _, g := range d.TLSGroups {
		if len(g.Interfaces) == 0 {
			return fmt.Errorf("группа TLS %s не привязана ни к одному интерфейсу", g.ID)
		}
		if !g.Validated {
			return fmt.Errorf("группа TLS %s ещё не прошла проверку сертификата", g.ID)
		}
		for _, role := range g.Interfaces {
			if _, ok := roles[role]; !ok {
				return fmt.Errorf("группа TLS %s ссылается на неизвестный интерфейс %s", g.ID, role)
			}
			covered[role] = true
		}
		if g.WaitingCSR {
			return fmt.Errorf("группа TLS %s: ожидается сертификат по CSR от организационного УЦ", g.ID)
		}
		if g.CertFile == "" || g.KeyFile == "" {
			return fmt.Errorf("группа TLS %s: не заданы файлы сертификата и ключа", g.ID)
		}
	}
	for role := range roles {
		if !covered[role] {
			return fmt.Errorf("интерфейс %s не обеспечен сертификатом TLS", role)
		}
	}
	if d.DB.Server == "" || d.DB.Database == "" || d.DB.User == "" {
		return errors.New("не заполнены параметры подключения к SQL Server")
	}
	if !d.DB.Encrypt && !d.DB.InsecureConfirmed {
		return errors.New("отключённое шифрование SQL-трафика требует явного подтверждения")
	}
	if d.DB.Encrypt && d.DB.TrustServerCert {
		return errors.New("проверку сертификата SQL Server отключать нельзя; задайте ca_file и server_name")
	}
	if d.ServiceAcct.Mode != "create" && d.ServiceAcct.Mode != "existing" {
		return errors.New("не выбрана учётная запись службы")
	}
	if d.ServiceAcct.Mode == "existing" && strings.TrimSpace(d.ServiceAcct.Account) == "" {
		return errors.New("не указана существующая учётная запись службы")
	}
	if !d.Superadmin.PasswordSealed {
		return errors.New("пароль первого суперадминистратора не задан")
	}
	return nil
}

// Summary renders the no-secrets summary shown before applying.
func (d *Draft) Summary() string {
	var b strings.Builder
	mode := map[string]string{"install": "первоначальная установка", "adopt": "приём существующей установки"}[d.Mode]
	fmt.Fprintf(&b, "Режим: %s\n", mode)
	fmt.Fprintf(&b, "Раздел адресов: %s\n", map[string]string{"simple": "простой (один адрес и сертификат)", "advanced": "расширенный (отдельные адреса)"}[d.ModeChoice])
	for _, i := range d.Interfaces {
		fmt.Fprintf(&b, "  %s: прослушивание %s, клиенты: %s\n", roleTitle(i.Role), i.Listen, strings.Join(i.ClientNames, ", "))
	}
	for _, g := range d.TLSGroups {
		fmt.Fprintf(&b, "  TLS (%s): режим %s, сертификат %s\n", strings.Join(g.Interfaces, "+"), certModeTitle(g.Mode), g.CertFile)
		if g.WaitingCSR {
			fmt.Fprintf(&b, "  TLS (%s): ожидается сертификат по CSR\n", strings.Join(g.Interfaces, "+"))
		}
	}
	fmt.Fprintf(&b, "SQL Server: %s:%d, база %s, пользователь %s, шифрование: %s\n",
		d.DB.Server, d.DB.Port, d.DB.Database, d.DB.User, dbTLSModeTitle(d.DB))
	fmt.Fprintf(&b, "Учётная запись службы: %s\n", serviceAcctTitle(d.ServiceAcct))
	fmt.Fprintf(&b, "Суперадминистратор: %s (%s)\n", d.Superadmin.DisplayName, d.Superadmin.Email)
	return b.String()
}

func roleTitle(role string) string {
	return map[string]string{"agent": "агентский API", "admin": "админка", "integration": "интеграционный API"}[role]
}

func certModeTitle(mode string) string {
	return map[string]string{"import": "импорт готового", "csr": "по CSR от УЦ Windows", "ca": "собственный CA установки"}[mode]
}

func dbTLSModeTitle(db DBPlan) string {
	if !db.Encrypt {
		return "ШИФРОВАНИЕ ЯВНО ОТКЛЮЧЕНО (трафик идёт без TLS по требованию настройки; сервер, принудительно требующий TLS, отклонит подключение)"
	}
	if db.TrustServerCert {
		return "проверка сертификата сервера отключена (не рекомендуется)"
	}
	return "TLS с проверкой имени и цепочки"
}

func serviceAcctTitle(a ServiceAccount) string {
	if a.Mode == "create" {
		return fmt.Sprintf("создать новую локальную учётную запись %s (случайный пароль)", a.Account)
	}
	return "использовать существующую " + a.Account
}

// SortInterfaces orders interfaces for deterministic rendering.
func SortInterfaces(list []Interface) {
	sort.Slice(list, func(i, j int) bool { return list[i].Role < list[j].Role })
}

// FirewallSummary returns the final per-interface port memo.
func (d *Draft) FirewallSummary() string {
	var b strings.Builder
	for _, i := range d.Interfaces {
		port := portOf(i.Listen)
		switch i.Role {
		case "agent":
			fmt.Fprintf(&b, "  %s (%s) — открыть для сети АРМ\n", port, roleTitle(i.Role))
		case "admin":
			fmt.Fprintf(&b, "  %s (%s) — открыть только для административных машин/подсети\n", port, roleTitle(i.Role))
		case "integration":
			fmt.Fprintf(&b, "  %s (%s) — открыть только для доверенных систем интеграции\n", port, roleTitle(i.Role))
		}
	}
	fmt.Fprintf(&b, "  Исходящее подключение к SQL Server: %s:%d (TCP) — разрешите бэкенду\n", d.DB.Server, d.DB.Port)
	return b.String()
}

func portOf(listen string) string {
	_, port, err := net.SplitHostPort(listen)
	if err != nil {
		return listen
	}
	return port
}

// Now is a test seam.
var Now = time.Now

var _ = os.Getenv
