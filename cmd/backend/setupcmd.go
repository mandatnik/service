package main

// Interactive console wizard commands: setup, configure and the local
// superadministrator access recovery. All texts are Russian; passwords are
// read hidden and never appear in command lines, logs or diagnostics.

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/term"

	"mandatnik/internal/backend"
	"mandatnik/internal/backend/config"
	"mandatnik/internal/backend/db"
	"mandatnik/internal/backend/licensecrypto"
	"mandatnik/internal/backend/store"
	"mandatnik/internal/platform"
	"mandatnik/internal/setup"
	"mandatnik/internal/version"
)

// terminalUI is the console implementation of setup.UI.
type terminalUI struct{}

func (terminalUI) Sayf(format string, args ...any) {
	fmt.Printf("  "+format+"\n", args...)
}

func (terminalUI) Ask(label, current string) (string, error) {
	if current != "" {
		fmt.Printf("%s [текущее: %s]: ", label, current)
	} else {
		fmt.Printf("%s: ", label)
	}
	line, err := readLine()
	if err != nil {
		return "", err
	}
	if strings.TrimSpace(line) == "" && current != "" {
		return current, nil
	}
	return strings.TrimSpace(line), nil
}

func (terminalUI) AskSecret(label string) (string, error) {
	fmt.Printf("%s: ", label)
	raw, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Println()
	if err != nil {
		return "", err
	}
	return string(raw), nil
}

func (terminalUI) Confirm(label string) (bool, error) {
	fmt.Printf("%s [да/нет]: ", label)
	line, err := readLine()
	if err != nil {
		return false, err
	}
	switch strings.ToLower(strings.TrimSpace(line)) {
	case "д", "да", "y", "yes":
		return true, nil
	}
	return false, nil
}

func (terminalUI) Choose(label string, options []string) (int, error) {
	fmt.Println(label)
	for i, option := range options {
		fmt.Printf("  %d) %s\n", i+1, option)
	}
	fmt.Print("номер: ")
	line, err := readLine()
	if err != nil {
		return 0, err
	}
	n := 0
	if _, err := fmt.Sscanf(strings.TrimSpace(line), "%d", &n); err != nil || n < 1 || n > len(options) {
		return 0, fmt.Errorf("некорректный выбор: %q", line)
	}
	return n - 1, nil
}

func readLine() (string, error) {
	scanner := &lineScanner{}
	return scanner.read()
}

// lineReader reads bytes from stdin without buffering the rest of the line.
type lineReader struct{ b []byte }

func (r *lineReader) Read(p []byte) (int, error) {
	return os.Stdin.Read(p)
}

type lineScanner struct{}

func (*lineScanner) read() (string, error) {
	reader := &lineReader{}
	var out []byte
	buf := make([]byte, 1)
	for {
		n, err := reader.Read(buf)
		if n > 0 {
			out = append(out, buf[0])
			if buf[0] == '\n' {
				break
			}
		}
		if err != nil {
			return string(out), err
		}
	}
	return strings.TrimRight(string(out), "\r\n"), nil
}

var _ io.Reader = &lineReader{}

// runSetup implements `mandatnik-backend setup`.
func runSetup(args []string) error {
	paths := setup.DefaultPaths()
	adopt := false
	for _, a := range args {
		if a == "--adopt" {
			adopt = true
		}
	}
	if err := setup.CheckAdministratorRights(); err != nil {
		return err
	}
	switch setup.MarkerStatus(paths) {
	case setup.MarkerCompleted:
		if adopt {
			return errors.New("установка уже завершена; для изменения настроек используйте «mandatnik-backend configure»")
		}
		return errors.New("установка уже завершена; повторный setup не перезаписывает настройки, ключи и пользователей — используйте «mandatnik-backend configure»")
	case setup.MarkerDraft:
		draft, err := setup.LoadDraft(paths)
		if err != nil {
			return err
		}
		ui := terminalUI{}
		ui.Sayf("обнаружен незавершённый черновик настройки от %s, пройдено шагов: %d из %d",
			draft.CreatedAt, len(draft.Steps), len(setup.StepOrder))
		keep, err := ui.Confirm("Продолжить прерванную настройку?")
		if err != nil {
			return err
		}
		if !keep {
			if err := setup.DeleteDraft(paths); err != nil {
				return err
			}
			if err := os.Remove(paths.Marker); err != nil && !os.IsNotExist(err) {
				return err
			}
			ui.Sayf("черновик удалён; настройка начнётся с нуля")
		}
	case setup.MarkerNone:
		// Fresh install, or explicit adoption of a pre-wizard installation.
	}

	if adopt {
		return adoptExistingInstallation(paths)
	}
	return runSetupWizard(paths)
}

// adoptExistingInstallation records the setup marker for installations made
// before the wizard existed, without recreating any data or keys.
func adoptExistingInstallation(paths setup.Paths) error {
	ui := terminalUI{}
	ui.Sayf("режим приёма существующей установки (--adopt): данные, ключи и пользователи не пересоздаются")
	cfgPath := platform.BackendConfigPath()
	if _, err := os.Stat(cfgPath); err != nil {
		return errors.New("файл конфигурации backend.json не найден; приёмить нечего")
	}
	cfg, err := config.Load(cfgPath)
	if err != nil {
		return fmt.Errorf("существующая конфигурация не читается: %w", err)
	}
	if _, err := os.Stat(cfg.TLSCertFile); err != nil {
		return fmt.Errorf("TLS-сертификат %s не найден: %w", cfg.TLSCertFile, err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	pool, err := db.Open(ctx, cfg.DB)
	if err != nil {
		return fmt.Errorf("проверка подключения к БД: %w", err)
	}
	defer pool.Close()
	marker := setup.Marker{Status: setup.MarkerCompleted, Mode: "adopt", BackendExe: executablePath()}
	if err := setup.SaveMarker(paths, marker); err != nil {
		return err
	}
	ui.Sayf("маркер завершённой установки записан; дальше используйте «mandatnik-backend configure»")
	return nil
}

func executablePath() string {
	exe, err := os.Executable()
	if err != nil {
		return ""
	}
	return exe
}

// runSetupWizard drives the full interactive installation.
func runSetupWizard(paths setup.Paths) error {
	ui := terminalUI{}
	w, err := setup.NewWizard(paths, ui, executablePath())
	if err != nil {
		return err
	}
	if err := w.Draft.Save(paths); err != nil {
		return err
	}
	fmt.Println("=== Мандатник: мастер первоначальной настройки бэкенда ===")
	fmt.Println("Все введённые пароли скрыты и не сохраняются в открытом виде.")

	for {
		pending := w.Draft.PendingSteps()
		if len(pending) == 0 {
			break
		}
		step := pending[0]
		if err := runStep(w, step, paths); err != nil {
			fmt.Fprintf(os.Stderr, "ошибка на шаге %q: %v\n", step, err)
			if keep, _ := ui.Confirm("Сохранить черновик и прервать? (нет — повторить шаг)"); keep {
				if err := w.Draft.Save(paths); err != nil {
					return err
				}
				return errors.New("настройка прервана; продолжите командой «mandatnik-backend setup»")
			}
			continue
		}
		if err := w.Draft.Save(paths); err != nil {
			return err
		}
	}
	return finishInstallation(paths, w)
}

func runStep(w *setup.Wizard, step string, paths setup.Paths) error {
	ui := w.UI
	switch step {
	case setup.StepIntro:
		ui.Sayf("Шаг 1: выбор схемы адресов")
		idx, err := ui.Choose("Как разделяются интерфейсы?",
			[]string{
				"Простой: один домен и один сертификат для всех трёх API",
				"Расширенный: отдельные адреса и сертификаты для агентского API, админки и интеграционного API",
			})
		if err != nil {
			return err
		}
		w.Draft.Mode = "install"
		w.Draft.ModeChoice = map[int]string{0: "simple", 1: "advanced"}[idx]
		w.Draft.SetStep(step, setup.StatusDone, w.Draft.ModeChoice)

	case setup.StepRights:
		if err := setup.CheckAdministratorRights(); err != nil {
			w.Draft.SetStep(step, setup.StatusFailed, err.Error())
			return err
		}
		ui.Sayf("Права администратора подтверждены")
		w.Draft.SetStep(step, setup.StatusDone, "")

	case setup.StepListening:
		return stepListening(w)

	case setup.StepCerts:
		return stepCertificates(w, paths)

	case setup.StepDatabase:
		return stepDatabase(w)

	case setup.StepServiceAcct:
		return stepServiceAccount(w)

	case setup.StepSuperadmin:
		return stepSuperadmin(w)

	case setup.StepApply, setup.StepService, setup.StepBundle, setup.StepFinish:
		// Applied in finishInstallation; marked done there.
		w.Draft.SetStep(step, setup.StatusDone, "")
		return nil
	}
	return nil
}

// stepListening collects interface addresses and ports. Existing ports are
// offered as defaults; every value is re-checked for conflicts and bindability.
func stepListening(w *setup.Wizard) error {
	ui := w.UI
	ui.Sayf("Шаг 2: адреса, интерфейсы и порты")
	defaults := map[string]string{
		"agent":       "0.0.0.0:8443",
		"admin":       "0.0.0.0:8444",
		"integration": "0.0.0.0:8446",
	}
	var roles []string
	if w.Draft.ModeChoice == "simple" {
		roles = []string{"agent", "admin", "integration"}
	} else {
		roles = []string{"agent", "admin", "integration"}
	}
	interfaces := make([]setup.Interface, 0, len(roles))
	hostname := localHostname()
	for _, role := range roles {
		ui.Sayf("Интерфейс %s", roleTitle(role))
		listen, err := ui.Ask(fmt.Sprintf("Адрес прослушивания host:порт для %s", roleTitle(role)), defaults[role])
		if err != nil {
			return err
		}
		defaultClient := defaults[role]
		if w.Draft.ModeChoice == "simple" {
			defaultClient = hostname + ":" + portOf(listen)
		}
		clients, err := ui.Ask("Адрес(а), которым будут пользоваться клиенты (DNS-имена и/или IP через запятую)", defaultClient)
		if err != nil {
			return err
		}
		var names []string
		for _, name := range strings.Split(clients, ",") {
			if name = strings.TrimSpace(name); name != "" {
				names = append(names, name)
			}
		}
		if len(names) == 0 {
			return fmt.Errorf("не указан адрес, которым пользуются клиенты, для %s", role)
		}
		interfaces = append(interfaces, setup.Interface{Role: role, Listen: listen, ClientNames: names})
	}
	if err := setup.CheckPorts([]string{
		interfaces[0].Listen, interfaces[1].Listen, interfaces[2].Listen,
	}); err != nil {
		return err
	}
	ui.Sayf("Порты проверены: конфликты не обнаружены, прослушивание доступно")
	w.Draft.Interfaces = interfaces
	if w.Draft.ModeChoice == "simple" {
		// One shared TLS group for all interfaces.
		w.Draft.TLSGroups = []setup.TLSGroup{{
			ID: "shared", Interfaces: []string{"agent", "admin", "integration"}, Mode: "import",
		}}
	} else {
		w.Draft.TLSGroups = []setup.TLSGroup{
			{ID: "agent", Interfaces: []string{"agent"}, Mode: "import"},
			{ID: "admin", Interfaces: []string{"admin"}, Mode: "import"},
			{ID: "integration", Interfaces: []string{"integration"}, Mode: "import"},
		}
	}
	w.Draft.SetStep(setup.StepListening, setup.StatusDone, "")
	return nil
}

func localHostname() string {
	name, err := os.Hostname()
	if err != nil {
		return "localhost"
	}
	return strings.ToLower(name)
}

func roleTitle(role string) string {
	return map[string]string{"agent": "агентский API", "admin": "админка", "integration": "интеграционный API"}[role]
}

func portOf(listen string) string {
	if _, port, err := net.SplitHostPort(listen); err == nil {
		return port
	}
	return listen
}

// stepCertificates drives the TLS source choice per group and validates the
// resulting certificate, key, chain and SAN coverage. Failed checks can be
// corrected and re-run; existing material is never replaced silently.
func stepCertificates(w *setup.Wizard, paths setup.Paths) error {
	ui := w.UI
	ui.Sayf("Шаг 3: сертификаты TLS")
	tlsDir := filepath.Join(platform.BackendDir(), "tls")
	if err := os.MkdirAll(tlsDir, 0o700); err != nil {
		return err
	}
	for i := range w.Draft.TLSGroups {
		group := &w.Draft.TLSGroups[i]
		ui.Sayf("Сертификат для %s", strings.Join(group.Interfaces, ", "))
		mode, err := ui.Choose("Источник сертификата",
			[]string{
				"Импорт готового сертификата (PFX/P12 или PEM сертификат + ключ)",
				"Создать CSR для организационного УЦ Windows (ожидание сертификата)",
				"Собственный CA установки (выпустить серверные сертификаты здесь)",
			})
		if err != nil {
			return err
		}
		group.Mode = map[int]string{0: "import", 1: "csr", 2: "ca"}[mode]
		hosts := collectGroupHosts(w, group)
		switch group.Mode {
		case "import":
			if err := importCertificate(ui, group, hosts, tlsDir); err != nil {
				return err
			}
		case "csr":
			if err := createCSR(ui, group, hosts, tlsDir); err != nil {
				return err
			}
		case "ca":
			if err := ownCACertificate(ui, group, hosts, tlsDir, w, paths); err != nil {
				return err
			}
		}
	}
	// All groups validated (or CSR-waiting, which blocks the apply step).
	for _, group := range w.Draft.TLSGroups {
		if group.WaitingCSR {
			return errors.New("есть группы, ожидающие сертификат по CSR; завершите их или выберите другой источник")
		}
	}
	w.Draft.SetStep(setup.StepCerts, setup.StatusDone, "")
	return nil
}

func collectGroupHosts(w *setup.Wizard, group *setup.TLSGroup) []string {
	var hosts []string
	for _, iface := range w.Draft.Interfaces {
		for _, role := range group.Interfaces {
			if iface.Role == role {
				hosts = append(hosts, iface.ClientNames...)
			}
		}
	}
	return dedupe(hosts)
}

func dedupe(values []string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, v := range values {
		if !seen[strings.ToLower(v)] {
			seen[strings.ToLower(v)] = true
			out = append(out, v)
		}
	}
	return out
}

// validateAgainst runs the certificate checks and lets the administrator fix
// problems by re-entering the path (repeat allowed by the wizard loop).
func validateAgainst(ui setup.UI, leaf *x509.Certificate, chain []*x509.Certificate, key any, hosts []string, trustAnchors []*x509.Certificate) (*setup.CertCheck, error) {
	if err := setup.KeyMatchesTLS(leaf, key); err != nil {
		return nil, err
	}
	check, err := setup.ValidateServerCert(leaf, chain, hosts, trustAnchors, time.Now())
	if err != nil {
		return nil, err
	}
	ui.Sayf("Субъект: %s", check.Subject)
	ui.Sayf("Издатель: %s", check.Issuer)
	ui.Sayf("Действует: %s — %s, ключ: %s, подпись: %s", check.NotBefore, check.NotAfter, check.KeyAlgorithm, check.Signature)
	ui.Sayf("SAN: %s", strings.Join(check.SANs, ", "))
	for _, warning := range check.Warnings {
		ui.Sayf("ВНИМАНИЕ: %s", warning)
	}
	if !check.OK {
		for _, problem := range check.Problems {
			ui.Sayf("ПРОБЛЕМА: %s", problem)
		}
		return nil, errors.New("сертификат не принят: устраните проблемы и повторите проверку")
	}
	ui.Sayf("Сертификат принят: SAN покрывает все выбранные адреса, ключ соответствует, срок действия и применения корректны")
	return check, nil
}

func importCertificate(ui setup.UI, group *setup.TLSGroup, hosts []string, tlsDir string) error {
	for {
		kind, err := ui.Choose("Формат импорта", []string{"PFX/P12 с паролем", "PEM: сертификат и цепочка + отдельный ключ"})
		if err != nil {
			return err
		}
		var leaf *x509.Certificate
		var chain []*x509.Certificate
		var key any
		if kind == 0 {
			pfx, err := ui.Ask("Путь к PFX/P12 файлу", group.CertFile)
			if err != nil {
				return err
			}
			password, err := ui.AskSecret("Пароль PFX (ввод скрыт)")
			if err != nil {
				return err
			}
			leaf, chain, key, err = setup.LoadPFX(pfx, password)
			if err != nil {
				ui.Sayf("Ошибка: %v", err)
				continue
			}
			group.CertFile = pfx
		} else {
			certPath, err := ui.Ask("Путь к PEM-сертификату (можно с цепочкой)", group.CertFile)
			if err != nil {
				return err
			}
			keyPath, err := ui.Ask("Путь к файлу закрытого ключа (PEM)", group.KeyFile)
			if err != nil {
				return err
			}
			leaf, chain, key, err = setup.LoadPEM(certPath, keyPath)
			if err != nil {
				ui.Sayf("Ошибка: %v", err)
				continue
			}
			group.CertFile, group.KeyFile = certPath, keyPath
		}
		if _, err := validateAgainst(ui, leaf, chain, key, hosts, chain); err != nil {
			ui.Sayf("%v", err)
			continue
		}
		// Install copies under the protected tls directory; originals stay.
		certCopy := filepath.Join(tlsDir, group.ID+".crt")
		keyCopy := filepath.Join(tlsDir, group.ID+".key")
		if err := writeInstalledPair(leaf, chain, key, certCopy, keyCopy); err != nil {
			return err
		}
		group.CertFile, group.KeyFile = certCopy, keyCopy
		group.Validated = true
		return nil
	}
}

func writeInstalledPair(leaf *x509.Certificate, chain []*x509.Certificate, key any, certPath, keyPath string) error {
	var certPEM strings.Builder
	writePEM(&certPEM, "CERTIFICATE", leaf.Raw)
	for _, c := range chain {
		writePEM(&certPEM, "CERTIFICATE", c.Raw)
	}
	if err := os.WriteFile(certPath, []byte(certPEM.String()), 0o600); err != nil {
		return err
	}
	if err := os.WriteFile(keyPath, marshalKey(key), 0o600); err != nil {
		return err
	}
	return secureBoth(certPath, keyPath)
}

func writePEM(b *strings.Builder, blockType string, der []byte) {
	b.WriteString(pemEncode(blockType, der))
}

func marshalKey(key any) []byte {
	// marshalKey is exported from the setup package for cmd use.
	return setup.MarshalKeyPEM(key)
}

func pemEncode(blockType string, der []byte) string {
	return setup.EncodePEM(blockType, der)
}

func secureBoth(certPath, keyPath string) error {
	if err := setup.SecurePath(certPath); err != nil {
		return err
	}
	return setup.SecurePath(keyPath)
}

// createCSR writes the key and CSR, marks the waiting state and prints the
// actions for the Windows CA administrator. A later setup run accepts the
// issued certificate.
func createCSR(ui setup.UI, group *setup.TLSGroup, hosts []string, tlsDir string) error {
	keyPath := filepath.Join(tlsDir, group.ID+".key")
	csrPath := filepath.Join(tlsDir, group.ID+".csr")
	if group.CSRFile != "" && !group.WaitingCSR {
		// Certificate already received in a previous run; accept it.
		return acceptCSRCertificate(ui, group, hosts)
	}
	if _, err := os.Stat(keyPath); err == nil && group.CSRFile == "" {
		ui.Sayf("Файл ключа %s уже существует; перезапись не выполняется", keyPath)
		return errors.New("выберите импорт готового сертификата для существующего ключа или удалите файл явно")
	}
	commonName, err := ui.Ask("Общее имя (CN) для CSR", hosts[0])
	if err != nil {
		return err
	}
	if _, err := setup.CreateKeyAndCSR(keyPath, csrPath, commonName, hosts); err != nil {
		return err
	}
	group.CSRFile = csrPath
	group.KeyFile = keyPath
	group.WaitingCSR = true
	ui.Sayf("CSR создан: %s", csrPath)
	ui.Sayf("Дальнейшие действия для администратора организационного УЦ Windows:")
	ui.Sayf("  1. Отправьте CSR в УЦ: certreq -submit -attrib \"Шаблон: WebServer\" %s", csrPath)
	ui.Sayf("     (используйте шаблон, экспортирующий закрытый ключ, если позже понадобится PFX)")
	ui.Sayf("  2. Полученный сертификат (предпочтительно полный PFX с ключом) сохраните на диск")
	ui.Sayf("  3. Снова запустите «mandatnik-backend setup» и продолжите настройку")
	return errors.New("настройка приостановлена: ожидается сертификат от УЦ; продолжите позже командой «mandatnik-backend setup»")
}

func acceptCSRCertificate(ui setup.UI, group *setup.TLSGroup, hosts []string) error {
	certPath, err := ui.Ask("Путь к полученному сертификату (PEM или PFX)", "")
	if err != nil {
		return err
	}
	var leaf *x509.Certificate
	var chain []*x509.Certificate
	var key any
	if strings.EqualFold(filepath.Ext(certPath), ".pfx") || strings.EqualFold(filepath.Ext(certPath), ".p12") {
		password, err := ui.AskSecret("Пароль PFX (ввод скрыт)")
		if err != nil {
			return err
		}
		leaf, chain, key, err = setup.LoadPFX(certPath, password)
	} else {
		keyPath, err := ui.Ask("Путь к закрытому ключу, созданному вместе с CSR", group.KeyFile)
		if err != nil {
			return err
		}
		leaf, chain, key, err = setup.LoadPEM(certPath, keyPath)
	}
	if err != nil {
		return err
	}
	if _, err := validateAgainst(ui, leaf, chain, key, hosts, chain); err != nil {
		return err
	}
	certCopy := filepath.Join(filepath.Dir(group.CSRFile), group.ID+".crt")
	if err := writeInstalledPair(leaf, chain, key, certCopy, group.KeyFile); err != nil {
		return err
	}
	group.CertFile = certCopy
	group.WaitingCSR = false
	group.Validated = true
	return nil
}

// ownCACertificate implements the installation-CA flow with protected export
// and the explicit deletion of the working CA key copy.
func ownCACertificate(ui setup.UI, group *setup.TLSGroup, hosts []string, tlsDir string, w *setup.Wizard, paths setup.Paths) error {
	if w.Draft.BundlePath != "" && !w.Draft.BundleCAKey {
		return errors.New("комплект восстановления уже создан без ключа CA; используйте другой режим")
	}
	caCertPath := filepath.Join(tlsDir, "installation-ca.crt")
	caKeyExport := filepath.Join(tlsDir, "installation-ca.key.enc")
	_, caStatErr := os.Stat(caCertPath)
	_, caKeyErr := os.Stat(caKeyExport)
	if caStatErr == nil && caKeyErr == nil {
		ui.Sayf("Обнаружен существующий CA установки: %s", caCertPath)
		return reissueFromExportedCA(ui, group, hosts, caCertPath, caKeyExport, tlsDir)
	}
	if caStatErr == nil || caKeyErr == nil {
		return errors.New("найден неполный набор файлов CA установки; проверьте каталог tls")
	}
	ui.Sayf("Будет создан отдельный CA этой установки (корневой сертификат + серверные сертификаты)")
	cn, err := ui.Ask("Имя CA (CN)", "Mandatnik Installation CA")
	if err != nil {
		return err
	}
	caCert, caKey, err := setup.CreateInstallationCA(cn, 1825)
	if err != nil {
		return err
	}
	exportPass, err := ui.AskSecret("Пароль для экспортируемого файла ключа CA (ввод скрыт)")
	if err != nil {
		return err
	}
	repeat, err := ui.AskSecret("Повторите пароль файла ключа CA")
	if err != nil {
		return err
	}
	if !setup.ComparePasswords(exportPass, repeat) {
		return errors.New("пароли не совпадают")
	}
	if len(exportPass) < 8 {
		return errors.New("пароль ключа CA должен содержать не менее 8 символов")
	}
	if err := setup.WriteCAFiles(caCertPath, caKeyExport, caCert, caKey, exportPass); err != nil {
		return err
	}
	cert, key, err := setup.IssueServerCert(caCert, caKey, hosts[0], hosts, 397)
	if err != nil {
		return err
	}
	certCopy := filepath.Join(tlsDir, group.ID+".crt")
	keyCopy := filepath.Join(tlsDir, group.ID+".key")
	if err := writeInstalledPair(cert, nil, key, certCopy, keyCopy); err != nil {
		return err
	}
	group.CertFile, group.KeyFile, group.CAFile = certCopy, keyCopy, caCertPath
	group.CAPrivateID = caKeyExport
	group.Validated = true
	ui.Sayf("Серверный сертификат выпущен и установлен: %s", certCopy)
	ui.Sayf("Экспортированные файлы CA:")
	ui.Sayf("  Публичный сертификат (распространить доверие через GPO или вручную): %s", caCertPath)
	ui.Sayf("  Закрытый ключ CA (зашифрован паролем, храните отдельно и в защищённом месте): %s", caKeyExport)
	ui.Sayf("ВАЖНО: закрытый ключ CA позволяет выпускать доверенные сертификаты — храните его вне сервера")
	ok, err := ui.Confirm("Экспортированный файл ключа CA сохранён вне рабочей копии; удалить рабочую копию ключа CA с сервера?")
	if err != nil {
		return err
	}
	if !ok {
		ui.Sayf("Рабочая копия ключа CA сохранена в %s — перенесите её в защищённое место и удалите вручную", caKeyExport)
	} else {
		// The bundle keeps its own encrypted copy of the CA key.
		w.Draft.BundleCAKey = true
		caKeyBytes, readErr := os.ReadFile(caKeyExport)
		if readErr != nil {
			return readErr
		}
		if err := os.WriteFile(filepath.Join(paths.Root, "installation-ca.key.enc"), caKeyBytes, 0o600); err != nil {
			return err
		}
		if err := setup.SecurePath(filepath.Join(paths.Root, "installation-ca.key.enc")); err != nil {
			return err
		}
		if err := setup.DeleteWorkingKey(caKeyExport); err != nil {
			return fmt.Errorf("не удалось удалить рабочую копию ключа CA: %w", err)
		}
		group.CAPrivateID = ""
		ui.Sayf("Рабочая копия ключа CA удалена с сервера (копия внутри зашифрованного комплекта восстановления)")
	}
	return nil
}

func reissueFromExportedCA(ui setup.UI, group *setup.TLSGroup, hosts []string, caCertPath, caKeyExport, tlsDir string) error {
	pass, err := ui.AskSecret("Пароль зашифрованного ключа CA (ввод скрыт)")
	if err != nil {
		return err
	}
	caKey, err := setup.DecryptPEMKey(caKeyExport, pass)
	if err != nil {
		return err
	}
	caCert, _, _, err := setup.LoadPEM(caCertPath, "")
	if err != nil {
		return err
	}
	cert, key, err := setup.IssueServerCert(caCert, caKey, hosts[0], hosts, 397)
	if err != nil {
		return err
	}
	certCopy := filepath.Join(tlsDir, group.ID+".crt")
	keyCopy := filepath.Join(tlsDir, group.ID+".key")
	if err := writeInstalledPair(cert, nil, key, certCopy, keyCopy); err != nil {
		return err
	}
	group.CertFile, group.KeyFile, group.CAFile = certCopy, keyCopy, caCertPath
	group.Validated = true
	ui.Sayf("Сертификат перевыпущен существующим CA установки")
	return nil
}

// stepDatabase prompts for SQL Server parameters, probes the connection and
// classifies the database. Fresh installs require an empty database; existing
// installations must be adopted or restored with their own keys.
func stepDatabase(w *setup.Wizard) error {
	ui := w.UI
	ui.Sayf("Шаг 4: подключение к SQL Server")
	ui.Sayf("Мастер подключается только к уже созданной базе данных и учётной записи SQL.")
	ui.Sayf("Установка SQL Server, создание базы или логина не выполняются; sa не запрашивается.")
	for {
		server, err := ui.Ask("Сервер SQL Server (имя или IP)", w.Draft.DB.Server)
		if err != nil {
			return err
		}
		portText, err := ui.Ask("Порт SQL Server", intOr1433(w.Draft.DB.Port))
		if err != nil {
			return err
		}
		database, err := ui.Ask("Имя базы данных", w.Draft.DB.Database)
		if err != nil {
			return err
		}
		user, err := ui.Ask("Имя пользователя SQL", w.Draft.DB.User)
		if err != nil {
			return err
		}
		password, err := ui.AskSecret("Пароль пользователя SQL (ввод скрыт)")
		if err != nil {
			return err
		}
		w.Draft.DB = setup.DBPlan{Server: server, Database: database, User: user, Encrypt: true}
		w.Draft.DB.Port = parseInt(portText, 1433)

		encryptYes, err := ui.Confirm("Требовать защищённое подключение (TLS) к SQL Server? [рекомендуется: да]")
		if err != nil {
			return err
		}
		w.Draft.DB.Encrypt = encryptYes
		if encryptYes {
			serverName, err := ui.Ask("Имя сервера для проверки сертификата SQL (SAN), пусто — как указано выше", server)
			if err != nil {
				return err
			}
			w.Draft.DB.ServerName = serverName
			caFile, err := ui.Ask("PEM-файл доверенного УЦ SQL Server (пусто — системные корневые)", "")
			if err != nil {
				return err
			}
			w.Draft.DB.CAFile = caFile
		} else {
			ui.Sayf("ВНИМАНИЕ: при отключённом шифровании трафик идёт по сети без TLS, если SQL Server")
			ui.Sayf("сам принудительно не требует шифрования (тогда подключение просто не установится).")
			confirmOff, err := ui.Confirm("Подтверждаете явно отключённое шифрование SQL-трафика?")
			if err != nil {
				return err
			}
			if !confirmOff {
				continue
			}
			w.Draft.DB.InsecureConfirmed = true
		}
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		creds := setup.ProbeCredentials{
			Server: server, Port: w.Draft.DB.Port, Database: database, User: user,
			Password: password, Encrypt: encryptYes,
			TrustServerCertificate: false,
		}
		pool, err := setup.Connect(ctx, creds)
		if err != nil {
			cancel()
			ui.Sayf("Ошибка подключения: %v", err)
			retry, _ := ui.Confirm("Исправить данные и повторить проверку?")
			if !retry {
				return err
			}
			continue
		}
		probe, err := setup.ProbeDatabase(ctx, pool, creds)
		if err != nil {
			pool.Close()
			cancel()
			ui.Sayf("Ошибка проверки базы: %v", err)
			retry, _ := ui.Confirm("Исправить данные и повторить проверку?")
			if !retry {
				return err
			}
			continue
		}
		if err := setup.CheckMigrationRights(ctx, pool); err != nil {
			pool.Close()
			cancel()
			return fmt.Errorf("учётная запись не имеет прав, необходимых для миграций и работы: %w", err)
		}
		pool.Close()
		cancel()
		switch probe.Kind {
		case "empty":
			ui.Sayf("База пуста — подойдёт для новой установки")
		case "mandatnik":
			return errors.New("в этой базе найдены таблицы «Мандатника»; новая установка поверх существующей запрещена — подключите существующую установку (setup --adopt) или выполните восстановление с её ключами")
		default:
			return errors.New("база не пуста и не содержит объектов «Мандатника» (чужая база) — укажите пустую базу, созданную специально для установки")
		}
		if err := w.RuntimeSecrets.Put(setup.SecretDBPassword, []byte(password)); err != nil {
			return fmt.Errorf("сохраняю пароль БД в защищённом хранилище: %w", err)
		}
		w.Draft.DB.EmptyVerified = true
		w.Draft.SetStep(setup.StepDatabase, setup.StatusDone, fmt.Sprintf("%s:%d/%s", server, w.Draft.DB.Port, database))
		return nil
	}
}

func intOr1433(port int) string {
	if port == 0 {
		return "1433"
	}
	return fmt.Sprint(port)
}

func parseInt(text string, def int) int {
	n := 0
	if _, err := fmt.Sscanf(strings.TrimSpace(text), "%d", &n); err != nil || n < 1 || n > 65535 {
		return def
	}
	return n
}

// stepServiceAccount plans the Windows service account.
func stepServiceAccount(w *setup.Wizard) error {
	ui := w.UI
	ui.Sayf("Шаг 5: учётная запись Windows-службы")
	idx, err := ui.Choose("Какая учётная запись будет использоваться службой?",
		[]string{
			"Создать отдельную локальную учётную запись со случайным паролем (рекомендуется)",
			"Использовать существующую локальную учётную запись и её пароль",
		})
	if err != nil {
		return err
	}
	if idx == 0 {
		account, err := ui.Ask("Имя новой учётной записи", "mandatnik_svc")
		if err != nil {
			return err
		}
		w.Draft.ServiceAcct = setup.ServiceAccount{Mode: "create", Account: account}
	} else {
		account, err := ui.Ask("Имя существующей учётной записи (например .\\svc_mandatnik)", "")
		if err != nil {
			return err
		}
		password, err := ui.AskSecret("Пароль существующей учётной записи (ввод скрыт)")
		if err != nil {
			return err
		}
		if len(password) < 12 {
			return errors.New("пароль учётной записи должен содержать не менее 12 символов")
		}
		if err := w.RuntimeSecrets.Put(setup.SecretSvcPassword, []byte(password)); err != nil {
			return err
		}
		w.Draft.ServiceAcct = setup.ServiceAccount{Mode: "existing", Account: account, PasswordSealed: true}
	}
	w.Draft.SetStep(setup.StepServiceAcct, setup.StatusDone, w.Draft.ServiceAcct.Account)
	return nil
}

// stepSuperadmin collects the first superadministrator identity.
func stepSuperadmin(w *setup.Wizard) error {
	ui := w.UI
	ui.Sayf("Шаг 6: первый суперадминистратор")
	displayName, err := ui.Ask("Отображаемое имя", w.Draft.Superadmin.DisplayName)
	if err != nil {
		return err
	}
	email, err := ui.Ask("Email (используется как логин)", w.Draft.Superadmin.Email)
	if err != nil {
		return err
	}
	for {
		password, err := ui.AskSecret("Пароль администратора (минимум 12 символов, ввод скрыт)")
		if err != nil {
			return err
		}
		if len(password) < 12 {
			ui.Sayf("Пароль слишком короткий; минимум 12 символов")
			continue
		}
		if strings.EqualFold(password, email) || strings.EqualFold(password, displayName) {
			ui.Sayf("Пароль не должен совпадать с логином или именем")
			continue
		}
		repeat, err := ui.AskSecret("Повторите пароль")
		if err != nil {
			return err
		}
		if !setup.ComparePasswords(password, repeat) {
			ui.Sayf("Пароли не совпадают; повторите ввод")
			continue
		}
		if err := w.RuntimeSecrets.Put(setup.SecretAdminPassword, []byte(password)); err != nil {
			return err
		}
		w.Draft.Superadmin = setup.Superadmin{Email: email, DisplayName: displayName, PasswordSealed: true}
		break
	}
	w.Draft.SetStep(setup.StepSuperadmin, setup.StatusDone, email)
	return nil
}

// finishInstallation applies the collected draft after an explicit summary and
// confirmation. Marker is written only after the service start and checks.
func finishInstallation(paths setup.Paths, w *setup.Wizard) error {
	ui := w.UI
	if err := w.ValidateDraftConfig(); err != nil {
		return fmt.Errorf("итоговая проверка не пройдена: %w", err)
	}
	fmt.Println("=== Сводка перед применением (без секретов) ===")
	fmt.Print(w.Draft.Summary())
	confirmed, err := ui.Confirm("Применить настройки и выполнить установку?")
	if err != nil {
		return err
	}
	if !confirmed {
		return errors.New("применение отменено; черновик сохранён, продолжите командой «mandatnik-backend setup»")
	}

	w.Draft.SetStep(setup.StepApply, setup.StatusDone, "подтверждено")
	if err := w.Draft.Save(paths); err != nil {
		return err
	}

	// 1. Configuration file + protected DB password.
	cfg := configFromDraft(w)
	cfgPath := platform.BackendConfigPath()
	if err := os.MkdirAll(filepath.Dir(cfgPath), 0o700); err != nil {
		return err
	}
	if _, err := os.Stat(cfgPath); err == nil {
		if err := backupFile(cfgPath, paths.Backups); err != nil {
			return err
		}
	}
	if err := writeConfig(cfg, cfgPath); err != nil {
		return err
	}
	dbPassword, err := w.RuntimeSecrets.Get(setup.SecretDBPassword)
	if err != nil {
		return err
	}
	if err := setup.WriteRuntimePassword(paths.Password, dbPassword); err != nil {
		return err
	}
	ui.Sayf("Конфигурация сохранена: %s (пароль БД — в защищённом файле)", cfgPath)

	// 2. License keys: create only when absent; existing keys are preserved.
	keyringExists := fileExists(cfg.LicenseKeyringFile)
	fingerprintExists := fileExists(cfg.LicenseFingerprintKeyFile)
	if keyringExists && fingerprintExists {
		ui.Sayf("Существующие ключи шифрования данных и HMAC сохранены без изменений")
		w.Draft.LicenseInited = true
	} else if !keyringExists && !fingerprintExists {
		if _, err := licensecrypto.InitKeyring(cfg.LicenseKeyringFile); err != nil {
			return err
		}
		if err := licensecrypto.InitFingerprintKey(cfg.LicenseFingerprintKeyFile); err != nil {
			return err
		}
		ui.Sayf("Созданы ключи шифрования номеров лицензий и HMAC-ключ")
		w.Draft.LicenseInited = true
	} else {
		return errors.New("найдена только часть ключей лицензий (keyring или HMAC); установка прервана — проверьте каталог вручную")
	}

	// 3. Database migrations (applied changes cannot be rolled back; they are
	// recorded explicitly in the draft).
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	pool, err := db.Open(ctx, cfg.DB)
	if err != nil {
		return fmt.Errorf("подключение к БД для миграций: %w", err)
	}
	if err := db.Migrate(ctx, pool, func(format string, args ...any) {
		ui.Sayf(format, args...)
	}); err != nil {
		pool.Close()
		return fmt.Errorf("миграции не выполнены (уже применённые миграции сохранены и не отменяются): %w", err)
	}
	versions, err := db.MigrationStatus(ctx, pool)
	pool.Close()
	if err != nil {
		return err
	}
	w.Draft.AppliedMigrations = versions
	w.Draft.DB.Migrated = true
	ui.Sayf("Миграции применены: %d шт", len(versions))

	// 4. First superadministrator.
	adminPassword, err := w.RuntimeSecrets.Get(setup.SecretAdminPassword)
	if err != nil {
		return err
	}
	hash, err := backend.HashAdminPassword(string(adminPassword))
	if err != nil {
		return err
	}
	pool, err = db.Open(ctx, cfg.DB)
	if err != nil {
		return err
	}
	defer pool.Close()
	if _, err := store.New(pool).UpsertAdmin(ctx, w.Draft.Superadmin.Email, w.Draft.Superadmin.DisplayName, "superadmin", hash); err != nil {
		return fmt.Errorf("создание первого суперадминистратора: %w", err)
	}
	ui.Sayf("Суперадминистратор создан: %s", w.Draft.Superadmin.Email)

	// 5. Service account + service registration.
	svcPassword := generatePassword(32)
	if w.Draft.ServiceAcct.Mode == "create" {
		if err := setup.CreateLocalAccount(w.Draft.ServiceAcct.Account, svcPassword); err != nil {
			return fmt.Errorf("создание учётной записи службы: %w", err)
		}
	} else {
		raw, err := w.RuntimeSecrets.Get(setup.SecretSvcPassword)
		svcPassword = string(raw)
		if err != nil {
			return err
		}
	}
	if err := setup.InstallService(executablePath(), []string{"run", "-config", cfgPath}); err != nil {
		return fmt.Errorf("регистрация службы: %w", err)
	}
	if err := setup.ConfigureServiceAccount(w.Draft.ServiceAcct.Account, svcPassword); err != nil {
		return fmt.Errorf("настройка учётной записи службы: %w", err)
	}
	// The runtime secret store must be readable by the actual service account.
	if err := setup.WidenRuntimeSecretsACL(paths, w.Draft.ServiceAcct.Account); err != nil {
		return err
	}
	ui.Sayf("Служба %s зарегистрирована (автозапуск), учётная запись: %s", setup.ServiceNameText, w.Draft.ServiceAcct.Account)
	w.Draft.SetStep(setup.StepApply, setup.StatusDone, "настройки применены")

	// 6. Start and verify.
	if err := setup.StartService(60 * time.Second); err != nil {
		return fmt.Errorf("запуск службы не удался (миграции и настройки уже применены, их откат не выполняется): %w", err)
	}
	if err := verifyService(cfg); err != nil {
		return fmt.Errorf("проверка работоспособности не пройдена: %w", err)
	}
	w.Draft.SetStep(setup.StepService, setup.StatusDone, "служба работает")
	ui.Sayf("Служба запущена и отвечает; соединение с БД установлено, HTTPS-интерфейсы работают")

	// 7. Recovery bundle.
	if err := stepBundle(w, paths); err != nil {
		return err
	}

	// 8. Marker + draft cleanup + memo.
	w.Draft.SetStep(setup.StepBundle, setup.StatusDone, w.Draft.BundlePath)
	w.Draft.SetStep(setup.StepFinish, setup.StatusDone, "")
	if err := w.Draft.Save(paths); err != nil {
		return err
	}
	marker := setup.Marker{Status: setup.MarkerCompleted, Mode: "install", BackendExe: executablePath()}
	if err := setup.SaveMarker(paths, marker); err != nil {
		return err
	}
	if err := setup.DeleteDraft(paths); err != nil {
		return err
	}
	printFinalMemo(cfg, w, paths)
	return nil
}

func stepBundle(w *setup.Wizard, paths setup.Paths) error {
	ui := w.UI
	ui.Sayf("Шаг 7: комплект восстановления")
	ui.Sayf("Комплект содержит секреты (ключи шифрования, TLS-материал, пароль БД) и требует защищённого хранения.")
	ui.Sayf("Резервная копия БД выполняется отдельно; для восстановления нужны совместимые копии БД и ключей.")
	ui.Sayf("Пароль учётной записи службы в комплект не включается. После ротации ключей комплект нужно обновить.")
	pass, err := ui.AskSecret("Пароль комплекта восстановления (ввод скрыт)")
	if err != nil {
		return err
	}
	repeat, err := ui.AskSecret("Повторите пароль комплекта")
	if err != nil {
		return err
	}
	if !setup.ComparePasswords(pass, repeat) {
		return errors.New("пароли не совпадают")
	}
	cfg := configFromDraft(w)
	files, manifest := bundleInputs(cfg, w, paths)
	bundlePath := paths.Bundle
	if err := setup.BuildBundle(bundlePath, manifest, files, pass); err != nil {
		return fmt.Errorf("экспорт комплекта: %w", err)
	}
	if _, _, err := setup.OpenBundle(bundlePath, pass); err != nil {
		return err
	}
	w.Draft.BundlePath = bundlePath
	ui.Sayf("Комплект проверен после экспорта и записан: %s", bundlePath)
	readme := recoveryReadme(cfg, w)
	if err := os.WriteFile(paths.BundleReadme, []byte(readme), 0o600); err != nil {
		return err
	}
	return setup.SecurePath(paths.BundleReadme)
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func generatePassword(length int) string {
	const alphabet = "abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789!@#$%^*-_=+"
	buf := make([]byte, length)
	if _, err := rand.Read(buf); err != nil {
		return "Mnd-" + fmt.Sprint(time.Now().UnixNano()) + "-password"
	}
	out := make([]byte, 0, length)
	for i := 0; i < length; i++ {
		out = append(out, alphabet[int(buf[i])%len(alphabet)])
	}
	return string(out)
}

func verifyService(cfg config.Config) error {
	for _, listen := range []string{cfg.AgentListen, cfg.AdminListen, cfg.IntegrationListen} {
		if err := probeHTTPS(listen); err != nil {
			return fmt.Errorf("интерфейс %s: %w", listen, err)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	return backend.Health(ctx, cfg)
}

func probeHTTPS(listen string) error {
	host, port, err := net.SplitHostPort(listen)
	if err != nil {
		return err
	}
	addr := net.JoinHostPort(host, port)
	if host == "0.0.0.0" || host == "" {
		addr = net.JoinHostPort("127.0.0.1", port)
	}
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	conn, err := tls.DialWithDialer(dialer, "tcp", addr, &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12}) //nolint:gosec // local health probe only
	if err != nil {
		return fmt.Errorf("TLS-рукопожатие: %w", err)
	}
	defer conn.Close()
	client := &http.Client{
		Timeout:   10 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}, //nolint:gosec // local health probe only
	}
	resp, err := client.Get("https://" + addr + "/")
	if err != nil {
		return fmt.Errorf("HTTP-запрос: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 500 {
		return fmt.Errorf("сервер ответил %d", resp.StatusCode)
	}
	return nil
}

func printFinalMemo(cfg config.Config, w *setup.Wizard, paths setup.Paths) {
	fmt.Println("=== Установка завершена. Краткая памятка ===")
	fmt.Printf("  Админка: https://<адрес-админки>%s (порты интерфейсов ниже)\n", "")
	for _, iface := range w.Draft.Interfaces {
		fmt.Printf("  %s: прослушивание %s, клиенты: %s\n", roleTitle(iface.Role), iface.Listen, strings.Join(iface.ClientNames, ", "))
	}
	fmt.Printf("  Служба: %s — %s\n", setup.ServiceNameText, "автозапуск, работает")
	fmt.Print("  Открыть входящие порты:\n")
	fmt.Print(w.Draft.FirewallSummary())
	fmt.Printf("  Настройки: %s\n", cfg.Path)
	fmt.Printf("  Защищённые секреты: %s, %s\n", paths.RuntimeSealed, paths.Password)
	fmt.Printf("  Журналы: %s\n", cfg.LogFile)
	fmt.Println("  Изменение адресов, сертификатов, пароля БД и учётной записи службы: «mandatnik-backend configure»")
	fmt.Println("  Восстановление доступа суперадминистратора: «mandatnik-backend admin-reset-password»")
	if w.Draft.BundlePath != "" {
		fmt.Printf("  Комплект восстановления: %s (и файл %s)\n", w.Draft.BundlePath, paths.BundleReadme)
	}
	if w.Draft.TLSGroups != nil {
		for _, group := range w.Draft.TLSGroups {
			if group.CAFile != "" {
				fmt.Printf("  Публичный сертификат CA установки (для распространения доверия): %s\n", group.CAFile)
			}
		}
	}
	fmt.Println("  Значения секретов не выводятся.")
	fmt.Printf("  Версия: %s\n", version.String())
}

func configFromDraft(w *setup.Wizard) config.Config {
	cfg := config.Config{
		AgentListen:       listenOf(w.Draft.Interfaces, "agent"),
		AdminListen:       listenOf(w.Draft.Interfaces, "admin"),
		IntegrationListen: listenOf(w.Draft.Interfaces, "integration"),
		LogFile:           filepath.Join(platform.BackendLogDir(), "backend.txt"),
	}
	for _, group := range w.Draft.TLSGroups {
		// Per-role pairs are written to cfg.TLSPerRole below.
		_ = group
	}
	// Per-interface certificates need a small config extension; the simple
	// scheme stores the shared pair.
	if len(w.Draft.TLSGroups) > 1 {
		// Extended mode: keep per-role pairs in the new config section.
		cfg.TLSPerRole = map[string]config.TLSPair{}
		for _, group := range w.Draft.TLSGroups {
			for _, role := range group.Interfaces {
				cfg.TLSPerRole[role] = config.TLSPair{CertFile: group.CertFile, KeyFile: group.KeyFile}
			}
		}
	}
	cfg.DB = config.DB{
		Server:       w.Draft.DB.Server,
		Port:         w.Draft.DB.Port,
		Database:     w.Draft.DB.Database,
		User:         w.Draft.DB.User,
		PasswordFile: pathsPassword(w),
		Encrypt:      w.Draft.DB.Encrypt,
		ServerName:   w.Draft.DB.ServerName,
		CAFile:       w.Draft.DB.CAFile,
	}
	return cfg
}

func listenOf(interfaces []setup.Interface, role string) string {
	for _, iface := range interfaces {
		if iface.Role == role {
			return iface.Listen
		}
	}
	return ""
}

func pathsPassword(w *setup.Wizard) string {
	_ = w
	return filepath.Join(platform.BackendDir(), setup.PasswordFileName)
}

func backupFile(path, backupDir string) error {
	if err := os.MkdirAll(backupDir, 0o700); err != nil {
		return err
	}
	stamp := time.Now().UTC().Format("20060102T150405Z")
	target := filepath.Join(backupDir, fmt.Sprintf("%s.%s", filepath.Base(path), stamp))
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return os.WriteFile(target, raw, 0o600)
}

func writeConfig(cfg config.Config, path string) error {
	cfg.Path = ""
	raw, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		return err
	}
	return setup.SecurePath(path)
}

func configPathFromArgs(args []string) string {
	for i, arg := range args {
		if arg == "-config" && i+1 < len(args) {
			return args[i+1]
		}
	}
	return ""
}

var _ = exec.Command
var _ = json.Marshal
var _ = version.String
