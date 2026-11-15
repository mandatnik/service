// Recovery bundle assembly and the printed/readable documentation of its
// exact content, plus the superadministrator recovery command.
package main

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"mandatnik/internal/backend"
	"mandatnik/internal/backend/config"
	"mandatnik/internal/backend/db"
	"mandatnik/internal/backend/licensecrypto"
	"mandatnik/internal/backend/store"
	"mandatnik/internal/platform"
	"mandatnik/internal/setup"
)

// bundleInputs collects the files for the recovery bundle. The service
// account password is deliberately excluded; everything else that is needed
// to restore data is included inside the encrypted container.
func bundleInputs(cfg config.Config, w *setup.Wizard, paths setup.Paths) ([]setup.BundleFile, *setup.BundleManifest) {
	files := []setup.BundleFile{}
	add := func(name, role, path string) {
		raw, err := os.ReadFile(path)
		if err != nil {
			return
		}
		files = append(files, setup.BundleFile{Name: name, Role: role, Size: len(raw), Data: raw})
	}
	add("backend.json", "settings", cfg.Path)
	add("license-keyring.json", "key", cfg.LicenseKeyringFile)
	add("license-fingerprint.key", "key", cfg.LicenseFingerprintKeyFile)
	add("tls-cert.crt", "certificate", cfg.TLSCertFile)
	add("tls-key.key", "key", cfg.TLSKeyFile)
	for _, group := range w.Draft.TLSGroups {
		if group.CAFile != "" {
			add("installation-ca.crt", "ca", group.CAFile)
		}
		if group.CAPrivateID != "" {
			add("installation-ca.key.enc", "ca", group.CAPrivateID)
		}
	}
	// The DB password: required to restore (secrets belong only inside the
	// encrypted bundle, never in the plaintext config).
	if raw, err := w.RuntimeSecrets.Get(setup.SecretDBPassword); err == nil {
		files = append(files, setup.BundleFile{Name: "db-password.txt", Role: "secret", Size: len(raw), Data: raw})
	}
	caKeyInBundle := false
	for _, f := range files {
		if f.Name == "installation-ca.key.enc" {
			caKeyInBundle = true
		}
	}
	manifest := &setup.BundleManifest{
		ContainsCAKey:           caKeyInBundle,
		ContainsServicePassword: false,
		BackendExe:              executablePath(),
	}
	return files, manifest
}

// recoveryReadme is the human-readable memo stored next to the bundle.
func recoveryReadme(cfg config.Config, w *setup.Wizard) string {
	var b strings.Builder
	b.WriteString("Комплект восстановления «Мандатник»\n\n")
	b.WriteString("Состав комплекта:\n")
	b.WriteString("  backend.json              — конфигурация бэкенда (без секретов)\n")
	b.WriteString("  license-keyring.json      — keyring шифрования номеров лицензий\n")
	b.WriteString("  license-fingerprint.key   — HMAC-ключ дедупликации\n")
	b.WriteString("  tls-cert.crt / tls-key.key— TLS-материал бэкенда\n")
	if w.Draft.BundleCAKey {
		b.WriteString("  installation-ca.crt / installation-ca.key.enc — CA установки (ключ зашифрован своим паролем)\n")
	}
	b.WriteString("  db-password.txt           — пароль SQL-учётной записи\n")
	b.WriteString("Пароль учётной записи Windows-службы в комплект НЕ включается.\n\n")
	b.WriteString("Правила:\n")
	b.WriteString("  1. Комплект содержит секреты: храните файл и пароль раздельно и в защищённых местах.\n")
	b.WriteString("  2. Резервная копия БД выполняется отдельно от комплекта.\n")
	b.WriteString("  3. Для восстановления нужны совместимые копии БД и ключей из этого комплекта.\n")
	b.WriteString("  4. После ротации ключей (license-keyring-rotate, смена сертификатов) комплект необходимо обновить.\n\n")
	fmt.Fprintf(&b, "Расположение настроек: %s\n", cfg.Path)
	fmt.Fprintf(&b, "Расположение журналов: %s\n", cfg.LogFile)
	fmt.Fprintf(&b, "Комплект: %s\n", w.Draft.BundlePath)
	return b.String()
}

// runAdminReset implements `mandatnik-backend admin-reset-password`.
func runAdminReset(args []string) error {
	if err := setup.CheckAdministratorRights(); err != nil {
		return err
	}
	configPath := configPathFromArgs(args)
	cfg, err := config.Load(configPath)
	if err != nil {
		return err
	}
	if err := gateSetup(cfg); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	pool, err := db.Open(ctx, cfg.DB)
	if err != nil {
		return err
	}
	defer pool.Close()

	var email string
	for i, arg := range args {
		if arg == "-email" && i+1 < len(args) {
			email = args[i+1]
		}
	}
	target, err := setup.ResolveSuperadmin(ctx, pool, email)
	if err != nil {
		if strings.Contains(err.Error(), "несколько") || strings.Contains(err.Error(), "укажите") {
			list, listErr := setup.ListSuperadmins(ctx, pool)
			if listErr == nil {
				fmt.Println("Доступные суперадминистраторы:")
				for _, entry := range list {
					fmt.Printf("  %s (%s)\n", entry.Email, entry.DisplayName)
				}
			}
		}
		return err
	}
	ui := terminalUI{}
	fmt.Printf("Выбран суперадминистратор: %s (%s)\n", target.Email, target.DisplayName)
	for {
		password, err := ui.AskSecret("Новый пароль (минимум 12 символов, ввод скрыт)")
		if err != nil {
			return err
		}
		if len(password) < 12 {
			fmt.Println("Пароль слишком короткий; минимум 12 символов")
			continue
		}
		repeat, err := ui.AskSecret("Повторите новый пароль")
		if err != nil {
			return err
		}
		if !setup.ComparePasswords(password, repeat) {
			fmt.Println("Пароли не совпадают; повторите ввод")
			continue
		}
		hash, err := backend.HashAdminPassword(password)
		if err != nil {
			return err
		}
		if err := setup.ResetSuperadminPassword(ctx, pool, target.ID, hash); err != nil {
			return err
		}
		fmt.Println("Пароль изменён, активные сессии пользователя завершены, запись аудита создана.")
		fmt.Println("Старый пароль и его хеш не отображаются.")
		return nil
	}
}

func gateSetup(cfg config.Config) error {
	paths := setup.DefaultPaths()
	if setup.MarkerStatus(paths) != setup.MarkerCompleted {
		return fmt.Errorf("первоначальная настройка не завершена; выполните «mandatnik-backend setup»")
	}
	_ = cfg
	return nil
}

// initLicenseKeysIfMissing creates license keys only when absent (wizard path).
func initLicenseKeysIfMissing(cfg config.Config) (bool, error) {
	keyringExists := fileExists(cfg.LicenseKeyringFile)
	fingerprintExists := fileExists(cfg.LicenseFingerprintKeyFile)
	if keyringExists && fingerprintExists {
		return false, nil
	}
	if keyringExists || fingerprintExists {
		return false, fmt.Errorf("найдена только часть ключей лицензий; проверьте каталог")
	}
	if _, err := licensecrypto.InitKeyring(cfg.LicenseKeyringFile); err != nil {
		return false, err
	}
	return true, licensecrypto.InitFingerprintKey(cfg.LicenseFingerprintKeyFile)
}

var _ = sql.ErrNoRows
var _ = store.AdminRoleSuperAdmin
var _ = platform.BackendDir
var _ = filepath.Join
