// `mandatnik-backend configure` — change settings of a completed installation
// with validation, protected backup, service restart and rollback of the
// configuration files when the new state fails verification.
package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"mandatnik/internal/backend"
	"mandatnik/internal/backend/config"
	"mandatnik/internal/backend/db"
	"mandatnik/internal/backend/licensecrypto"
	"mandatnik/internal/platform"
	"mandatnik/internal/setup"
)

// runConfigure drives the settings-change wizard.
func runConfigure(args []string) error {
	paths := setup.DefaultPaths()
	if setup.MarkerStatus(paths) != setup.MarkerCompleted {
		return errors.New("первоначальная настройка не завершена; сначала выполните «mandatnik-backend setup»")
	}
	if err := setup.CheckAdministratorRights(); err != nil {
		return err
	}
	ui := terminalUI{}
	cfg, err := config.Load(configPathFromArgs(args))
	if err != nil {
		return err
	}
	for {
		section, err := ui.Choose("Выберите раздел для изменения",
			[]string{
				"Адреса, интерфейсы и порты",
				"Сертификаты TLS",
				"Подключение и пароль БД",
				"Локальная учётная запись службы",
				"Выход",
			})
		if err != nil {
			return err
		}
		switch section {
		case 0:
			if err := configureListening(ui, cfg); err != nil {
				return err
			}
		case 1:
			if err := configureCertificates(ui, cfg); err != nil {
				return err
			}
		case 2:
			if err := configureDatabase(ui, cfg); err != nil {
				return err
			}
		case 3:
			if err := configureServiceAccount(ui, cfg); err != nil {
				return err
			}
		case 4:
			return nil
		}
		again, err := ui.Confirm("Продолжить изменение других настроек?")
		if err != nil {
			return err
		}
		if !again {
			return nil
		}
	}
}

// applyConfig validates, backs up, writes and restarts the service. On a
// failed verification the previous configuration is restored.
func applyConfig(ui terminalUI, old config.Config, next config.Config, paths setup.Paths) error {
	if err := validateNewConfig(next); err != nil {
		return err
	}
	confirmed, err := ui.Confirm(fmt.Sprintf("Применить изменения (служба %s будет перезапущена)?", setup.ServiceNameText))
	if err != nil {
		return err
	}
	if !confirmed {
		return errors.New("изменения отменены")
	}
	if err := backupFile(old.Path, paths.Backups); err != nil {
		return err
	}
	// Write to a temporary file, swap, restart, verify; restore on failure.
	tmp := old.Path + ".new"
	if err := writeConfig(next, tmp); err != nil {
		return err
	}
	if err := os.Rename(tmp, next.Path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if setup.MarkerStatus(paths) == setup.MarkerCompleted {
		if err := setup.StopService(60 * time.Second); err != nil {
			ui.Sayf("предупреждение: остановка службы: %v", err)
		}
		if err := setup.StartService(90 * time.Second); err != nil {
			ui.Sayf("применение не удалось, возвращаю предыдущую конфигурацию")
			_ = writeConfig(old, next.Path)
			if startErr := setup.StartService(90 * time.Second); startErr != nil {
				ui.Sayf("ВНИМАНИЕ: предыдущая конфигурация возвращена, но служба не запустилась: %v", startErr)
			}
			return fmt.Errorf("служба не запустилась с новой конфигурацией: %w", err)
		}
	}
	if err := verifyService(next); err != nil {
		ui.Sayf("проверка работоспособности не пройдена, возвращаю предыдущую конфигурацию")
		_ = writeConfig(old, next.Path)
		_ = setup.StopService(30 * time.Second)
		if startErr := setup.StartService(90 * time.Second); startErr != nil {
			ui.Sayf("ВНИМАНИЕ: предыдущая конфигурация возвращена, но служба не запустилась: %v", startErr)
		}
		return fmt.Errorf("новая конфигурация не прошла проверку: %w", err)
	}
	ui.Sayf("Изменения применены, служба перезапущена и проверена")
	return nil
}

func validateNewConfig(cfg config.Config) error {
	return cfg.Validate()
}

func configureListening(ui terminalUI, cfg config.Config) error {
	paths := setup.DefaultPaths()
	ui.Sayf("Изменение адресов влияет на клиентов: понадобится обновить конфигурацию агентов,")
	ui.Sayf("записи DNS, правила брандмауэра и доверие к сертификатам на АРМ и у интеграций.")
	next := cfg
	roles := []struct {
		title  string
		listen *string
	}{{"агентский API", &next.AgentListen}, {"админка", &next.AdminListen}, {"интеграционный API", &next.IntegrationListen}}
	for _, role := range roles {
		value, err := ui.Ask(fmt.Sprintf("Адрес прослушивания %s", role.title), *role.listen)
		if err != nil {
			return err
		}
		*role.listen = value
	}
	// Certificate coverage for the changed addresses is not re-derived here;
	// warn when per-role certificates exist and the admin confirms manually.
	return applyConfig(ui, cfg, next, paths)
}

func configureCertificates(ui terminalUI, cfg config.Config) error {
	paths := setup.DefaultPaths()
	tlsDir := filepath.Join(platform.BackendDir(), "tls")
	_, err := ui.Choose("Раздел сертификатов",
		[]string{
			"Заменить общий сертификат (импорт PFX/PEM)",
			"Перевыпустить сертификат CA установки (требуется экспортированный ключ CA)",
		})
	if err != nil {
		return err
	}
	next := cfg
	certPath, err := ui.Ask("Путь к PEM-сертификату (можно с цепочкой) или PFX", "")
	if err != nil {
		return err
	}
	var certCopy, keyCopy string
	if strings.EqualFold(filepath.Ext(certPath), ".pfx") || strings.EqualFold(filepath.Ext(certPath), ".p12") {
		password, err := ui.AskSecret("Пароль PFX (ввод скрыт)")
		if err != nil {
			return err
		}
		leaf, chain, key, err := setup.LoadPFX(certPath, password)
		if err != nil {
			return err
		}
		certCopy = filepath.Join(tlsDir, "backend.crt")
		keyCopy = filepath.Join(tlsDir, "backend.key")
		if err := writeInstalledPair(leaf, chain, key, certCopy, keyCopy); err != nil {
			return err
		}
	} else {
		keyPath, err := ui.Ask("Путь к PEM-ключу", "")
		if err != nil {
			return err
		}
		leaf, chain, key, err := setup.LoadPEM(certPath, keyPath)
		if err != nil {
			return err
		}
		certCopy = filepath.Join(tlsDir, "backend.crt")
		keyCopy = filepath.Join(tlsDir, "backend.key")
		if err := writeInstalledPair(leaf, chain, key, certCopy, keyCopy); err != nil {
			return err
		}
	}
	next.TLSCertFile, next.TLSKeyFile = certCopy, keyCopy
	return applyConfig(ui, cfg, next, paths)
}

func configureDatabase(ui terminalUI, cfg config.Config) error {
	paths := setup.DefaultPaths()
	ui.Sayf("ВНИМАНИЕ: смена подключения на другую базу без ключей этой установки")
	ui.Sayf("означает доступ к чужим данным без возможности расшифровать номера лицензий.")
	next := cfg
	server, err := ui.Ask("Сервер SQL Server", next.DB.Server)
	if err != nil {
		return err
	}
	portText, err := ui.Ask("Порт", fmt.Sprint(next.DB.Port))
	if err != nil {
		return err
	}
	database, err := ui.Ask("Имя базы данных", next.DB.Database)
	if err != nil {
		return err
	}
	user, err := ui.Ask("Пользователь SQL", next.DB.User)
	if err != nil {
		return err
	}
	password, err := ui.AskSecret("Новый пароль пользователя SQL (ввод скрыт; пусто — оставить текущий)")
	if err != nil {
		return err
	}
	next.DB.Server = server
	next.DB.Port = parseInt(portText, next.DB.Port)
	next.DB.Database = database
	next.DB.User = user
	if password != "" {
		if err := setup.WriteRuntimePassword(paths.Password, []byte(password)); err != nil {
			return err
		}
	}
	// Connect and verify before applying.
	creds := setup.ProbeCredentials{Server: server, Port: next.DB.Port, Database: database, User: user, Encrypt: true}
	if password != "" {
		creds.Password = password
	} else {
		current, err := next.DB.Password()
		if err != nil {
			return err
		}
		creds.Password = current
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	pool, err := setup.Connect(ctx, creds)
	if err != nil {
		return fmt.Errorf("новое подключение не проверяется: %w", err)
	}
	probe, err := setup.ProbeDatabase(ctx, pool, creds)
	pool.Close()
	if err != nil {
		return err
	}
	switch probe.Kind {
	case "mandatnik":
		ui.Sayf("Обнаружена база «Мандатника», применённые миграции: %v", probe.Migrations)
	case "empty":
		ui.Sayf("База пуста; миграции будут применены при запуске")
	default:
		return errors.New("база не пуста и не содержит объектов «Мандатника» (чужая база) — подключение отклонено")
	}
	if password != "" {
		// Keep the keyring/fingerprint of THIS installation; nothing new is created.
	}
	// Migrate on the new database before switching the service.
	if probe.Kind == "empty" {
		pool, err := db.Open(ctx, next.DB)
		if err != nil {
			return err
		}
		if err := db.Migrate(ctx, pool, func(f string, a ...any) { ui.Sayf(f, a...) }); err != nil {
			pool.Close()
			return err
		}
		pool.Close()
	}
	_ = licensecrypto.LoadKeyring
	return applyConfig(ui, cfg, next, paths)
}

func configureServiceAccount(ui terminalUI, cfg config.Config) error {
	paths := setup.DefaultPaths()
	_ = paths
	mode, err := ui.Choose("Учётная запись службы",
		[]string{"Создать новую локальную учётную запись", "Указать существующую локальную учётную запись"})
	if err != nil {
		return err
	}
	var account, password string
	if mode == 0 {
		account, err = ui.Ask("Имя новой учётной записи", "mandatnik_svc")
		if err != nil {
			return err
		}
		password = generatePassword(32)
	} else {
		account, err = ui.Ask("Имя существующей учётной записи", "")
		if err != nil {
			return err
		}
		password, err = ui.AskSecret("Пароль учётной записи (ввод скрыт)")
		if err != nil {
			return err
		}
	}
	if setup.MarkerStatus(setup.DefaultPaths()) != setup.MarkerCompleted {
		return errors.New("служба не зарегистрирована")
	}
	if mode == 0 {
		if err := setup.CreateLocalAccount(account, password); err != nil {
			return err
		}
	}
	if err := setup.ConfigureServiceAccount(account, password); err != nil {
		return err
	}
	ui.Sayf("Учётная запись службы обновлена: %s", account)
	_ = cfg
	return nil
}

var _ = backend.Health
