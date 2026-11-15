package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"time"

	"mandatnik/internal/platform"
	"mandatnik/internal/setup"

	"mandatnik/internal/backend"
	"mandatnik/internal/backend/config"
	"mandatnik/internal/version"
)

// gateRun refuses a plain start when the installation is not completed and
// points to the wizard; existing pre-wizard installations keep running.
func gateRun() error {
	paths := setup.DefaultPaths()
	if setup.MarkerStatus(paths) == setup.MarkerNone {
		// Legacy compatibility: no marker, but a working backend.json means
		// the installation predates the wizard and keeps working.
		if _, err := os.Stat(platform.BackendConfigPath()); err == nil {
			fmt.Fprintln(os.Stderr, "backend: обнаружена существующая установка без маркера мастера; она продолжает работать. Для новых возможностей выполните «mandatnik-backend setup --adopt».")
			return nil
		}
		return fmt.Errorf("первоначальная настройка не выполнена; запустите «mandatnik-backend setup»")
	}
	if setup.MarkerStatus(paths) == setup.MarkerDraft {
		return fmt.Errorf("установка не завершена: есть незавершённый черновик; выполните «mandatnik-backend setup», чтобы продолжить, или удалите черновик по подсказке мастера")
	}
	return nil
}

func serviceInstall(args []string) error {
	if err := setup.CheckAdministratorRights(); err != nil {
		return err
	}
	cfgPath := configPathFromArgs(args)
	if cfgPath == "" {
		cfgPath = platform.BackendConfigPath()
	}
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	return setup.InstallService(exe, []string{"run", "-config", cfgPath})
}

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	configPath := func(args []string) string {
		fs := flag.NewFlagSet("backend", flag.ExitOnError)
		config := fs.String("config", "", "path to backend.json (default: ProgramData)")
		_ = fs.Parse(args)
		return *config
	}
	switch os.Args[1] {
	case "version", "-version", "--version":
		fmt.Println(version.String())
	case "run":
		if err := gateRun(); err != nil {
			fmt.Fprintln(os.Stderr, "backend:", err)
			os.Exit(1)
		}
		if err := backend.RunPlatform(configPath(os.Args[2:])); err != nil {
			fmt.Fprintln(os.Stderr, "backend:", err)
			os.Exit(1)
		}
	case "setup":
		if err := runSetup(os.Args[2:]); err != nil {
			fmt.Fprintln(os.Stderr, "setup:", err)
			os.Exit(1)
		}
	case "configure":
		if err := runConfigure(os.Args[2:]); err != nil {
			fmt.Fprintln(os.Stderr, "configure:", err)
			os.Exit(1)
		}
	case "admin-reset-password":
		if err := runAdminReset(os.Args[2:]); err != nil {
			fmt.Fprintln(os.Stderr, "admin-reset-password:", err)
			os.Exit(1)
		}
	case "service-install":
		if err := serviceInstall(os.Args[2:]); err != nil {
			fmt.Fprintln(os.Stderr, "service-install:", err)
			os.Exit(1)
		}
	case "service-uninstall":
		if err := setup.UninstallService(); err != nil {
			fmt.Fprintln(os.Stderr, "service-uninstall:", err)
			os.Exit(1)
		}
	case "service-start":
		if err := setup.StartService(60 * time.Second); err != nil {
			fmt.Fprintln(os.Stderr, "service-start:", err)
			os.Exit(1)
		}
	case "service-stop":
		if err := setup.StopService(60 * time.Second); err != nil {
			fmt.Fprintln(os.Stderr, "service-stop:", err)
			os.Exit(1)
		}
	case "service-status":
		status, err := setup.QueryService()
		if err != nil {
			fmt.Fprintln(os.Stderr, "service-status:", err)
			os.Exit(1)
		}
		fmt.Printf("installed=%t running=%t state=%s\n", status.Installed, status.Running, status.State)
	case "bootstrap":
		if err := backend.Bootstrap(configPath(os.Args[2:])); err != nil {
			fmt.Fprintln(os.Stderr, "bootstrap:", err)
			os.Exit(1)
		}
	case "admin-create":
		args := os.Args[2:]
		fs := flag.NewFlagSet("admin-create", flag.ExitOnError)
		configPath := fs.String("config", "", "path to backend.json (default: ProgramData)")
		email := fs.String("email", "", "administrator email address")
		name := fs.String("name", "", "administrator display name")
		role := fs.String("role", "admin", "administrator role (admin or superadmin)")
		_ = fs.Parse(args)
		password := platform.Env("MANDATNIK_ADMIN_PASSWORD")
		if password == "" {
			fmt.Fprintln(os.Stderr, "admin-create: MANDATNIK_ADMIN_PASSWORD is not set")
			os.Exit(2)
		}
		if err := backend.CreateOrUpdateAdmin(*configPath, *email, *name, *role, password); err != nil {
			fmt.Fprintln(os.Stderr, "admin-create:", err)
			os.Exit(1)
		}
	case "hash-password":
		password := platform.Env("MANDATNIK_ADMIN_PASSWORD")
		if password == "" {
			fmt.Fprintln(os.Stderr, "hash-password: MANDATNIK_ADMIN_PASSWORD is not set")
			os.Exit(2)
		}
		hash, err := backend.HashAdminPassword(password)
		if err != nil {
			fmt.Fprintln(os.Stderr, "hash-password:", err)
			os.Exit(1)
		}
		fmt.Println(hash)
	case "migrate":
		if err := backend.Migrate(configPath(os.Args[2:])); err != nil {
			fmt.Fprintln(os.Stderr, "migrate:", err)
			os.Exit(1)
		}
	case "license-init":
		if err := backend.InitLicenseKeys(configPath(os.Args[2:])); err != nil {
			fmt.Fprintln(os.Stderr, "license-init:", err)
			os.Exit(1)
		}
	case "license-keyring-rotate":
		if err := backend.RotateLicenseKey(configPath(os.Args[2:])); err != nil {
			fmt.Fprintln(os.Stderr, "license-keyring-rotate:", err)
			os.Exit(1)
		}
	case "health":
		cfg, err := config.Load(configPath(os.Args[2:]))
		if err != nil {
			fmt.Fprintln(os.Stderr, "health:", err)
			os.Exit(1)
		}
		if err := backend.Health(context.Background(), cfg); err != nil {
			fmt.Fprintln(os.Stderr, "health:", err)
			os.Exit(1)
		}
		fmt.Println("ok")
	case "help", "-h", "--help":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n", os.Args[1])
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Print(`mandatnik-backend - single-process inventory backend

Usage:
  mandatnik-backend.exe version
  mandatnik-backend.exe setup [--adopt]
  mandatnik-backend.exe configure
  mandatnik-backend.exe admin-reset-password [-email EMAIL]
  mandatnik-backend.exe service-install | service-uninstall | service-start | service-stop | service-status
  mandatnik-backend.exe bootstrap [-config PATH]
  mandatnik-backend.exe migrate [-config PATH]
  mandatnik-backend.exe health [-config PATH]
  mandatnik-backend.exe admin-create -config PATH -email EMAIL -name "DISPLAY NAME" [-role admin|superadmin]
  mandatnik-backend.exe hash-password
  mandatnik-backend.exe license-init [-config PATH]
  mandatnik-backend.exe license-keyring-rotate [-config PATH]
  mandatnik-backend.exe run [-config PATH]

setup — interactive installation wizard (Windows, administrator console).
configure — change settings of a completed installation.
run refuses to start without a completed setup; the wizard is never started
implicitly. Passwords are never accepted as command-line arguments.
`)
}
