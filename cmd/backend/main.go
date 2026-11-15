package main

import (
	"context"
	"flag"
	"fmt"
	"mandatnik/internal/platform"
	"os"

	"mandatnik/internal/backend"
	"mandatnik/internal/backend/config"
	"mandatnik/internal/version"
)

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
		if err := backend.Run(configPath(os.Args[2:])); err != nil {
			fmt.Fprintln(os.Stderr, "backend:", err)
			os.Exit(1)
		}
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
  mandatnik-backend.exe bootstrap [-config PATH]
  mandatnik-backend.exe migrate [-config PATH]
  mandatnik-backend.exe health [-config PATH]
  mandatnik-backend.exe admin-create -config PATH -email EMAIL -name "DISPLAY NAME" [-role admin|superadmin]
  mandatnik-backend.exe hash-password
  mandatnik-backend.exe license-init [-config PATH]
  mandatnik-backend.exe license-keyring-rotate [-config PATH]
  mandatnik-backend.exe run [-config PATH]

Bootstrap uses MANDATNIK_SA_PASSWORD. Runtime uses the DB password referenced
by backend.json (environment variable or ACL-protected file).
admin-create and hash-password read the administrator password from
MANDATNIK_ADMIN_PASSWORD; plaintext passwords are never command-line args.
`)
}
