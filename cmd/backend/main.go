package main

import (
	"context"
	"flag"
	"fmt"
	"os"

	"telehack2026/internal/backend"
	"telehack2026/internal/backend/config"
	"telehack2026/internal/version"
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
	case "migrate":
		if err := backend.Migrate(configPath(os.Args[2:])); err != nil {
			fmt.Fprintln(os.Stderr, "migrate:", err)
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
	fmt.Print(`telehack-backend - single-process inventory backend

Usage:
  telehack-backend.exe version
  telehack-backend.exe bootstrap [-config PATH]
  telehack-backend.exe migrate [-config PATH]
  telehack-backend.exe health [-config PATH]
  telehack-backend.exe run [-config PATH]

Bootstrap uses TELEHACK_SA_PASSWORD. Runtime uses the DB password referenced
by backend.json (environment variable or ACL-protected file).
`)
}
