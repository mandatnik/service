package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"mandatnik/internal/backend/config"
)

type acceptanceConfig struct {
	ServerURL   string    `json:"server_url"`
	CAFile      string    `json:"ca_file"`
	EvidenceDir string    `json:"evidence_dir"`
	DB          config.DB `json:"db"`
}

func loadAcceptanceConfig(path string) (acceptanceConfig, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return acceptanceConfig{}, err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var cfg acceptanceConfig
	if err := decoder.Decode(&cfg); err != nil {
		return acceptanceConfig{}, err
	}
	if cfg.ServerURL == "" {
		return cfg, fmt.Errorf("server_url is required")
	}
	if cfg.EvidenceDir == "" {
		cfg.EvidenceDir = "evidence/acceptance"
	}
	if err := cfg.DB.Validate(); err != nil {
		return cfg, fmt.Errorf("db: %w", err)
	}
	return cfg, nil
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: acceptance contract -config acceptance.json [-evidence DIR]")
		os.Exit(2)
	}
	switch os.Args[1] {
	case "contract":
		fs := flag.NewFlagSet("contract", flag.ExitOnError)
		configPath := fs.String("config", "acceptance.json", "acceptance JSON")
		evidenceDir := fs.String("evidence", "", "override evidence directory")
		_ = fs.Parse(os.Args[2:])
		cfg, err := loadAcceptanceConfig(*configPath)
		if err != nil {
			fmt.Fprintln(os.Stderr, "config:", err)
			os.Exit(1)
		}
		if *evidenceDir != "" {
			cfg.EvidenceDir = *evidenceDir
		}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
		defer cancel()
		if err := runContract(ctx, cfg); err != nil {
			fmt.Fprintln(os.Stderr, "contract:", err)
			os.Exit(1)
		}
	case "config":
		fs := flag.NewFlagSet("config", flag.ExitOnError)
		configPath := fs.String("config", "acceptance.json", "acceptance JSON")
		interval := fs.Int("interval", 1, "scan interval in days")
		dirs := fs.String("dirs", "", "semicolon-separated certificate directories")
		recursive := fs.Bool("recursive", true, "scan directories recursively")
		_ = fs.Parse(os.Args[2:])
		cfg, err := loadAcceptanceConfig(*configPath)
		if err != nil {
			fmt.Fprintln(os.Stderr, "config:", err)
			os.Exit(1)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()
		if err := setStandConfig(ctx, cfg, *interval, strings.Split(*dirs, ";"), *recursive); err != nil {
			fmt.Fprintln(os.Stderr, "config:", err)
			os.Exit(1)
		}
	case "replay-prepare", "replay-check":
		fs := flag.NewFlagSet(os.Args[1], flag.ExitOnError)
		configPath := fs.String("config", "acceptance.json", "acceptance JSON")
		file := fs.String("file", "/tmp/mandatnik-replay.json", "replay state file")
		_ = fs.Parse(os.Args[2:])
		cfg, err := loadAcceptanceConfig(*configPath)
		if err != nil {
			fmt.Fprintln(os.Stderr, "config:", err)
			os.Exit(1)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()
		if os.Args[1] == "replay-prepare" {
			if err := prepareReplay(ctx, cfg, *file); err != nil {
				fmt.Fprintln(os.Stderr, "replay-prepare:", err)
				os.Exit(1)
			}
		} else {
			if err := checkReplay(ctx, cfg, *file); err != nil {
				fmt.Fprintln(os.Stderr, "replay-check:", err)
				os.Exit(1)
			}
		}
	case "proxy":
		if err := runP10Proxy(os.Args[2:]); err != nil {
			fmt.Fprintln(os.Stderr, "proxy:", err)
			os.Exit(1)
		}
	case "help", "-h", "--help":
		fmt.Println("usage: acceptance contract -config acceptance.json [-evidence DIR]")
		fmt.Println("       acceptance config -config acceptance.json -interval 1 -dirs 'C:\\certs'")
		fmt.Println("       acceptance proxy -listen 0.0.0.0:9443 -backend https://... -cert ... -key ... -ca ...")
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n", os.Args[1])
		os.Exit(2)
	}
}
