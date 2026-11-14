package main

import (
	"flag"
	"fmt"
	"os"

	"telehack2026/internal/agent"
	"telehack2026/internal/version"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	command := os.Args[1]
	switch command {
	case "version", "-version", "--version":
		fmt.Println(version.String())
	case "run":
		fs := flag.NewFlagSet("run", flag.ExitOnError)
		config := fs.String("config", "", "path to agent-config.json (default: ProgramData)")
		_ = fs.Parse(os.Args[2:])
		if err := agent.Run(*config); err != nil {
			fmt.Fprintln(os.Stderr, "agent:", err)
			os.Exit(1)
		}
	case "help", "-h", "--help":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n", command)
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Print(`telehack-agent - Windows service certificate and CryptoPro inventory agent

Usage:
  telehack-agent.exe version
  telehack-agent.exe run [-config PATH]

The command set is extended by later implementation stages (install, status,
diagnostics, reset-identity). Normal operation requires no CLI after install.
`)
}
