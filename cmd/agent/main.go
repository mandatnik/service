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
	switch os.Args[1] {
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
	case "install":
		fs := flag.NewFlagSet("install", flag.ExitOnError)
		config := fs.String("config", "", "path to agent-config.json (default: ProgramData)")
		_ = fs.Parse(os.Args[2:])
		if err := agent.InstallService(*config); err != nil {
			fmt.Fprintln(os.Stderr, "install:", err)
			os.Exit(1)
		}
		fmt.Println("service installed:", agent.ServiceName)
	case "uninstall":
		fs := flag.NewFlagSet("uninstall", flag.ExitOnError)
		purge := fs.Bool("purge", false, "remove agent identity, queue and logs")
		_ = fs.Parse(os.Args[2:])
		if err := agent.UninstallService(*purge); err != nil {
			fmt.Fprintln(os.Stderr, "uninstall:", err)
			os.Exit(1)
		}
		fmt.Println("service removed")
	case "start", "stop":
		var err error
		if os.Args[1] == "start" {
			err = agent.StartService()
		} else {
			err = agent.StopService()
		}
		if err != nil {
			fmt.Fprintln(os.Stderr, os.Args[1]+":", err)
			os.Exit(1)
		}
		fmt.Println("ok")
	case "status":
		info, err := agent.QueryService()
		if err != nil {
			fmt.Fprintln(os.Stderr, "status:", err)
			os.Exit(1)
		}
		fmt.Printf("%s %s pid=%d\n", info.Name, info.State, info.ProcessID)
		if info.BinaryPath != "" {
			fmt.Println(info.BinaryPath)
		}
	case "diag":
		text, err := agent.Diagnostics()
		if err != nil {
			fmt.Fprintln(os.Stderr, "diag:", err)
			os.Exit(1)
		}
		fmt.Print(text)
	case "reset-identity":
		fs := flag.NewFlagSet("reset-identity", flag.ExitOnError)
		confirm := fs.Bool("confirm", false, "confirm archiving the current identity")
		_ = fs.Parse(os.Args[2:])
		if !*confirm {
			fmt.Fprintln(os.Stderr, "reset-identity requires --confirm")
			os.Exit(2)
		}
		backup, err := agent.ResetIdentity()
		if err != nil {
			fmt.Fprintln(os.Stderr, "reset-identity:", err)
			os.Exit(1)
		}
		fmt.Println("identity archived to", backup)
	case "help", "-h", "--help":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n", os.Args[1])
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Print(`telehack-agent - Windows service certificate and CryptoPro inventory agent

Usage:
  telehack-agent.exe version
  telehack-agent.exe install [-config PATH]
  telehack-agent.exe uninstall [-purge]
  telehack-agent.exe run [-config PATH]
  telehack-agent.exe start | stop | status | diag
  telehack-agent.exe reset-identity --confirm

Normal operation requires no CLI after install. The command set does not add
inbound ports or change user certificate stores.
`)
}
