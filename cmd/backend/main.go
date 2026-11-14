package main

import (
	"flag"
	"fmt"
	"os"

	"telehack2026/internal/backend"
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
		config := fs.String("config", "", "path to backend.json (default: ProgramData)")
		_ = fs.Parse(os.Args[2:])
		if err := backend.Run(*config); err != nil {
			fmt.Fprintln(os.Stderr, "backend:", err)
			os.Exit(1)
		}
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
  telehack-backend.exe run [-config PATH]

Bootstrap, migration and administration commands are added in P04/P05.
`)
}
