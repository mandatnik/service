package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

type evidence struct {
	StartedAt  time.Time       `json:"started_at"`
	FinishedAt time.Time       `json:"finished_at"`
	ServerURL  string          `json:"server_url"`
	Results    []evidenceCheck `json:"results"`
}

type evidenceCheck struct {
	Name   string         `json:"name"`
	OK     bool           `json:"ok"`
	Error  string         `json:"error,omitempty"`
	Detail map[string]any `json:"detail,omitempty"`
}

func newEvidence(serverURL string) *evidence {
	return &evidence{StartedAt: time.Now().UTC(), ServerURL: serverURL}
}

func (e *evidence) add(name string, ok bool, detail map[string]any, err error) {
	check := evidenceCheck{Name: name, OK: ok, Detail: detail}
	if err != nil {
		check.Error = err.Error()
	}
	e.Results = append(e.Results, check)
	status := "PASS"
	if !ok {
		status = "FAIL"
	}
	fmt.Printf("%-4s %s", status, name)
	if err != nil {
		fmt.Printf(": %v", err)
	}
	fmt.Println()
}

func (e *evidence) failed() int {
	count := 0
	for _, result := range e.Results {
		if !result.OK {
			count++
		}
	}
	return count
}

func (e *evidence) write(directory string) (string, error) {
	e.FinishedAt = time.Now().UTC()
	if err := os.MkdirAll(directory, 0o755); err != nil {
		return "", err
	}
	name := "contract-" + time.Now().UTC().Format("20060102T150405Z") + ".json"
	path := filepath.Join(directory, name)
	raw, err := json.MarshalIndent(e, "", "  ")
	if err != nil {
		return "", err
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		return "", err
	}
	return path, nil
}
