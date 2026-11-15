package agent

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"mandatnik/internal/platform"
	"mandatnik/internal/protocol"
)

// registrationNotice is deliberately stored outside state.json. Older agents
// use DisallowUnknownFields for state.json; a downgrade must not fail only
// because a newer agent wrote a pending-confirmation marker.
type registrationNotice struct {
	State     string `json:"state,omitempty"`
	RequestID string `json:"request_id,omitempty"`
	Message   string `json:"message,omitempty"`
	UpdatedAt string `json:"updated_at"`
}

func registrationNoticePath() string {
	return filepath.Join(platform.AgentDir(), "registration-state.json")
}

func loadRegistrationNotice() (registrationNotice, error) {
	var notice registrationNotice
	raw, err := os.ReadFile(registrationNoticePath())
	if err != nil {
		if os.IsNotExist(err) {
			return notice, nil
		}
		return notice, err
	}
	if err := protocol.RejectDuplicateKeys(raw); err != nil {
		return notice, fmt.Errorf("registration-state.json: %w", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&notice); err != nil {
		return notice, fmt.Errorf("decode registration-state.json: %w", err)
	}
	return notice, nil
}

func saveRegistrationNotice(notice registrationNotice) error {
	if notice.State == "" && notice.RequestID == "" && notice.Message == "" {
		if err := os.Remove(registrationNoticePath()); err != nil && !os.IsNotExist(err) {
			return err
		}
		return nil
	}
	notice.UpdatedAt = time.Now().UTC().Format(time.RFC3339Nano)
	raw, err := json.MarshalIndent(notice, "", "  ")
	if err != nil {
		return err
	}
	if err := writeFileAtomic(registrationNoticePath(), raw, 0o600); err != nil {
		return err
	}
	return securePath(registrationNoticePath())
}
