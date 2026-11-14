package protocol

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
)

// ConfigHash returns SHA-256 over the JCS representation of the config.
func ConfigHash(cfg AgentConfig) (string, error) {
	if err := ValidateConfig(&cfg); err != nil {
		return "", err
	}
	raw, err := json.Marshal(cfg)
	if err != nil {
		return "", fmt.Errorf("marshal config: %w", err)
	}
	canonical, err := Canonicalize(raw)
	if err != nil {
		return "", fmt.Errorf("canonicalize config: %w", err)
	}
	sum := sha256.Sum256(canonical)
	return hex.EncodeToString(sum[:]), nil
}

// CanonicalConfig returns the exact JSON bytes whose hash is ConfigHash.
func CanonicalConfig(cfg AgentConfig) ([]byte, error) {
	if err := ValidateConfig(&cfg); err != nil {
		return nil, err
	}
	raw, err := json.Marshal(cfg)
	if err != nil {
		return nil, fmt.Errorf("marshal config: %w", err)
	}
	return Canonicalize(raw)
}

// LegacyConfigHash is computed over the protocol-1 projection. Old agents must
// keep receiving a body and hash they can decode with DisallowUnknownFields.
func LegacyConfigHash(cfg AgentConfig) (string, error) {
	return ConfigHash(cfg.LegacyProjection())
}

func LegacyCanonicalConfig(cfg AgentConfig) ([]byte, error) {
	return CanonicalConfig(cfg.LegacyProjection())
}

// DecodeConfig parses and validates a configuration JSON document, rejecting
// duplicate keys and unknown fields.
func DecodeConfig(raw []byte) (AgentConfig, error) {
	if err := RejectDuplicateKeys(raw); err != nil {
		return AgentConfig{}, err
	}
	var cfg AgentConfig
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&cfg); err != nil {
		return AgentConfig{}, fmt.Errorf("decode config: %w", err)
	}
	if err := ValidateConfig(&cfg); err != nil {
		return AgentConfig{}, err
	}
	return cfg, nil
}
