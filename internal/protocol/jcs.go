package protocol

import (
	"fmt"

	jsoncanonicalizer "github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
)

// Canonicalize returns the RFC 8785 (JCS) canonical UTF-8 bytes of a JSON
// document. Duplicate object member names and non-UTF-8 input are rejected
// before canonicalization.
func Canonicalize(raw []byte) ([]byte, error) {
	if err := RejectDuplicateKeys(raw); err != nil {
		return nil, err
	}
	out, err := jsoncanonicalizer.Transform(raw)
	if err != nil {
		return nil, fmt.Errorf("JCS canonicalization: %w", err)
	}
	return out, nil
}
