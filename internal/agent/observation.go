package agent

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"time"
	"unicode/utf8"

	"mandatnik/internal/certparse"
	"mandatnik/internal/protocol"
)

// observeDER converts DER into the wire observation. A parse failure still
// yields an observation by hash/DER with ParseError filled, so the server can
// record the certificate without inferring removal; the caller must mark the
// source incomplete. include=false means the DER cannot be represented in a
// protocol report at all (larger than MaxDERBytes) and must be skipped.
func observeDER(der []byte) (protocol.ObservedCertificate, bool, error) {
	sum := sha256.Sum256(der)
	observation := protocol.ObservedCertificate{
		SHA256:    hex.EncodeToString(sum[:]),
		DERBase64: base64.StdEncoding.EncodeToString(der),
	}
	if len(der) > protocol.MaxDERBytes {
		return observation, false, fmt.Errorf("DER exceeds %d bytes", protocol.MaxDERBytes)
	}
	parsed, err := certparse.Parse(der)
	if err != nil {
		observation.ParseError = boundError(err.Error())
		return observation, true, err
	}
	observation.SerialHex = parsed.SerialHex
	observation.SerialNumber = parsed.SerialNumber
	observation.Subject = truncateUTF8(parsed.SubjectString, protocol.MaxCertificateSubject)
	observation.Issuer = truncateUTF8(parsed.IssuerString, protocol.MaxCertificateSubject)
	// A certificate outside the supported timestamp range cannot be carried
	// by ValidateTimestamp. Keep it as an explicit parse error instead of
	// invalidating the whole report.
	if !supportedYear(parsed.NotBefore) || !supportedYear(parsed.NotAfter) {
		observation.ParseError = "certificate validity is outside the supported 2000..2200 range"
		return observation, true, nil
	}
	observation.NotBefore = parsed.NotBefore.UTC().Format("2006-01-02T15:04:05Z07:00")
	observation.NotAfter = parsed.NotAfter.UTC().Format("2006-01-02T15:04:05Z07:00")
	observation.OwnerCN = truncateUTF8(parsed.Subject.CommonName(), protocol.MaxCertificateSubject)
	observation.INN = truncateUTF8(parsed.AttributeString(certparse.OIDINN), protocol.MaxCertificateSubject)
	observation.SNILS = truncateUTF8(parsed.AttributeString(certparse.OIDSNILS), protocol.MaxCertificateSubject)
	observation.PublicKeyBits = parsed.PublicKeyBits
	observation.SignatureAlgorithm = certparse.SignatureAlgorithmName(parsed.SignatureAlgorithm)
	if parsed.EmbeddedLicense {
		observation.EmbeddedLicense = "present"
	} else {
		observation.EmbeddedLicense = "absent"
	}
	return observation, true, nil
}

func supportedYear(t time.Time) bool {
	return t.Year() >= 2000 && t.Year() <= 2200
}

// truncateUTF8 cuts a string to at most max bytes without splitting a rune.
func truncateUTF8(value string, max int) string {
	if len(value) <= max {
		return value
	}
	cut := max
	for cut > 0 && !utf8.RuneStart(value[cut]) {
		cut--
	}
	return value[:cut]
}

// stripWhitespace trims a BOM and surrounding whitespace from a certificate
// file. Windows tools sometimes emit UTF-8 BOMs in PEM files.
func stripWhitespace(data []byte) []byte {
	data = bytes.TrimPrefix(data, []byte{0xEF, 0xBB, 0xBF})
	// Trim only ASCII file padding, never bytes.TrimSpace: a DER certificate
	// may legitimately end with 0x0C (form feed), which unicode.IsSpace would
	// remove and corrupt the certificate.
	return bytes.Trim(data, " \t\r\n")
}
