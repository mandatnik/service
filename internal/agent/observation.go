package agent

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"

	"telehack2026/internal/certparse"
	"telehack2026/internal/protocol"
)

// observeDER converts DER into the wire observation. If field parsing fails,
// the certificate is still reported by hash/DER with ParseError filled; the
// caller must mark the source incomplete so no removal is inferred.
func observeDER(der []byte) (protocol.ObservedCertificate, error) {
	sum := sha256.Sum256(der)
	observation := protocol.ObservedCertificate{
		SHA256:    hex.EncodeToString(sum[:]),
		DERBase64: base64.StdEncoding.EncodeToString(der),
	}
	parsed, err := certparse.Parse(der)
	if err != nil {
		observation.ParseError = err.Error()
		return observation, err
	}
	observation.SerialHex = parsed.SerialHex
	observation.SerialNumber = parsed.SerialNumber
	observation.Subject = parsed.SubjectString
	observation.Issuer = parsed.IssuerString
	observation.NotBefore = parsed.NotBefore.UTC().Format("2006-01-02T15:04:05Z07:00")
	observation.NotAfter = parsed.NotAfter.UTC().Format("2006-01-02T15:04:05Z07:00")
	observation.OwnerCN = parsed.Subject.CommonName()
	observation.INN = parsed.AttributeString(certparse.OIDINN)
	observation.SNILS = parsed.AttributeString(certparse.OIDSNILS)
	observation.PublicKeyBits = parsed.PublicKeyBits
	observation.SignatureAlgorithm = certparse.SignatureAlgorithmName(parsed.SignatureAlgorithm)
	if parsed.EmbeddedLicense {
		observation.EmbeddedLicense = "present"
	} else {
		observation.EmbeddedLicense = "absent"
	}
	return observation, nil
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
