// Package certparse parses the public parts of X.509 certificates, including
// GOST certificates, without verifying trust or signatures. It extracts the
// fields required for inventory: DER, SHA-256, serial, issuer, subject by OID,
// validity and the documented embedded CryptoPro license extension.
package certparse

import (
	"bytes"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"
	"unicode/utf16"
	"unicode/utf8"

	"golang.org/x/text/encoding/charmap"
)

// Documented OID of the built-in limited CryptoPro CSP license extension.
// Sources: CryptoPro forum and vendor knowledge base. This is detection of
// the extension's presence only; it is not a license validity check.
var OIDEmbeddedCryptoProLicense = asn1.ObjectIdentifier{1, 2, 643, 2, 2, 49, 2}

// Common Russian subject attribute OIDs. Names are read by OID, not by the
// localized labels displayed by CryptoAPI or .NET.
var (
	OIDINN    = asn1.ObjectIdentifier{1, 2, 643, 3, 131, 1, 1}
	OIDSNILS  = asn1.ObjectIdentifier{1, 2, 643, 100, 3}
	OIDOGRN   = asn1.ObjectIdentifier{1, 2, 643, 100, 1}
	OIDOGRNIP = asn1.ObjectIdentifier{1, 2, 643, 100, 5}
)

// Certificate contains the inventory fields extracted from a DER certificate.
type Certificate struct {
	Raw                []byte
	SHA256             string
	Serial             *big.Int
	SerialHex          string
	SerialNumber       string
	Subject            Name
	Issuer             Name
	SubjectString      string
	IssuerString       string
	NotBefore          time.Time
	NotAfter           time.Time
	SignatureAlgorithm asn1.ObjectIdentifier
	PublicKeyAlgorithm asn1.ObjectIdentifier
	PublicKeyBits      int
	IsCA               bool
	Extensions         []Extension
	EmbeddedLicense    bool
}

// Name is a parsed X.501 distinguished name.
type Name struct {
	RDNs []RDN
}

// RDN is one relative distinguished name.
type RDN struct {
	Attributes []Attribute
}

// Attribute is one type-and-value pair.
type Attribute struct {
	Type  asn1.ObjectIdentifier
	Value string
}

type algorithmIdentifier struct {
	Algorithm  asn1.ObjectIdentifier
	Parameters asn1.RawValue `asn1:"optional"`
}

type validity struct {
	NotBefore time.Time
	NotAfter  time.Time
}

type publicKeyInfo struct {
	Algorithm algorithmIdentifier
	PublicKey asn1.BitString
}

type extension struct {
	ID       asn1.ObjectIdentifier
	Critical bool `asn1:"optional"`
	Value    []byte
}

type tbsCertificate struct {
	Raw                  asn1.RawContent
	Version              int `asn1:"optional,explicit,tag:0,default:0"`
	SerialNumber         *big.Int
	Signature            algorithmIdentifier
	Issuer               asn1.RawValue
	Validity             validity
	Subject              asn1.RawValue
	SubjectPublicKeyInfo publicKeyInfo
	IssuerUniqueID       asn1.BitString `asn1:"optional,tag:1"`
	SubjectUniqueID      asn1.BitString `asn1:"optional,tag:2"`
	Extensions           []extension    `asn1:"optional,explicit,tag:3"`
}

type certificate struct {
	Raw       asn1.RawContent
	TBS       tbsCertificate
	Algorithm algorithmIdentifier
	Signature asn1.BitString
}

// Extension is a certificate extension OID/value pair.
type Extension struct {
	OID      asn1.ObjectIdentifier
	Critical bool
	Value    []byte
}

// Parse parses one DER certificate. It rejects trailing data and negative
// serial numbers. It does not check the certificate signature, chain, dates or
// revocation; inventory collection must not imply trust.
func Parse(der []byte) (*Certificate, error) {
	if len(der) == 0 {
		return nil, errors.New("empty DER")
	}
	var parsed certificate
	rest, err := asn1.Unmarshal(der, &parsed)
	if err != nil {
		return nil, fmt.Errorf("parse certificate ASN.1: %w", err)
	}
	if len(rest) != 0 {
		return nil, errors.New("trailing data after certificate DER")
	}
	if parsed.TBS.SerialNumber == nil || parsed.TBS.SerialNumber.Sign() < 0 {
		return nil, errors.New("invalid certificate serial number")
	}
	subject, err := parseName(parsed.TBS.Subject.FullBytes)
	if err != nil {
		return nil, fmt.Errorf("parse subject: %w", err)
	}
	issuer, err := parseName(parsed.TBS.Issuer.FullBytes)
	if err != nil {
		return nil, fmt.Errorf("parse issuer: %w", err)
	}
	sum := sha256.Sum256(der)
	cert := &Certificate{
		Raw:                append([]byte(nil), der...),
		SHA256:             hex.EncodeToString(sum[:]),
		Serial:             new(big.Int).Set(parsed.TBS.SerialNumber),
		SerialHex:          strings.ToLower(parsed.TBS.SerialNumber.Text(16)),
		SerialNumber:       parsed.TBS.SerialNumber.Text(10),
		Subject:            subject,
		Issuer:             issuer,
		SubjectString:      subject.String(),
		IssuerString:       issuer.String(),
		NotBefore:          parsed.TBS.Validity.NotBefore.UTC(),
		NotAfter:           parsed.TBS.Validity.NotAfter.UTC(),
		SignatureAlgorithm: parsed.Algorithm.Algorithm,
		PublicKeyAlgorithm: parsed.TBS.SubjectPublicKeyInfo.Algorithm.Algorithm,
		PublicKeyBits:      publicKeyBits(parsed.TBS.SubjectPublicKeyInfo),
	}
	for _, ext := range parsed.TBS.Extensions {
		cert.Extensions = append(cert.Extensions, Extension{
			OID:      ext.ID,
			Critical: ext.Critical,
			Value:    append([]byte(nil), ext.Value...),
		})
		switch {
		case ext.ID.Equal(OIDEmbeddedCryptoProLicense):
			cert.EmbeddedLicense = true
		case ext.ID.Equal(asn1.ObjectIdentifier{2, 5, 29, 19}):
			var bc struct {
				CA      bool `asn1:"optional"`
				PathLen int  `asn1:"optional"`
			}
			if _, err := asn1.Unmarshal(ext.Value, &bc); err == nil {
				cert.IsCA = bc.CA
			}
		}
	}
	return cert, nil
}

// ParseFile parses a PEM or DER certificate file. PEM files may contain more
// than one CERTIFICATE block; non-certificate PEM blocks are ignored, but at
// least one certificate must be present.
func ParseFile(data []byte) ([]*Certificate, error) {
	if len(data) == 0 {
		return nil, errors.New("empty certificate file")
	}
	if bytes.Contains(data, []byte("-----BEGIN")) {
		var out []*Certificate
		rest := data
		for {
			block, next := pem.Decode(rest)
			if block == nil {
				break
			}
			rest = next
			if block.Type != "CERTIFICATE" {
				continue
			}
			cert, err := Parse(block.Bytes)
			if err != nil {
				if len(out) > 0 {
					return out, err
				}
				return nil, err
			}
			out = append(out, cert)
		}
		if len(out) == 0 {
			return nil, errors.New("PEM file contains no CERTIFICATE block")
		}
		return out, nil
	}
	cert, err := Parse(data)
	if err != nil {
		return nil, err
	}
	return []*Certificate{cert}, nil
}

// FindAttribute returns the first value of an attribute OID.
func (n Name) FindAttribute(oid asn1.ObjectIdentifier) (string, bool) {
	for _, rdn := range n.RDNs {
		for _, attr := range rdn.Attributes {
			if attr.Type.Equal(oid) {
				return attr.Value, true
			}
		}
	}
	return "", false
}

// CommonName returns the CN attribute, if present.
func (n Name) CommonName() string {
	value, _ := n.FindAttribute(asn1.ObjectIdentifier{2, 5, 4, 3})
	return value
}

// String renders the name in a stable RFC 4514-like form using short labels
// and OID dotted notation for unknown attributes. Attribute order follows the
// certificate DER order.
func (n Name) String() string {
	var rdns []string
	for _, rdn := range n.RDNs {
		var attrs []string
		for _, attr := range rdn.Attributes {
			label := attributeLabel(attr.Type)
			attrs = append(attrs, label+"="+escapeDNValue(attr.Value))
		}
		if len(attrs) > 0 {
			rdns = append(rdns, strings.Join(attrs, "+"))
		}
	}
	return strings.Join(rdns, ", ")
}

// AttributeString returns a named attribute from the subject.
func (c *Certificate) AttributeString(oid asn1.ObjectIdentifier) string {
	value, _ := c.Subject.FindAttribute(oid)
	return value
}

// SerialHexLower returns the serial number as lower-case hexadecimal without
// a leading sign or zero padding, matching the test fixture manifest.
func (c *Certificate) SerialHexLower() string {
	return c.Serial.Text(16)
}

func parseName(full []byte) (Name, error) {
	var seq asn1.RawValue
	rest, err := asn1.Unmarshal(full, &seq)
	if err != nil {
		return Name{}, err
	}
	if len(rest) != 0 || seq.Tag != asn1.TagSequence || !seq.IsCompound {
		return Name{}, errors.New("name is not a sequence")
	}
	content := seq.Bytes
	var name Name
	for len(content) > 0 {
		var set asn1.RawValue
		content, err = asn1.Unmarshal(content, &set)
		if err != nil {
			return Name{}, fmt.Errorf("parse RDN set: %w", err)
		}
		if set.Tag != asn1.TagSet || !set.IsCompound {
			return Name{}, errors.New("RDN is not a set")
		}
		rdn := RDN{}
		setContent := set.Bytes
		for len(setContent) > 0 {
			var pair struct {
				Type  asn1.ObjectIdentifier
				Value asn1.RawValue
			}
			setContent, err = asn1.Unmarshal(setContent, &pair)
			if err != nil {
				return Name{}, fmt.Errorf("parse attribute: %w", err)
			}
			value, err := decodeDirectoryString(pair.Value)
			if err != nil {
				return Name{}, fmt.Errorf("decode attribute %s: %w", pair.Type.String(), err)
			}
			rdn.Attributes = append(rdn.Attributes, Attribute{Type: pair.Type, Value: value})
		}
		name.RDNs = append(name.RDNs, rdn)
	}
	return name, nil
}

func decodeDirectoryString(raw asn1.RawValue) (string, error) {
	if raw.IsCompound {
		return "", errors.New("compound directory string is unexpected")
	}
	switch raw.Tag {
	case asn1.TagUTF8String:
		if !utf8.Valid(raw.Bytes) {
			return "", errors.New("invalid UTF-8 string")
		}
		return string(raw.Bytes), nil
	case asn1.TagPrintableString, asn1.TagIA5String, asn1.TagNumericString, 20: // 20 = T61String
		if raw.Tag == 20 {
			if decoded, err := charmap.Windows1251.NewDecoder().Bytes(raw.Bytes); err == nil {
				if utf8.Valid(decoded) && containsCyrillic(string(decoded)) {
					return string(decoded), nil
				}
			}
		}
		if utf8.Valid(raw.Bytes) {
			return string(raw.Bytes), nil
		}
		runes := make([]rune, len(raw.Bytes))
		for i, b := range raw.Bytes {
			runes[i] = rune(b)
		}
		return string(runes), nil
	case asn1.TagBMPString:
		if len(raw.Bytes)%2 != 0 {
			return "", errors.New("BMPString has odd length")
		}
		units := make([]uint16, 0, len(raw.Bytes)/2)
		for i := 0; i < len(raw.Bytes); i += 2 {
			units = append(units, uint16(raw.Bytes[i])<<8|uint16(raw.Bytes[i+1]))
		}
		return string(utf16.Decode(units)), nil
	case 28: // UniversalString (UTF-32BE)
		if len(raw.Bytes)%4 != 0 {
			return "", errors.New("UniversalString has invalid length")
		}
		var b strings.Builder
		for i := 0; i < len(raw.Bytes); i += 4 {
			r := rune(raw.Bytes[i])<<24 | rune(raw.Bytes[i+1])<<16 | rune(raw.Bytes[i+2])<<8 | rune(raw.Bytes[i+3])
			b.WriteRune(r)
		}
		return b.String(), nil
	default:
		// Unknown string tag: return the raw bytes only if they are valid UTF-8;
		// otherwise use a lossless hex-free replacement would hide data, so
		// return an explicit error.
		if utf8.Valid(raw.Bytes) {
			return string(raw.Bytes), nil
		}
		return "", fmt.Errorf("unsupported ASN.1 string tag %d", raw.Tag)
	}
}

// publicKeyBits returns the cryptographic key size rather than the encoded
// BIT STRING length. GOST public keys are wrapped in an OCTET STRING and the
// curve security level is identified by the algorithm OID.
func publicKeyBits(info publicKeyInfo) int {
	switch info.Algorithm.Algorithm.String() {
	case "1.2.643.7.1.1.1.1", "1.2.643.2.2.19": // GOST 2012-256 / 2001-256
		return 256
	case "1.2.643.7.1.1.1.2": // GOST 2012-512
		return 512
	}
	bits := info.PublicKey.BitLength
	var octets []byte
	if rest, err := asn1.Unmarshal(info.PublicKey.Bytes, &octets); err == nil && len(rest) == 0 {
		bits = len(octets) * 8
	}
	return bits
}

func containsCyrillic(s string) bool {
	for _, r := range s {
		if r >= 0x0400 && r <= 0x04FF {
			return true
		}
	}
	return false
}

func attributeLabel(oid asn1.ObjectIdentifier) string {
	switch oid.String() {
	case "2.5.4.3":
		return "CN"
	case "2.5.4.6":
		return "C"
	case "2.5.4.7":
		return "L"
	case "2.5.4.8":
		return "ST"
	case "2.5.4.9":
		return "STREET"
	case "2.5.4.10":
		return "O"
	case "2.5.4.11":
		return "OU"
	case "2.5.4.5":
		return "SERIALNUMBER"
	case "2.5.4.4":
		return "SN"
	case "2.5.4.42":
		return "G"
	case "1.2.840.113549.1.9.1":
		return "E"
	case "1.2.643.3.131.1.1":
		return "INN"
	case "1.2.643.3.131.1.2":
		return "KPP"
	case "1.2.643.100.1":
		return "OGRN"
	case "1.2.643.100.4":
		return "INNLE"
	case "1.2.643.100.3":
		return "SNILS"
	case "1.2.643.100.5":
		return "OGRNIP"
	default:
		return oid.String()
	}
}

func escapeDNValue(value string) string {
	if value == "" {
		return ""
	}
	var b strings.Builder
	for i, r := range value {
		switch r {
		case ',', '+', '"', '\\', '<', '>', ';', '=':
			b.WriteByte('\\')
		case ' ':
			if i == 0 || i == len(value)-1 {
				b.WriteByte('\\')
			}
		case '#':
			if i == 0 {
				b.WriteByte('\\')
			}
		}
		b.WriteRune(r)
	}
	return b.String()
}

// SignatureAlgorithmName maps common OIDs to stable names for display. The
// raw OID is stored separately and is authoritative.
func SignatureAlgorithmName(oid asn1.ObjectIdentifier) string {
	switch oid.String() {
	case "1.2.643.7.1.1.3.2":
		return "GOST R 34.10-2012 256"
	case "1.2.643.7.1.1.3.3":
		return "GOST R 34.10-2012 512"
	case "1.2.643.2.2.3":
		return "GOST R 34.10-2001"
	case "1.2.840.113549.1.1.11":
		return "SHA-256 with RSA"
	case "1.2.840.113549.1.1.12":
		return "SHA-384 with RSA"
	case "1.2.840.10045.4.3.2":
		return "ECDSA with SHA-256"
	default:
		return oid.String()
	}
}
