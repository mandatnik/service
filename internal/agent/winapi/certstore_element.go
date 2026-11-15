package winapi

import (
	"crypto/sha1"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"strings"

	"mandatnik/internal/certparse"
)

// decodeFileStoreElement extracts the DER certificate from one physical file
// store element. Windows writes several shapes into
// SystemCertificates\My\Certificates:
//
//   - version 3 elements: a 44-byte header with the DER length at offset 40;
//   - CryptoPro container elements: a sequence of length/type/value records
//     (container name, key identifiers, SHA-1) followed by the DER certificate
//     and a final length record; the file name is the SHA-1 of the DER;
//   - raw DER written directly by third-party tools.
//
// A single unrecognized element must not make the whole physical store
// unreadable: callers keep the certificates that were parsed and mark the
// source partial. Unknown elements are skipped.
func decodeFileStoreElement(data []byte, name string) ([]byte, error) {
	if len(data) >= 44 && binary.LittleEndian.Uint32(data[0:4]) == 3 {
		derLength := int(binary.LittleEndian.Uint32(data[40:44]))
		if derLength > 0 && derLength <= len(data)-44 {
			der := data[44 : 44+derLength]
			if len(der) > 0 && der[0] == 0x30 {
				if len(data[12:32]) == sha1.Size {
					sum := sha1.Sum(der)
					if hex.EncodeToString(sum[:]) != hex.EncodeToString(data[12:32]) {
						return nil, errors.New("file-store SHA-1 header does not match DER")
					}
				}
				if looksLikeSHA1Name(name) {
					sum := sha1.Sum(der)
					if hex.EncodeToString(sum[:]) != strings.ToLower(name) {
						return nil, errors.New("file name does not match DER SHA-1")
					}
				}
				return append([]byte(nil), der...), nil
			}
		}
	}
	// CryptoPro containers and other wrappers keep the DER after a variable
	// header. The file name is the SHA-1 of the DER, which makes the match
	// unambiguous even without understanding the header layout.
	if looksLikeSHA1Name(name) {
		want := strings.ToLower(name)
		for _, der := range embeddedFileStoreDERs(data) {
			sum := sha1.Sum(der)
			if hex.EncodeToString(sum[:]) != want {
				continue
			}
			if _, err := certparse.Parse(der); err == nil {
				return append([]byte(nil), der...), nil
			}
		}
	}
	// Raw DER fallback (some tools or future formats write the DER directly).
	if _, err := certparse.Parse(data); err == nil {
		return append([]byte(nil), data...), nil
	}
	return nil, errors.New("unsupported file-store element format")
}

// embeddedFileStoreDERs yields complete DER SEQUENCE candidates embedded in a
// wrapped file. The length field is validated so a truncated element cannot be
// mistaken for a certificate. Headers may contain byte pairs that look like a
// DER tag, so callers verify the SHA-1 of the file name before accepting one.
func embeddedFileStoreDERs(data []byte) [][]byte {
	var out [][]byte
	for i := 0; i+4 <= len(data); i++ {
		if data[i] != 0x30 || data[i+1] != 0x82 {
			continue
		}
		size := int(binary.BigEndian.Uint16(data[i+2 : i+4]))
		if size == 0 || i+4+size > len(data) {
			continue
		}
		out = append(out, data[i:i+4+size])
	}
	return out
}

func looksLikeSHA1Name(name string) bool {
	if len(name) != 40 {
		return false
	}
	for _, r := range name {
		switch {
		case r >= '0' && r <= '9':
		case r >= 'a' && r <= 'f':
		case r >= 'A' && r <= 'F':
		default:
			return false
		}
	}
	return true
}
