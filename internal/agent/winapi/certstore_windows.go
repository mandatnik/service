//go:build windows

package winapi

import (
	"crypto/sha1"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
	"telehack2026/internal/certparse"
)

const (
	certStoreProvReg          = 4
	certStoreReadOnlyFlag     = 0x00008000
	certStoreOpenExistingFlag = 0x00004000
	maxCertificateDER         = 1024 * 1024
)

const certStoreSuffix = `Software\Microsoft\SystemCertificates\My`

var (
	crypt32                        = windows.NewLazySystemDLL("crypt32.dll")
	procCertOpenStore              = crypt32.NewProc("CertOpenStore")
	procCertEnumCertificates       = crypt32.NewProc("CertEnumCertificatesInStore")
	procCertCloseStore             = crypt32.NewProc("CertCloseStore")
	procCertFreeCertificateContext = crypt32.NewProc("CertFreeCertificateContext")
)

var cryptENotFound = syscall.Errno(0x80092004)

// certContext mirrors CERT_CONTEXT on 64-bit Windows.
type certContext struct {
	EncodingType uint32
	_            uint32
	Encoded      *byte
	EncodedLen   uint32
	_            uint32
	Info         uintptr
	Store        uintptr
}

// ReadUserStore reads the personal MY store of one profile. For an unloaded
// profile it temporarily mounts NTUSER.DAT. The store is opened read-only with
// CERT_STORE_PROV_REG and is never created if absent.
//
// present=false with err=nil means the store key does not exist (a successful
// empty result). Any non-nil error means the source is incomplete.
func ReadUserStore(profile Profile) (present bool, certificates [][]byte, err error) {
	if profile.Path == "" {
		return false, nil, errors.New("profile path is empty")
	}
	if profile.Loaded {
		if available, present, certs, logicalErr := readLogicalUserStore(profile); available {
			return present, deduplicateDER(certs), logicalErr
		}
		return readStoreFromUserKey(profile.SID, profile.Path)
	}
	hive := UserHivePath(profile.Path)
	if _, statErr := os.Stat(hive); statErr != nil {
		return false, nil, fmt.Errorf("NTUSER.DAT: %w", statErr)
	}
	mount, mountErr := LoadHive(hive)
	if mountErr != nil {
		// A user may have logged in between the Loaded check and RegLoadKey.
		// Re-check the real profile key before declaring the source unreadable.
		if loaded, loadErr := ProfileLoaded(profile.SID); loadErr == nil && loaded {
			return readStoreFromUserKey(profile.SID, profile.Path)
		}
		return false, nil, mountErr
	}
	defer func() {
		if unloadErr := UnloadHive(mount); unloadErr != nil && err == nil {
			err = unloadErr
		}
	}()
	return readStoreFromUserKey(mount, profile.Path)
}

func readStoreFromUserKey(keyName, profilePath string) (bool, [][]byte, error) {
	var certificates [][]byte
	var problems []error
	present := false
	key, err := registry.OpenKey(registry.USERS, keyName+`\`+certStoreSuffix, registry.READ)
	switch {
	case err == nil:
		store, openErr := openStoreFromKey(key)
		if openErr != nil {
			if !errors.Is(openErr, windows.ERROR_FILE_NOT_FOUND) && !errors.Is(openErr, cryptENotFound) {
				problems = append(problems, fmt.Errorf("open registry certificate store %s: %w", keyName, openErr))
			}
			_ = key.Close()
		} else {
			present = true
			certs, enumErr := enumerateCertificates(store)
			certificates = append(certificates, certs...)
			if enumErr != nil {
				problems = append(problems, enumErr)
			}
			procCertCloseStore.Call(store, 0)
		}
		_ = key.Close()
	case errors.Is(err, windows.ERROR_FILE_NOT_FOUND) || errors.Is(err, windows.ERROR_PATH_NOT_FOUND):
		// The registry-backed physical store may legitimately be absent when
		// Windows uses the roaming file store.
	default:
		problems = append(problems, fmt.Errorf("open registry certificate store %s: %w", keyName, err))
	}

	appData := appDataPathFromUserKey(keyName, profilePath)
	fileCerts, filePresent, fileErr := readFileStore(profilePath, appData)
	present = present || filePresent
	certificates = append(certificates, fileCerts...)
	if fileErr != nil {
		problems = append(problems, fileErr)
	}
	certificates = deduplicateDER(certificates)
	return present, certificates, errors.Join(problems...)
}

// appDataPathFromUserKey resolves the roaming AppData directory for a user.
// It is read from the user's own hive when available and falls back to the
// conventional profile path. This covers redirected AppData where the hive
// records an absolute path.
func appDataPathFromUserKey(keyName, profilePath string) string {
	key, err := registry.OpenKey(registry.USERS, keyName+`\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders`, registry.READ)
	if err == nil {
		value, _, valueErr := key.GetStringValue("AppData")
		_ = key.Close()
		if valueErr == nil {
			expanded := expandWindowsEnvironment(value, profilePath)
			if filepath.IsAbs(expanded) {
				return filepath.Clean(expanded)
			}
		}
	}
	if profilePath == "" {
		return ""
	}
	return filepath.Join(profilePath, "AppData", "Roaming")
}

func expandWindowsEnvironment(value, profilePath string) string {
	var builder strings.Builder
	for i := 0; i < len(value); {
		if value[i] != '%' {
			builder.WriteByte(value[i])
			i++
			continue
		}
		end := strings.IndexByte(value[i+1:], '%')
		if end < 0 {
			builder.WriteString(value[i:])
			break
		}
		name := strings.ToUpper(value[i+1 : i+1+end])
		switch name {
		case "USERPROFILE":
			builder.WriteString(profilePath)
		default:
			builder.WriteString(os.Getenv(name))
		}
		i += end + 2
	}
	return builder.String()
}

// readFileStore reads the roaming physical MY store. Windows writes one file
// per certificate with a 40-byte header followed by the DER; raw DER files are
// also accepted for robustness.
func readFileStore(profilePath, appDataPath string) ([][]byte, bool, error) {
	var roots []string
	if appDataPath != "" {
		roots = append(roots, filepath.Join(appDataPath, "Microsoft", "SystemCertificates", "My", "Certificates"))
		local := filepath.Join(filepath.Dir(appDataPath), "Local", "Microsoft", "SystemCertificates", "My", "Certificates")
		if local != roots[0] {
			roots = append(roots, local)
		}
	}
	if profilePath != "" {
		fallback := filepath.Join(profilePath, "AppData", "Roaming", "Microsoft", "SystemCertificates", "My", "Certificates")
		if len(roots) == 0 || fallback != roots[0] {
			roots = append(roots, fallback)
		}
	}
	var certs [][]byte
	present := false
	var problems []error
	seenRoots := make(map[string]bool)
	for _, root := range roots {
		if root == "" || seenRoots[strings.ToLower(root)] {
			continue
		}
		seenRoots[strings.ToLower(root)] = true
		entries, err := os.ReadDir(root)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			problems = append(problems, fmt.Errorf("read file store %s: %w", root, err))
			continue
		}
		present = true
		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}
			path := filepath.Join(root, entry.Name())
			data, err := os.ReadFile(path)
			if err != nil {
				problems = append(problems, fmt.Errorf("read %s: %w", path, err))
				continue
			}
			der, err := decodeFileStoreElement(data, entry.Name())
			if err != nil {
				problems = append(problems, fmt.Errorf("decode %s: %w", path, err))
				continue
			}
			certs = append(certs, der)
		}
	}
	return certs, present, errors.Join(problems...)
}

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
	// Raw DER fallback (some tools or future formats write the DER directly).
	if _, err := certparse.Parse(data); err == nil {
		return append([]byte(nil), data...), nil
	}
	return nil, errors.New("unsupported file-store element format")
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

func deduplicateDER(certs [][]byte) [][]byte {
	seen := make(map[[32]byte]bool, len(certs))
	out := certs[:0]
	for _, der := range certs {
		sum := sha256.Sum256(der)
		if seen[sum] {
			continue
		}
		seen[sum] = true
		out = append(out, der)
	}
	return out
}

func openStoreFromKey(key registry.Key) (uintptr, error) {
	handle := uintptr(key)
	store, _, lastErr := procCertOpenStore.Call(
		uintptr(certStoreProvReg),
		0,
		0,
		uintptr(certStoreReadOnlyFlag|certStoreOpenExistingFlag),
		handle,
	)
	if store == 0 {
		if lastErr == nil || lastErr == windows.ERROR_SUCCESS {
			return 0, errors.New("CertOpenStore(CERT_STORE_PROV_REG) failed without an error code")
		}
		return 0, fmt.Errorf("CertOpenStore(CERT_STORE_PROV_REG): %w", lastErr)
	}
	return store, nil
}

func enumerateCertificates(store uintptr) ([][]byte, error) {
	var certificates [][]byte
	var current uintptr
	for {
		next, _, lastErr := procCertEnumCertificates.Call(store, current)
		if next == 0 {
			if lastErr == nil || lastErr == windows.ERROR_SUCCESS || lastErr == windows.ERROR_NO_MORE_FILES || errors.Is(lastErr, cryptENotFound) {
				return certificates, nil
			}
			return certificates, fmt.Errorf("CertEnumCertificatesInStore: %w", lastErr)
		}
		current = next
		ctx := (*certContext)(unsafe.Pointer(current))
		if ctx.Encoded == nil || ctx.EncodedLen == 0 {
			continue
		}
		if ctx.EncodedLen > maxCertificateDER {
			// The enumeration owns the context; freeing it here would make the
			// next call use a stale pointer. Record the error and stop.
			procCertFreeCertificateContext.Call(current)
			return certificates, fmt.Errorf("certificate DER exceeds %d bytes", maxCertificateDER)
		}
		der := append([]byte(nil), unsafe.Slice(ctx.Encoded, int(ctx.EncodedLen))...)
		certificates = append(certificates, der)
	}
}
