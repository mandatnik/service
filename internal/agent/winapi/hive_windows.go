//go:build windows

package winapi

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

var (
	advapi32          = windows.NewLazySystemDLL("advapi32.dll")
	procRegLoadKeyW   = advapi32.NewProc("RegLoadKeyW")
	procRegUnLoadKeyW = advapi32.NewProc("RegUnLoadKeyW")
	hkeyUsers         = windows.Handle(registry.USERS)
)

const hiveMountPrefix = "TelehackAgent_"

// LoadHive temporarily mounts a user's NTUSER.DAT under a unique HKU name.
// The caller must call UnloadHive. Only the newly created mount is unloaded;
// foreign HKU branches are never touched.
func LoadHive(hivePath string) (string, error) {
	if _, err := os.Stat(hivePath); err != nil {
		return "", fmt.Errorf("hive file: %w", err)
	}
	for attempt := 0; attempt < 8; attempt++ {
		name := hiveMountPrefix + randomHex(8)
		exists, err := registryKeyExists(name)
		if err != nil {
			return "", err
		}
		if exists {
			continue
		}
		if err := regLoadKey(name, hivePath); err != nil {
			return "", fmt.Errorf("RegLoadKey(%s): %w", hivePath, err)
		}
		return name, nil
	}
	return "", errors.New("could not allocate a unique hive mount name")
}

// UnloadHive unloads a mount created by LoadHive. It retries briefly because
// registry handles may still be closing. It returns an error if the mount is
// still present after the retries.
func UnloadHive(name string) error {
	if name == "" {
		return nil
	}
	var lastErr error
	for attempt := 0; attempt < 12; attempt++ {
		err := regUnloadKey(name)
		if err == nil || errors.Is(err, windows.ERROR_FILE_NOT_FOUND) || errors.Is(err, windows.ERROR_PATH_NOT_FOUND) {
			return nil
		}
		lastErr = err
		time.Sleep(100 * time.Millisecond)
	}
	return fmt.Errorf("RegUnLoadKey(%s): %w", name, lastErr)
}

// HivePresent reports whether HKU\name exists.
func HivePresent(name string) bool {
	exists, err := registryKeyExists(name)
	return err == nil && exists
}

func registryKeyExists(name string) (bool, error) {
	key, err := registry.OpenKey(registry.USERS, name, registry.READ)
	if err != nil {
		if errors.Is(err, windows.ERROR_FILE_NOT_FOUND) || errors.Is(err, windows.ERROR_PATH_NOT_FOUND) {
			return false, nil
		}
		return false, err
	}
	return true, key.Close()
}

func regLoadKey(name, hivePath string) error {
	namePtr, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return err
	}
	pathPtr, err := windows.UTF16PtrFromString(hivePath)
	if err != nil {
		return err
	}
	r1, _, _ := procRegLoadKeyW.Call(uintptr(hkeyUsers), uintptr(unsafe.Pointer(namePtr)), uintptr(unsafe.Pointer(pathPtr)))
	if r1 != 0 {
		return syscall.Errno(r1)
	}
	return nil
}

func regUnloadKey(name string) error {
	namePtr, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return err
	}
	r1, _, _ := procRegUnLoadKeyW.Call(uintptr(hkeyUsers), uintptr(unsafe.Pointer(namePtr)))
	if r1 != 0 {
		return syscall.Errno(r1)
	}
	return nil
}

func randomHex(bytesCount int) string {
	buf := make([]byte, bytesCount)
	if _, err := rand.Read(buf); err != nil {
		// crypto/rand failure is unrecoverable for identity material; use a
		// time-based fallback only for a temporary hive name, never for keys.
		return fmt.Sprintf("%x", time.Now().UnixNano())[:bytesCount*2]
	}
	return hex.EncodeToString(buf)
}

// UserHivePath returns the NTUSER.DAT path for a profile directory.
func UserHivePath(profilePath string) string {
	return filepath.Join(profilePath, "NTUSER.DAT")
}
