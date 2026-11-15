//go:build windows

package setup

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
	"mandatnik/internal/agent/winapi"
)

// Wizard draft secrets are protected with the current user DPAPI scope: only
// the elevated administrator session that created them can read them back.
func sealCurrentUser(plain []byte) ([]byte, error) {
	return winapi.ProtectData(plain)
}

func unsealCurrentUser(blob []byte) ([]byte, error) {
	return winapi.UnprotectData(blob)
}

// Runtime secrets must be readable by the service account after a reboot, so
// they use machine-scope DPAPI and an ACL limited to Administrators/SYSTEM
// plus the actual service account (widened after service installation).
func sealMachine(plain []byte) ([]byte, error) {
	in := windows.DataBlob{Size: uint32(len(plain)), Data: ptr(plain)}
	var out windows.DataBlob
	if err := windows.CryptProtectData(&in, nil, nil, 0, nil,
		windows.CRYPTPROTECT_UI_FORBIDDEN|windows.CRYPTPROTECT_LOCAL_MACHINE, &out); err != nil {
		return nil, fmt.Errorf("CryptProtectData (machine scope): %w", err)
	}
	defer windows.LocalFree(windows.Handle(uintptr(unsafe.Pointer(out.Data))))
	return unsafe.Slice(out.Data, out.Size), nil
}

func unsealMachine(blob []byte) ([]byte, error) {
	in := windows.DataBlob{Size: uint32(len(blob)), Data: ptr(blob)}
	var out windows.DataBlob
	if err := windows.CryptUnprotectData(&in, nil, nil, 0, nil,
		windows.CRYPTPROTECT_UI_FORBIDDEN, &out); err != nil {
		return nil, fmt.Errorf("CryptUnprotectData (machine scope): %w", err)
	}
	defer windows.LocalFree(windows.Handle(uintptr(unsafe.Pointer(out.Data))))
	return unsafe.Slice(out.Data, out.Size), nil
}

func ptr(b []byte) *byte {
	if len(b) == 0 {
		return nil
	}
	return &b[0]
}

// secureFile applies the service/administrator DACL to a setup file.
func secureFile(path string) error { return winapi.SecureFile(path) }

// secureDir applies the protected DACL to a setup directory.
func secureDir(path string) error { return winapi.SecureDirectory(path) }
