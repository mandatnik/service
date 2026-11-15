//go:build windows

package winapi

import (
	"errors"
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

// This value is part of the persisted encryption format; changing it loses existing identities.
const dpapiEntropy = "Telehack2026.Agent.Key.v1"

// ProtectData encrypts data with DPAPI in the current service account's user
// scope. The caller must also apply a restrictive filesystem ACL.
func ProtectData(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, errors.New("refusing to protect empty data")
	}
	entropy := []byte(dpapiEntropy)
	in := windows.DataBlob{Size: uint32(len(data)), Data: &data[0]}
	ent := windows.DataBlob{Size: uint32(len(entropy)), Data: &entropy[0]}
	description, _ := windows.UTF16PtrFromString("Мандатник agent key")
	var out windows.DataBlob
	if err := windows.CryptProtectData(&in, description, &ent, 0, nil, windows.CRYPTPROTECT_UI_FORBIDDEN, &out); err != nil {
		return nil, fmt.Errorf("CryptProtectData: %w", err)
	}
	defer windows.LocalFree(windows.Handle(unsafe.Pointer(out.Data)))
	return append([]byte(nil), unsafe.Slice(out.Data, int(out.Size))...), nil
}

// UnprotectData decrypts a DPAPI blob produced by ProtectData.
func UnprotectData(blob []byte) ([]byte, error) {
	if len(blob) == 0 {
		return nil, errors.New("empty DPAPI blob")
	}
	entropy := []byte(dpapiEntropy)
	in := windows.DataBlob{Size: uint32(len(blob)), Data: &blob[0]}
	ent := windows.DataBlob{Size: uint32(len(entropy)), Data: &entropy[0]}
	var out windows.DataBlob
	var description *uint16
	if err := windows.CryptUnprotectData(&in, &description, &ent, 0, nil, windows.CRYPTPROTECT_UI_FORBIDDEN, &out); err != nil {
		return nil, fmt.Errorf("CryptUnprotectData: %w", err)
	}
	if description != nil {
		_, _ = windows.LocalFree(windows.Handle(unsafe.Pointer(description)))
	}
	defer windows.LocalFree(windows.Handle(unsafe.Pointer(out.Data)))
	return append([]byte(nil), unsafe.Slice(out.Data, int(out.Size))...), nil
}
