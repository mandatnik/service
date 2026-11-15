//go:build windows

package config

import (
	"encoding/base64"
	"fmt"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

func init() {
	unsealPasswordFile = unsealPasswordFileWindows
}

// unsealPasswordFileWindows decrypts machine-scope DPAPI password files.
func unsealPasswordFileWindows(value string) (string, error) {
	if !strings.HasPrefix(value, PasswordSealPrefix) {
		return value, nil
	}
	blob, err := base64.StdEncoding.DecodeString(strings.TrimSpace(strings.TrimPrefix(value, PasswordSealPrefix)))
	if err != nil {
		return "", fmt.Errorf("read db.password_file: %w", err)
	}
	if len(blob) == 0 {
		return "", fmt.Errorf("db.password_file sealed blob is empty")
	}
	in := windows.DataBlob{Size: uint32(len(blob)), Data: &blob[0]}
	var out windows.DataBlob
	if err := windows.CryptUnprotectData(&in, nil, nil, 0, nil, windows.CRYPTPROTECT_UI_FORBIDDEN, &out); err != nil {
		return "", fmt.Errorf("db.password_file: machine DPAPI unprotect failed (файл создан на другом сервере или повреждён): %w", err)
	}
	defer windows.LocalFree(windows.Handle(uintptr(unsafe.Pointer(out.Data))))
	return string(unsafe.Slice(out.Data, out.Size)), nil
}
