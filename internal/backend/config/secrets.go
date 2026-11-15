package config

import (
	"errors"
	"strings"
)

// PasswordSealPrefix marks a DPAPI-sealed db.password_file written by the
// setup wizard ("MNDKDPAPI1 <base64>"). Plain-text files remain supported for
// compatibility with existing installations.
const PasswordSealPrefix = "MNDKDPAPI1"

// unsealPasswordFile resolves either a plain-text or a sealed password file.
// The unseal hook is platform-provided; on Windows it decrypts with
// machine-scope DPAPI so the service account can read it after a reboot.
var unsealPasswordFile = func(value string) (string, error) {
	if strings.HasPrefix(value, PasswordSealPrefix) {
		return "", errors.New("файл пароля БД защищён DPAPI, но текущая платформа не умеет его расшифровать (ожидается Windows)")
	}
	return value, nil
}
