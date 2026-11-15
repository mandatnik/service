//go:build windows

package setup

import (
	"errors"
	"fmt"

	"golang.org/x/sys/windows"
)

// requireAdmin verifies the elevated-token precheck before any change.
func requireAdmin() error {
	var token windows.Token
	err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_QUERY, &token)
	if err != nil {
		return fmt.Errorf("открываю токен процесса: %w", err)
	}
	defer token.Close()
	if !token.IsElevated() {
		return errors.New("мастер настройки требует прав администратора; запустите консоль «от имени администратора»")
	}
	return nil
}
