//go:build windows

// Package winapi contains the Windows-specific adapters used by the agent:
// profile enumeration, registry-backed certificate stores, offline hive
// mounting, CryptoPro licensing and DPAPI. All functions are read-only unless
// explicitly named otherwise.
package winapi

import (
	"fmt"

	"golang.org/x/sys/windows"
)

// EnableBackupRestorePrivileges enables SeBackupPrivilege and
// SeRestorePrivilege on the current process token. The caller should treat a
// failure as a reason to expect incomplete offline-profile results, not as a
// fatal collector error.
func EnableBackupRestorePrivileges() error {
	return enablePrivileges([]string{"SeBackupPrivilege", "SeRestorePrivilege"})
}

func enablePrivileges(names []string) error {
	var token windows.Token
	if err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_ADJUST_PRIVILEGES|windows.TOKEN_QUERY, &token); err != nil {
		return fmt.Errorf("OpenProcessToken: %w", err)
	}
	defer token.Close()
	for _, name := range names {
		namePtr, err := windows.UTF16PtrFromString(name)
		if err != nil {
			return err
		}
		var luid windows.LUID
		if err := windows.LookupPrivilegeValue(nil, namePtr, &luid); err != nil {
			return fmt.Errorf("LookupPrivilegeValue(%s): %w", name, err)
		}
		state := windows.Tokenprivileges{
			PrivilegeCount: 1,
			Privileges: [1]windows.LUIDAndAttributes{{
				Luid:       luid,
				Attributes: windows.SE_PRIVILEGE_ENABLED,
			}},
		}
		if err := windows.AdjustTokenPrivileges(token, false, &state, 0, nil, nil); err != nil {
			return fmt.Errorf("AdjustTokenPrivileges(%s): %w", name, err)
		}
		// AdjustTokenPrivileges reports success even when not all privileges
		// were assigned; GetLastError is the documented discriminator.
		if err := windows.GetLastError(); err != nil && err != windows.ERROR_SUCCESS && err != windows.ERROR_NOT_ALL_ASSIGNED {
			return fmt.Errorf("AdjustTokenPrivileges(%s): %w", name, err)
		} else if err == windows.ERROR_NOT_ALL_ASSIGNED {
			return fmt.Errorf("privilege %s is not held by the service account", name)
		}
	}
	return nil
}
