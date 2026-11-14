//go:build windows

package winapi

import (
	"fmt"
	"io/fs"
	"path/filepath"

	"golang.org/x/sys/windows"
)

// stateDACL grants full control only to LOCAL SYSTEM and Administrators and
// removes inherited entries. Files created inside inherit this DACL.
const stateDACL = `D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)`

// SecureDirectory replaces the DACL of a directory without inheriting parent
// permissions. Existing children are handled by SecureTree.
func SecureDirectory(path string) error {
	sd, err := windows.SecurityDescriptorFromString(stateDACL)
	if err != nil {
		return fmt.Errorf("parse state DACL: %w", err)
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return fmt.Errorf("read state DACL: %w", err)
	}
	if err := windows.SetNamedSecurityInfo(
		path,
		windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil, nil, dacl, nil,
	); err != nil {
		return fmt.Errorf("set DACL on %s: %w", path, err)
	}
	return nil
}

// SecureFile applies the same protected DACL to an existing file.
func SecureFile(path string) error {
	sd, err := windows.SecurityDescriptorFromString(`D:P(A;;FA;;;SY)(A;;FA;;;BA)`)
	if err != nil {
		return fmt.Errorf("parse file DACL: %w", err)
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return fmt.Errorf("read file DACL: %w", err)
	}
	if err := windows.SetNamedSecurityInfo(
		path,
		windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil, nil, dacl, nil,
	); err != nil {
		return fmt.Errorf("set DACL on %s: %w", path, err)
	}
	return nil
}

// SecureTree applies the protected DACL to the directory and every existing
// child. It returns the first error; a single inaccessible stale file must not
// prevent the service from starting, so the caller logs rather than aborts.
func SecureTree(root string) error {
	if err := SecureDirectory(root); err != nil {
		return err
	}
	return filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if path == root {
			return nil
		}
		if entry.IsDir() {
			return SecureDirectory(path)
		}
		return SecureFile(path)
	})
}
