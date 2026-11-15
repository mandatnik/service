//go:build windows

package setup

import (
	"fmt"
	"path/filepath"

	"golang.org/x/sys/windows"
)

// WidenRuntimeSecretsACL grants the service account read access to the
// runtime secret store and the DB password file. The files were created with
// the Administrators/SYSTEM DACL by the wizard (elevated admin); the service
// runs under a different account and must read them after a reboot.
func WidenRuntimeSecretsACL(p Paths, serviceAccount string) error {
	sid, _, _, err := windows.LookupSID("", serviceAccount)
	if err != nil {
		return fmt.Errorf("определяю SID учётной записи службы %s: %w", serviceAccount, err)
	}
	admin, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		return err
	}
	system, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	if err != nil {
		return err
	}
	entries := []windows.EXPLICIT_ACCESS{grantRead(sid)}
	for _, s := range []*windows.SID{admin, system} {
		entries = append(entries, windows.EXPLICIT_ACCESS{
			AccessPermissions: windows.GENERIC_ALL,
			AccessMode:        windows.GRANT_ACCESS,
			Trustee:           sidTrustee(s),
		})
	}
	acl, err := windows.ACLFromEntries(entries, nil)
	if err != nil {
		return fmt.Errorf("формирую ACL для секретов: %w", err)
	}
	for _, path := range []string{p.RuntimeSealed, p.Password} {
		if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
			windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
			nil, nil, acl, nil); err != nil {
			return fmt.Errorf("применяю ACL к %s: %w", path, err)
		}
	}
	return nil
}

func grantRead(sid *windows.SID) windows.EXPLICIT_ACCESS {
	return windows.EXPLICIT_ACCESS{
		AccessPermissions: windows.GENERIC_READ,
		AccessMode:        windows.GRANT_ACCESS,
		Trustee:           sidTrustee(sid),
	}
}

func sidTrustee(sid *windows.SID) windows.TRUSTEE {
	return windows.TRUSTEE{
		TrusteeForm:  windows.TRUSTEE_IS_SID,
		TrusteeType:  windows.TRUSTEE_IS_USER,
		TrusteeValue: windows.TrusteeValueFromSID(sid),
	}
}

var _ = filepath.Join
