//go:build windows

package licensecrypto

import (
	"path/filepath"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

// On Windows the privacy boundary is the DACL, not os.Chmod's POSIX bits.
func TestPrivateKeyFilesRestrictWindowsACL(t *testing.T) {
	token, err := windows.OpenCurrentProcessToken()
	if err != nil {
		t.Fatal(err)
	}
	defer token.Close()
	user, err := token.GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	allowed := map[string]bool{user.User.Sid.String(): true, "S-1-5-18": true, "S-1-5-32-544": true}
	dir := t.TempDir()
	ringPath, fingerprintPath := filepath.Join(dir, "keyring.json"), filepath.Join(dir, "fingerprint.key")
	if _, err := InitKeyring(ringPath); err != nil {
		t.Fatal(err)
	}
	if err := InitFingerprintKey(fingerprintPath); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{ringPath, fingerprintPath} {
		sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
		if err != nil {
			t.Fatal(err)
		}
		control, _, err := sd.Control()
		if err != nil {
			t.Fatal(err)
		}
		if control&windows.SE_DACL_PROTECTED == 0 {
			t.Fatal("private key file inherits its parent DACL")
		}
		acl, _, err := sd.DACL()
		if err != nil {
			t.Fatal(err)
		}
		if acl == nil || acl.AceCount == 0 {
			t.Fatal("private key file has no restricted access list")
		}
		found := map[string]bool{}
		for i := uint32(0); i < uint32(acl.AceCount); i++ {
			var ace *windows.ACCESS_ALLOWED_ACE
			if err := windows.GetAce(acl, i, &ace); err != nil {
				t.Fatal(err)
			}
			if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE {
				t.Fatal("unexpected private key ACE type")
			}
			sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart)).String()
			if !allowed[sid] {
				t.Fatalf("private key file grants access to unexpected SID %s", sid)
			}
			found[sid] = true
		}
		for sid := range allowed {
			if !found[sid] {
				t.Fatalf("private key file missing expected SID %s", sid)
			}
		}
	}
}
