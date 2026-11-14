//go:build windows

package winapi

import (
	"errors"
	"fmt"
	"runtime"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	certStoreProvSystemW       = 10
	certSystemStoreCurrentUser = 0x00010000
)

var (
	wtsapi32                    = windows.NewLazySystemDLL("wtsapi32.dll")
	advapi32DLL                 = windows.NewLazySystemDLL("advapi32.dll")
	procWTSEnumerateSessionsW   = wtsapi32.NewProc("WTSEnumerateSessionsW")
	procWTSQuerySessionInfoW    = wtsapi32.NewProc("WTSQuerySessionInformationW")
	procWTSQueryUserToken       = wtsapi32.NewProc("WTSQueryUserToken")
	procWTSFreeMemory           = wtsapi32.NewProc("WTSFreeMemory")
	procImpersonateLoggedOnUser = advapi32DLL.NewProc("ImpersonateLoggedOnUser")
)

type wtsSessionInfo struct {
	SessionID      uint32
	_              uint32
	WinStationName *uint16
	State          uint32
	_              uint32
}

// readLogicalUserStore reads the logical MY store through the logged-on
// user's own token. This handles file-backed roaming stores and CryptoPro
// store elements whose on-disk format is not public. available=false means no
// matching interactive session token was found, so the caller should use the
// physical store fallback.
func readLogicalUserStore(profile Profile) (available bool, present bool, certificates [][]byte, err error) {
	token, tokenErr := findSessionToken(profile.SID)
	if tokenErr != nil {
		return false, false, nil, nil
	}
	if token == 0 {
		return false, false, nil, nil
	}
	defer windows.CloseHandle(windows.Handle(token))

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if r, _, callErr := procImpersonateLoggedOnUser.Call(uintptr(token)); r == 0 {
		return true, false, nil, fmt.Errorf("ImpersonateLoggedOnUser: %w", callErr)
	}
	defer windows.RevertToSelf()

	store, openErr := openCurrentUserSystemStore()
	if openErr != nil {
		return true, false, nil, openErr
	}
	defer procCertCloseStore.Call(store, 0)
	certs, enumErr := enumerateCertificates(store)
	return true, true, certs, enumErr
}

func findSessionToken(sid string) (windows.Token, error) {
	// Best effort: LocalSystem normally holds SeTcbPrivilege. If enabling fails,
	// WTSQueryUserToken will simply be unavailable and the physical fallback is
	// used.
	_ = enablePrivileges([]string{"SeTcbPrivilege"})
	var sessions *wtsSessionInfo
	var count uint32
	r1, _, callErr := procWTSEnumerateSessionsW.Call(0, 0, 1, uintptr(unsafe.Pointer(&sessions)), uintptr(unsafe.Pointer(&count)))
	if r1 == 0 {
		return 0, fmt.Errorf("WTSEnumerateSessionsW: %w", callErr)
	}
	defer procWTSFreeMemory.Call(uintptr(unsafe.Pointer(sessions)))
	if sessions == nil || count == 0 {
		return 0, nil
	}
	list := unsafe.Slice(sessions, int(count))
	for _, session := range list {
		if session.State != 0 { // WTSActive
			continue
		}
		var token windows.Token
		ok, _, _ := procWTSQueryUserToken.Call(uintptr(session.SessionID), uintptr(unsafe.Pointer(&token)))
		if ok == 0 || token == 0 {
			continue
		}
		matches, matchErr := tokenMatchesSID(token, sid)
		if matchErr != nil || !matches {
			_ = windows.CloseHandle(windows.Handle(token))
			continue
		}
		return token, nil
	}
	return 0, nil
}

func tokenMatchesSID(token windows.Token, sid string) (bool, error) {
	user, err := token.GetTokenUser()
	if err != nil {
		return false, err
	}
	if user.User.Sid == nil {
		return false, errors.New("token has no user SID")
	}
	return user.User.Sid.String() == sid, nil
}

func openCurrentUserSystemStore() (uintptr, error) {
	name, err := windows.UTF16PtrFromString("MY")
	if err != nil {
		return 0, err
	}
	store, _, lastErr := procCertOpenStore.Call(
		uintptr(certStoreProvSystemW),
		0,
		0,
		uintptr(certSystemStoreCurrentUser|certStoreReadOnlyFlag),
		uintptr(unsafe.Pointer(name)),
	)
	if store == 0 {
		if lastErr == nil || lastErr == windows.ERROR_SUCCESS {
			return 0, errors.New("CertOpenStore(CERT_STORE_PROV_SYSTEM_W) failed without an error code")
		}
		return 0, fmt.Errorf("CertOpenStore(CERT_STORE_PROV_SYSTEM_W): %w", lastErr)
	}
	return store, nil
}
