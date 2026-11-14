//go:build windows

package winapi

import (
	"fmt"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

// SystemIdentity is diagnostic context for service-only evidence.
type SystemIdentity struct {
	User      string
	SID       string
	SessionID uint32
	OSVersion string
	Hostname  string
}

// CurrentSystemIdentity returns the account, SID and session of the current
// process. A real SCM service must show SYSTEM/S-1-5-18/session 0.
func CurrentSystemIdentity() SystemIdentity {
	out := SystemIdentity{}
	token, err := windows.OpenCurrentProcessToken()
	if err == nil {
		defer token.Close()
		if user, userErr := token.GetTokenUser(); userErr == nil && user.User.Sid != nil {
			out.SID = user.User.Sid.String()
			out.User = accountName(user.User.Sid)
		}
	}
	var session uint32
	if err := windows.ProcessIdToSessionId(windows.GetCurrentProcessId(), &session); err == nil {
		out.SessionID = session
	}
	out.OSVersion = OSVersionString()
	if hostname, err := windows.ComputerName(); err == nil {
		out.Hostname = hostname
	}
	return out
}

func accountName(sid *windows.SID) string {
	var nameLen, domainLen uint32
	var use uint32
	_ = windows.LookupAccountSid(nil, sid, nil, &nameLen, nil, &domainLen, &use)
	if nameLen == 0 {
		return sid.String()
	}
	name := make([]uint16, nameLen)
	domain := make([]uint16, domainLen)
	if err := windows.LookupAccountSid(nil, sid, &name[0], &nameLen, &domain[0], &domainLen, &use); err != nil {
		return sid.String()
	}
	account := windows.UTF16ToString(name)
	domainName := windows.UTF16ToString(domain)
	if domainName == "" {
		return account
	}
	return domainName + `\` + account
}

// InstalledOSVersion returns a stable OS description for the report.
func InstalledOSVersion() string {
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows NT\CurrentVersion`, registry.READ|registry.WOW64_64KEY)
	if err != nil {
		return ""
	}
	defer key.Close()
	product, _, _ := key.GetStringValue("ProductName")
	build, _, _ := key.GetStringValue("CurrentBuild")
	ubr, _, _ := key.GetIntegerValue("UBR")
	result := product
	if build != "" {
		result += " " + build
	}
	if ubr != 0 {
		result += fmt.Sprintf(".%d", ubr)
	}
	return result
}
