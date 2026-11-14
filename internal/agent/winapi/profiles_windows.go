//go:build windows

package winapi

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

const currentVersionKey = `SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList`

// Profile describes a local user profile discovered in ProfileList.
type Profile struct {
	SID    string
	Name   string
	Path   string
	Loaded bool
}

// EnumerateProfiles lists local interactive user profiles. System service
// profiles and machine stores are excluded. A profile whose path is missing is
// still returned so the report can mark it incomplete rather than silently
// absent.
func EnumerateProfiles() ([]Profile, error) {
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, currentVersionKey, registry.READ|registry.WOW64_64KEY)
	if err != nil {
		return nil, fmt.Errorf("open ProfileList: %w", err)
	}
	defer key.Close()
	names, err := key.ReadSubKeyNames(-1)
	if err != nil {
		return nil, fmt.Errorf("enumerate ProfileList: %w", err)
	}
	var profiles []Profile
	for _, sid := range names {
		if !isUserSID(sid) {
			continue
		}
		sub, err := registry.OpenKey(key, sid, registry.READ|registry.WOW64_64KEY)
		if err != nil {
			profiles = append(profiles, Profile{SID: sid, Path: "", Loaded: false, Name: sid})
			continue
		}
		rawPath, _, pathErr := sub.GetStringValue("ProfileImagePath")
		_ = sub.Close()
		if pathErr != nil {
			profiles = append(profiles, Profile{SID: sid, Path: "", Loaded: false, Name: sid})
			continue
		}
		profilePath := filepath.Clean(os.ExpandEnv(rawPath))
		if !profilePathAllowed(profilePath) {
			continue
		}
		loaded, loadErr := ProfileLoaded(sid)
		if loadErr != nil {
			// A profile that cannot even be probed is returned with Loaded
			// false; the collector will attempt the hive and report the error.
			loaded = false
		}
		profiles = append(profiles, Profile{
			SID:    sid,
			Name:   lookupAccountName(sid, profilePath),
			Path:   profilePath,
			Loaded: loaded,
		})
	}
	sort.Slice(profiles, func(i, j int) bool { return profiles[i].SID < profiles[j].SID })
	return profiles, nil
}

func isUserSID(sid string) bool {
	if !strings.HasPrefix(sid, "S-1-5-21-") {
		return false
	}
	switch sid {
	case "S-1-5-18", "S-1-5-19", "S-1-5-20":
		return false
	}
	return true
}

func profilePathAllowed(path string) bool {
	if path == "" || path == "." {
		return false
	}
	lower := strings.ToLower(filepath.Clean(path))
	if strings.Contains(lower, `\system32\config\systemprofile`) ||
		strings.Contains(lower, `\system32\config\localservice`) ||
		strings.Contains(lower, `\system32\config\networkservice`) ||
		strings.HasSuffix(lower, `\systemprofile`) ||
		strings.HasSuffix(lower, `\localservice`) ||
		strings.HasSuffix(lower, `\networkservice`) {
		return false
	}
	base := strings.ToLower(filepath.Base(lower))
	switch base {
	case "default", "default user", "all users", "public":
		return false
	}
	return true
}

// ProfileLoaded reports whether HKU\SID currently exists.
func ProfileLoaded(sid string) (bool, error) {
	key, err := registry.OpenKey(registry.USERS, sid, registry.READ)
	if err != nil {
		if err == windows.ERROR_FILE_NOT_FOUND || err == windows.ERROR_PATH_NOT_FOUND {
			return false, nil
		}
		return false, err
	}
	_ = key.Close()
	return true, nil
}

func lookupAccountName(sid string, profilePath string) string {
	sidPtr, err := windows.StringToSid(sid)
	if err != nil {
		return filepath.Base(profilePath)
	}
	var nameLen, domainLen uint32
	var use uint32
	_ = windows.LookupAccountSid(nil, sidPtr, nil, &nameLen, nil, &domainLen, &use)
	if nameLen == 0 {
		return filepath.Base(profilePath)
	}
	name := make([]uint16, nameLen)
	domain := make([]uint16, domainLen)
	if err := windows.LookupAccountSid(nil, sidPtr, &name[0], &nameLen, &domain[0], &domainLen, &use); err != nil {
		return filepath.Base(profilePath)
	}
	account := windows.UTF16ToString(name)
	domainName := windows.UTF16ToString(domain)
	if domainName == "" {
		return account
	}
	return domainName + `\` + account
}
