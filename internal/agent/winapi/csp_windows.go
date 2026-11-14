//go:build windows

package winapi

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/windows/registry"
)

// CSPProduct is one installed CryptoPro product from the uninstall registry.
type CSPProduct struct {
	GUID           string
	DisplayName    string
	DisplayVersion string
	Branch         string
}

var knownCSPProducts = map[string]string{
	"{50F91F80-D397-437C-B0C8-62128DE3B55E}": "5",
	"{407E5BA7-6406-40BF-A4DC-3654B8F584C1}": "4",
}

// DiscoverCSPProducts enumerates the two documented product GUIDs in both
// 64-bit and WOW6432Node uninstall views. It does not infer CSP version from
// an arbitrary DLL.
func DiscoverCSPProducts() []CSPProduct {
	roots := []string{
		`SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`,
		`SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall`,
	}
	seen := make(map[string]bool)
	var products []CSPProduct
	for _, root := range roots {
		key, err := registry.OpenKey(registry.LOCAL_MACHINE, root, registry.READ|registry.WOW64_64KEY)
		if err != nil {
			continue
		}
		names, _ := key.ReadSubKeyNames(-1)
		for _, name := range names {
			branch, known := knownCSPProducts[strings.ToUpper(name)]
			sub, err := registry.OpenKey(key, name, registry.READ|registry.WOW64_64KEY)
			if err != nil {
				continue
			}
			displayName, _, _ := sub.GetStringValue("DisplayName")
			displayVersion, _, _ := sub.GetStringValue("DisplayVersion")
			_ = sub.Close()
			if !known {
				if !looksLikeCryptoProCSP(displayName) {
					continue
				}
				major := versionMajor(displayVersion)
				if major != 4 && major != 5 {
					continue
				}
				branch = fmt.Sprintf("%d", major)
			}
			if seen[branch] {
				continue
			}
			seen[branch] = true
			products = append(products, CSPProduct{
				GUID:           strings.ToUpper(name),
				DisplayName:    displayName,
				DisplayVersion: displayVersion,
				Branch:         branch,
			})
		}
		_ = key.Close()
	}
	return products
}

var csptestVersionPattern = regexp.MustCompile(`CSP \(Type:80\) v([0-9][0-9.]*)[^R\r\n]*Release Ver:([0-9][0-9.]*)`)

// CSPVersions contains the release version of the installed product and the
// cryptographic core version. They come from the vendor's csptest output and
// are intentionally separate fields.
type CSPVersions struct {
	Product string
	Core    string
	Source  string
	Output  string
}

// ReadCSPVersions runs the read-only vendor diagnostic
// `csptest -keyset -verifycontext -silent`. It does not create containers.
func ReadCSPVersions() (CSPVersions, error) {
	path := findCSPTest()
	if path == "" {
		return CSPVersions{}, fmt.Errorf("csptest.exe not found")
	}
	output, err := runCSPTest(path)
	if err != nil {
		return CSPVersions{Source: path}, err
	}
	matches := csptestVersionPattern.FindStringSubmatch(output)
	if len(matches) != 3 {
		return CSPVersions{Source: path, Output: output}, fmt.Errorf("csptest output does not contain release/core versions")
	}
	return CSPVersions{
		Core:    matches[1],
		Product: matches[2],
		Source:  path,
		Output:  output,
	}, nil
}

func findCSPTest() string {
	candidates := []string{
		`C:\Program Files (x86)\Crypto Pro\CSP\csptest.exe`,
		`C:\Program Files\Crypto Pro\CSP\csptest.exe`,
	}
	for _, candidate := range candidates {
		if info, err := os.Stat(candidate); err == nil && !info.IsDir() {
			return candidate
		}
	}
	if path, err := exec.LookPath("csptest.exe"); err == nil {
		return path
	}
	return ""
}

func runCSPTest(path string) (string, error) {
	// The version probe is read-only. It is run with a fixed argument list and
	// a timeout; no user-controlled data is passed.
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, path, "-keyset", "-verifycontext", "-silent")
	command.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	output, err := command.CombinedOutput()
	if err != nil {
		return string(output), fmt.Errorf("csptest: %w", err)
	}
	return string(output), nil
}

// DiscoverEnvironment distinguishes a workstation from Windows Server using
// the same stable registry source as OSVersionString. Unknown is explicit.
func DiscoverEnvironment() string {
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows NT\CurrentVersion`, registry.READ|registry.WOW64_64KEY)
	if err != nil {
		return "unknown"
	}
	defer key.Close()
	product, _, _ := key.GetStringValue("ProductName")
	installation, _, _ := key.GetStringValue("InstallationType")
	text := strings.ToLower(product + " " + installation)
	switch {
	case strings.Contains(text, "server"):
		return "server"
	case strings.TrimSpace(product) != "":
		return "workstation"
	default:
		return "unknown"
	}
}

// OSVersionString returns ProductName/CurrentBuild/UBR from the registry,
// which is stable and localized independently of RtlGetVersion.
func OSVersionString() string {
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows NT\CurrentVersion`, registry.READ|registry.WOW64_64KEY)
	if err != nil {
		return ""
	}
	defer key.Close()
	product, _, _ := key.GetStringValue("ProductName")
	build, _, _ := key.GetStringValue("CurrentBuild")
	ubr, _, _ := key.GetIntegerValue("UBR")
	version := strings.TrimSpace(product)
	if build != "" {
		version += " " + build
	}
	if ubr != 0 {
		version += fmt.Sprintf(".%d", ubr)
	}
	return strings.TrimSpace(version)
}
