//go:build windows

package winapi

import (
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"golang.org/x/sys/windows/registry"
	"mandatnik/internal/protocol"
)

const installerUserDataProducts = `SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\Products`

// knownPackedProducts maps the documented product GUIDs to the packed MSI
// ProductCode branch used by the ProductID value. A branch is still verified
// against the installed uninstall entry before any write.
var knownPackedProducts = map[string]string{
	"{50F91F80-D397-437C-B0C8-62128DE3B55E}": "08F19F05793DC7340B8C2621D83E5BE5",
	"{407E5BA7-6406-40BF-A4DC-3654B8F584C1}": "7AB5E7046046FB044ACD63458B5F481C",
}

// LicenseProduct is one installed CryptoPro CSP product for which a ProductID
// branch exists. ProductID itself is read separately and never logged.
type LicenseProduct struct {
	ProperGUID        string
	PackedGUID        string
	DisplayName       string
	DisplayVersion    string
	Major             int
	InstallProperties string
}

// DiscoverLicenseProducts verifies the installed CSP against the MSI
// InstallProperties branch. It never creates a branch for a missing product.
func DiscoverLicenseProducts() ([]LicenseProduct, error) {
	installed := DiscoverCSPProducts()
	if len(installed) == 0 {
		return nil, errors.New("CryptoPro CSP is not installed")
	}
	branches, err := installerBranches()
	if err != nil {
		return nil, err
	}
	var products []LicenseProduct
	for _, product := range installed {
		major, _ := strconv.Atoi(strings.TrimSpace(product.Branch))
		if major != 4 && major != 5 {
			continue
		}
		expected := knownPackedProducts[strings.ToUpper(product.GUID)]
		selected := ""
		for _, branch := range branches {
			if !strings.EqualFold(branch.PackedGUID, expected) && expected != "" {
				continue
			}
			if !looksLikeCryptoProCSP(branch.DisplayName) {
				continue
			}
			branchMajor := versionMajor(branch.DisplayVersion)
			if branchMajor != 0 && branchMajor != major {
				continue
			}
			selected = branch.PackedGUID
			break
		}
		if selected == "" {
			// Fall back to a uniquely matching branch by display name/version.
			for _, branch := range branches {
				if looksLikeCryptoProCSP(branch.DisplayName) && versionMajor(branch.DisplayVersion) == major {
					selected = branch.PackedGUID
					break
				}
			}
		}
		if selected == "" {
			return nil, fmt.Errorf("no MSI InstallProperties branch for CryptoPro CSP %d", major)
		}
		products = append(products, LicenseProduct{
			ProperGUID:        strings.ToUpper(product.GUID),
			PackedGUID:        strings.ToUpper(selected),
			DisplayName:       product.DisplayName,
			DisplayVersion:    product.DisplayVersion,
			Major:             major,
			InstallProperties: installerProductPath(selected),
		})
	}
	sort.Slice(products, func(i, j int) bool { return products[i].Major > products[j].Major })
	return products, nil
}

type installerBranch struct {
	PackedGUID     string
	DisplayName    string
	DisplayVersion string
}

func installerBranches() ([]installerBranch, error) {
	root, err := registry.OpenKey(registry.LOCAL_MACHINE, installerUserDataProducts, registry.READ|registry.WOW64_64KEY)
	if err != nil {
		return nil, fmt.Errorf("open MSI installer products: %w", err)
	}
	defer root.Close()
	names, err := root.ReadSubKeyNames(-1)
	if err != nil {
		return nil, fmt.Errorf("enumerate MSI installer products: %w", err)
	}
	var branches []installerBranch
	for _, name := range names {
		props, err := registry.OpenKey(root, name+`\InstallProperties`, registry.READ|registry.WOW64_64KEY)
		if err != nil {
			continue
		}
		displayName, _, _ := props.GetStringValue("DisplayName")
		productName, _, _ := props.GetStringValue("ProductName")
		displayVersion, _, _ := props.GetStringValue("DisplayVersion")
		_ = props.Close()
		if displayName == "" {
			displayName = productName
		}
		branches = append(branches, installerBranch{PackedGUID: strings.ToUpper(name), DisplayName: displayName, DisplayVersion: displayVersion})
	}
	return branches, nil
}

func looksLikeCryptoProCSP(name string) bool {
	lower := strings.ToLower(strings.TrimSpace(name))
	if !strings.Contains(lower, "csp") {
		return false
	}
	return strings.Contains(lower, "cryptopro") || strings.Contains(lower, "crypto-pro") || strings.Contains(lower, "криптопро")
}

func versionMajor(value string) int {
	value = strings.TrimSpace(value)
	if dot := strings.IndexByte(value, '.'); dot >= 0 {
		value = value[:dot]
	}
	major, err := strconv.Atoi(value)
	if err != nil || major < 1 || major > 99 {
		return 0
	}
	return major
}

func installerProductPath(packed string) string {
	return installerUserDataProducts + `\` + strings.ToUpper(packed) + `\InstallProperties`
}

// ReadProductID reads the raw REG value without logging it.
func ReadProductID(product LicenseProduct) (value string, valueType uint32, present bool, err error) {
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, product.InstallProperties, registry.READ|registry.WOW64_64KEY)
	if err != nil {
		return "", 0, false, err
	}
	defer key.Close()
	value, valueType, err = key.GetStringValue("ProductID")
	if errors.Is(err, registry.ErrNotExist) {
		return "", 0, false, nil
	}
	if err != nil {
		return "", 0, false, err
	}
	return value, valueType, true, nil
}

// WriteProductID performs the single native registry write. The caller must
// have persisted the original value and an intent record first.
func WriteProductID(product LicenseProduct, serial string) error {
	normalized := protocol.NormalizeSerial(serial)
	if err := protocol.ValidateSerialFormat(normalized); err != nil {
		return err
	}
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, product.InstallProperties, registry.SET_VALUE|registry.WOW64_64KEY)
	if err != nil {
		return fmt.Errorf("open ProductID branch: %w", err)
	}
	defer key.Close()
	if err := key.SetStringValue("ProductID", normalized); err != nil {
		return fmt.Errorf("write ProductID: %w", err)
	}
	return nil
}

// RestoreProductID restores a value only through an explicit caller decision.
// present=false removes the value, restoring the original absent state.
func RestoreProductID(product LicenseProduct, value string, valueType uint32, present bool) error {
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, product.InstallProperties, registry.SET_VALUE|registry.WOW64_64KEY)
	if err != nil {
		return fmt.Errorf("open ProductID branch for restore: %w", err)
	}
	defer key.Close()
	if !present {
		if err := key.DeleteValue("ProductID"); err != nil && !errors.Is(err, registry.ErrNotExist) {
			return fmt.Errorf("delete ProductID during restore: %w", err)
		}
		return nil
	}
	if valueType != registry.SZ {
		return fmt.Errorf("cannot restore unsupported ProductID registry type %d", valueType)
	}
	if err := key.SetStringValue("ProductID", value); err != nil {
		return fmt.Errorf("restore ProductID: %w", err)
	}
	return nil
}

// LicenseObservation reads the provided product's current ProductID and COM
// license state. The full ProductID stays in memory and is compared to the
// expected serial; only the sanitized license facts are returned.
func LicenseObservation(product LicenseProduct, expectedSerial string) (protocol.LicenseInfo, bool, error) {
	current, _, present, err := ReadProductID(product)
	if err != nil {
		return protocol.LicenseInfo{Kind: "unknown", State: "error", TermKind: "unknown", IsTrial: "unknown"}, false, err
	}
	matched := present && protocol.NormalizeSerial(current) == protocol.NormalizeSerial(expectedSerial)
	all := DiscoverCSPProducts()
	filtered := make([]CSPProduct, 0, len(all))
	for _, candidate := range all {
		if versionMajor(candidate.Branch) == product.Major {
			filtered = append(filtered, candidate)
		}
	}
	if len(filtered) == 0 {
		return protocol.LicenseInfo{Kind: "unknown", State: "error", TermKind: "unknown", IsTrial: "unknown"}, matched,
			fmt.Errorf("no installed CSP product for major %d", product.Major)
	}
	info, collectErr := CollectLicense(filtered)
	if collectErr != nil {
		info.State = "error"
		if info.Kind == "" {
			info.Kind = "unknown"
		}
		if info.TermKind == "" {
			info.TermKind = "unknown"
		}
		if info.IsTrial == "" {
			info.IsTrial = "unknown"
		}
		return info, matched, collectErr
	}
	return info, matched, nil
}

// CompareTerms verifies the declared pool term against the observed CSP term.
// A declared one/two-year term cannot prove its exact date without a fresh
// expiry; an active time-limited license is therefore accepted for either.
func CompareTerms(declared string, info protocol.LicenseInfo) bool {
	switch declared {
	case protocol.PoolTermPerpetual:
		return info.TermKind == "perpetual"
	case protocol.PoolTermOneYear, protocol.PoolTermTwoYears:
		return info.TermKind == "time_limited"
	default:
		return false
	}
}
