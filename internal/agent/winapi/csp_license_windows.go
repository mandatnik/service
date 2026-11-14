//go:build windows

package winapi

import (
	"fmt"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/go-ole/go-ole"
	"golang.org/x/sys/windows/registry"
	"telehack2026/internal/licenseclass"
	"telehack2026/internal/protocol"
)

// CollectLicenses reads CPCSPLicense for every installed CSP product and
// returns records with a non-empty serial-derived license_id. The second
// result is the best candidate for the legacy single LicenseInfo field, even
// when its serial could not be read.
func CollectLicenses(products []CSPProduct) ([]protocol.LicenseInfo, protocol.LicenseInfo, error) {
	fallback := protocol.LicenseInfo{
		Kind:       "unknown",
		State:      "unknown",
		TermKind:   "unknown",
		IsTrial:    "unknown",
		KindSource: "CPCSPLicense.GetType",
		Source:     "CPCSPLicense",
	}
	if len(products) == 0 {
		fallback.State = "not_installed"
		return nil, fallback, nil
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if err := ole.CoInitializeEx(0, ole.COINIT_APARTMENTTHREADED); err != nil {
		if oleErr, ok := err.(*ole.OleError); !ok || oleErr.Code() != 1 { // S_FALSE is success
			fallback.State = "error"
			fallback.Error = "CoInitializeEx: " + err.Error()
			return nil, fallback, err
		}
	}
	defer ole.CoUninitialize()

	clsid, err := ole.CLSIDFromProgID("CPCSPLicense.CPCSPLicense")
	if err != nil {
		fallback.State = "error"
		fallback.Error = "CPCSPLicense CLSID: " + err.Error()
		return nil, fallback, err
	}
	unknown, err := ole.CreateInstance(clsid, ole.IID_IDispatch)
	if err != nil {
		fallback.State = "error"
		fallback.Error = "create CPCSPLicense: " + err.Error()
		return nil, fallback, err
	}
	defer unknown.Release()
	dispatch, err := unknown.QueryInterface(ole.IID_IDispatch)
	if err != nil {
		fallback.State = "error"
		fallback.Error = "CPCSPLicense IDispatch: " + err.Error()
		return nil, fallback, err
	}
	defer dispatch.Release()

	sort.Slice(products, func(i, j int) bool { return products[i].Branch > products[j].Branch })
	var records []protocol.LicenseInfo
	var lastErr error
	for _, product := range products {
		candidate, err := queryLicense(dispatch, product)
		if fallback.Kind == "unknown" && candidate.Kind != "unknown" {
			fallback = candidate
		}
		if err != nil {
			lastErr = err
			candidate.Error = err.Error()
			continue
		}
		if candidate.LicenseID != "" {
			records = append(records, candidate)
		}
	}
	if lastErr != nil && len(records) == 0 {
		fallback.Error = lastErr.Error()
	}
	return records, fallback, lastErr
}

func queryLicense(dispatch *ole.IDispatch, product CSPProduct) (protocol.LicenseInfo, error) {
	info := protocol.LicenseInfo{
		Kind:        "unknown",
		State:       "unknown",
		TermKind:    "unknown",
		IsTrial:     "unknown",
		KindSource:  "CPCSPLicense.GetType",
		Source:      "CPCSPLicense",
		Product:     "csp",
		ProductCode: 0,
		ProductName: product.DisplayName,
	}
	if info.ProductName == "" {
		info.ProductName = "КриптоПро CSP"
	}
	kindVariant, err := dispatch.CallMethod("GetType", product.GUID)
	if err != nil {
		return info, fmt.Errorf("GetType(%s): %w", product.GUID, err)
	}
	defer kindVariant.Clear()
	raw, err := variantI32(kindVariant)
	if err != nil {
		return info, fmt.Errorf("GetType(%s): %w", product.GUID, err)
	}
	info.KindRaw = fmt.Sprintf("%d", raw)
	info.Kind = licenseclass.KindFromRaw(raw)

	expireVariant, err := dispatch.CallMethod("GetExpireDate", product.GUID)
	if err != nil {
		info.State = "error"
		return info, fmt.Errorf("GetExpireDate(%s): %w", product.GUID, err)
	}
	defer expireVariant.Clear()
	wallClock, err := variantTime(expireVariant)
	if err != nil {
		info.State = "error"
		return info, fmt.Errorf("GetExpireDate(%s): %w", product.GUID, err)
	}
	rawText := wallClock.Format("2006-01-02T15:04:05")
	localWall := time.Date(wallClock.Year(), wallClock.Month(), wallClock.Day(), wallClock.Hour(), wallClock.Minute(), wallClock.Second(), 0, time.Local)
	info.ValidToRaw = rawText
	info.ValidToUTC = localWall.UTC().Format(time.RFC3339)
	info.TimeBasis = "system_local_assumed"
	info.TermKind = licenseclass.TermKind(true)
	info.State = licenseclass.StateFromWallClock(localWall, time.Now())

	serial, serialErr := ReadLicenseSerial(product.GUID)
	if serialErr != nil {
		info.Complete = false
		info.Error = "serial: " + serialErr.Error()
		return info, nil
	}
	licenseID, err := protocol.LicenseIDFromSerial(serial)
	if err != nil {
		info.Complete = false
		info.Error = "serial: " + err.Error()
		return info, nil
	}
	masked, err := protocol.MaskLicenseSerial(serial)
	if err != nil {
		info.Complete = false
		info.Error = "serial: " + err.Error()
		return info, nil
	}
	info.LicenseID = licenseID
	info.SerialMasked = masked
	info.Complete = true
	return info, nil
}

// ReadLicenseSerial reads the MSI ProductID for a CryptoPro CSP product. The
// value is the license serial without separators. The full serial never leaves
// the workstation: the agent stores only its hash and masked form.
func ReadLicenseSerial(productGUID string) (string, error) {
	compressed, err := msiCompressedGUID(productGUID)
	if err != nil {
		return "", err
	}
	relative := `SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\Products\` +
		compressed + `\InstallProperties`
	views := []uint32{registry.WOW64_64KEY, registry.WOW64_32KEY, 0}
	var lastErr error
	for _, view := range views {
		key, err := registry.OpenKey(registry.LOCAL_MACHINE, relative, registry.READ|view)
		if err != nil {
			lastErr = err
			continue
		}
		value, _, err := key.GetStringValue("ProductID")
		_ = key.Close()
		if err != nil {
			lastErr = err
			continue
		}
		value = strings.TrimSpace(value)
		if value == "" {
			lastErr = fmt.Errorf("ProductID is empty")
			continue
		}
		return value, nil
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("ProductID not found")
	}
	return "", fmt.Errorf("read ProductID for %s: %w", productGUID, lastErr)
}

// msiCompressedGUID converts an MSI ProductCode GUID to the registry product
// key form used below UserData\S-1-5-18\Products.
func msiCompressedGUID(guid string) (string, error) {
	trimmed := strings.TrimSpace(strings.Trim(guid, "{}"))
	parts := strings.Split(trimmed, "-")
	if len(parts) != 5 || len(parts[0]) != 8 || len(parts[1]) != 4 || len(parts[2]) != 4 || len(parts[3]) != 4 || len(parts[4]) != 12 {
		return "", fmt.Errorf("invalid product GUID %q", guid)
	}
	compressed := reverseString(parts[0]) + reverseString(parts[1]) + reverseString(parts[2]) +
		swapPairs(parts[3]) + swapPairs(parts[4])
	return strings.ToUpper(compressed), nil
}

func reverseString(value string) string {
	runes := []rune(value)
	for left, right := 0, len(runes)-1; left < right; left, right = left+1, right-1 {
		runes[left], runes[right] = runes[right], runes[left]
	}
	return string(runes)
}

func swapPairs(value string) string {
	if len(value)%2 != 0 {
		return value
	}
	out := []byte(value)
	for index := 0; index < len(out); index += 2 {
		out[index], out[index+1] = out[index+1], out[index]
	}
	return string(out)
}

func variantI32(variant *ole.VARIANT) (int32, error) {
	if variant == nil {
		return 0, fmt.Errorf("nil VARIANT")
	}
	switch value := variant.Value().(type) {
	case int32:
		return value, nil
	case int16:
		return int32(value), nil
	case uint32:
		if value > 0x7fffffff {
			return 0, fmt.Errorf("type code out of range: %d", value)
		}
		return int32(value), nil
	case int64:
		if value < -0x80000000 || value > 0x7fffffff {
			return 0, fmt.Errorf("type code out of range: %d", value)
		}
		return int32(value), nil
	default:
		return 0, fmt.Errorf("unexpected VARIANT %s", variant.VT.String())
	}
}

func variantTime(variant *ole.VARIANT) (time.Time, error) {
	if variant == nil {
		return time.Time{}, fmt.Errorf("nil VARIANT")
	}
	switch value := variant.Value().(type) {
	case time.Time:
		return value, nil
	case float64:
		// OLE Automation date: days since 1899-12-30. Treat the result as a
		// wall-clock value; the caller records the time basis explicitly.
		return time.Date(1899, 12, 30, 0, 0, 0, 0, time.UTC).Add(time.Duration(value * 24 * float64(time.Hour))), nil
	default:
		return time.Time{}, fmt.Errorf("unexpected date VARIANT %s", variant.VT.String())
	}
}

// CollectCSP collects presence, product/core versions and license state. A
// missing CSP is a complete result with Present=false; an unreadable COM
// license or missing core version makes only CSP collection partial.
func CollectCSP() protocol.CSPResult {
	products := DiscoverCSPProducts()
	result := protocol.CSPResult{
		Scanned:  true,
		Complete: true,
		Present:  len(products) > 0,
		Products: make([]protocol.CSPProduct, 0, len(products)),
		License: protocol.LicenseInfo{
			Kind:       "unknown",
			State:      "unknown",
			TermKind:   "unknown",
			IsTrial:    "unknown",
			KindSource: "CPCSPLicense.GetType",
			Source:     "CPCSPLicense",
		},
	}
	for _, product := range products {
		result.Products = append(result.Products, protocol.CSPProduct{
			ProductGUID:    product.GUID,
			DisplayName:    product.DisplayName,
			DisplayVersion: product.DisplayVersion,
			Branch:         product.Branch,
		})
	}
	versions, versionErr := ReadCSPVersions()
	if versions.Product != "" {
		result.Present = true
		result.ProductVersion = versions.Product
	}
	if versions.Core != "" {
		result.CoreVersion = versions.Core
	}
	if versions.Source != "" {
		// csptest exists, so the product is present even if the version probe
		// failed. An absent executable with no uninstall entry is a complete
		// "not installed" result.
		result.Present = true
	}
	if result.ProductVersion == "" && len(products) > 0 {
		result.ProductVersion = products[0].DisplayVersion
	}
	if !result.Present {
		result.License.State = "not_installed"
		return result
	}
	if versionErr != nil {
		result.Complete = false
		result.Error = appendCSPError(result.Error, "version probe: "+versionErr.Error())
	}
	licenses, fallback, licenseErr := CollectLicenses(products)
	result.License = fallback
	result.Licenses = licenses
	if licenseErr != nil {
		result.Complete = false
		result.Error = appendCSPError(result.Error, "license: "+licenseErr.Error())
	}
	return result
}

func appendCSPError(existing, message string) string {
	if existing == "" {
		return boundCSPError(message)
	}
	return boundCSPError(existing + "; " + message)
}

func boundCSPError(value string) string {
	if len(value) <= protocol.MaxErrorBytes {
		return value
	}
	return value[:protocol.MaxErrorBytes]
}
