//go:build windows

package winapi

import (
	"fmt"
	"runtime"
	"sort"
	"time"

	"github.com/go-ole/go-ole"
	"telehack2026/internal/licenseclass"
	"telehack2026/internal/protocol"
)

// CollectLicense reads CPCSPLicense for the first installed product. It uses
// only the base COM component; CAdES is not a dependency. Raw type code and
// source are preserved even when classification is unknown.
func CollectLicense(products []CSPProduct) (protocol.LicenseInfo, error) {
	info := protocol.LicenseInfo{
		Kind:       "unknown",
		State:      "unknown",
		TermKind:   "unknown",
		IsTrial:    "unknown",
		KindSource: "CPCSPLicense.GetType",
		Source:     "CPCSPLicense",
	}
	if len(products) == 0 {
		info.State = "not_installed"
		return info, nil
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if err := ole.CoInitializeEx(0, ole.COINIT_APARTMENTTHREADED); err != nil {
		if oleErr, ok := err.(*ole.OleError); !ok || oleErr.Code() != 1 { // S_FALSE is success
			info.State = "error"
			info.Error = "CoInitializeEx: " + err.Error()
			return info, err
		}
	}
	defer ole.CoUninitialize()

	clsid, err := ole.CLSIDFromProgID("CPCSPLicense.CPCSPLicense")
	if err != nil {
		info.State = "error"
		info.Error = "CPCSPLicense CLSID: " + err.Error()
		return info, err
	}
	unknown, err := ole.CreateInstance(clsid, ole.IID_IDispatch)
	if err != nil {
		info.State = "error"
		info.Error = "create CPCSPLicense: " + err.Error()
		return info, err
	}
	defer unknown.Release()
	dispatch, err := unknown.QueryInterface(ole.IID_IDispatch)
	if err != nil {
		info.State = "error"
		info.Error = "CPCSPLicense IDispatch: " + err.Error()
		return info, err
	}
	defer dispatch.Release()

	sort.Slice(products, func(i, j int) bool { return products[i].Branch > products[j].Branch })
	var lastErr error
	for _, product := range products {
		candidate, err := queryLicense(dispatch, product)
		if err == nil {
			return candidate, nil
		}
		lastErr = err
		info = candidate
	}
	if lastErr != nil {
		info.Error = lastErr.Error()
		return info, lastErr
	}
	return info, nil
}

func queryLicense(dispatch *ole.IDispatch, product CSPProduct) (protocol.LicenseInfo, error) {
	info := protocol.LicenseInfo{
		Kind:       "unknown",
		State:      "unknown",
		TermKind:   "unknown",
		IsTrial:    "unknown",
		KindSource: "CPCSPLicense.GetType",
		Source:     "CPCSPLicense",
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
	return info, nil
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
	license, licenseErr := CollectLicense(products)
	result.License = license
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
