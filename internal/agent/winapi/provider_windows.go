//go:build windows

package winapi

import (
	"errors"
	"fmt"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"mandatnik/internal/licenseclass"
	"mandatnik/internal/protocol"
)

const (
	certKeyProvInfoPropID = 2
	certKeyContextPropID  = 5
	certNCryptKeySpec     = 0xFFFFFFFF
)

var (
	procCertGetCertificateContextProperty = crypt32.NewProc("CertGetCertificateContextProperty")
	cryptENotFoundProvider                = syscall.Errno(0x80092004)
)

// cryptKeyProvInfo mirrors CRYPT_KEY_PROV_INFO on 64-bit Windows. Pointers are
// read only while the CERT_CONTEXT is alive; they are never dereferenced after
// the context is released.
type cryptKeyProvInfo struct {
	ContainerName  *uint16
	ProvName       *uint16
	ProvType       uint32
	Flags          uint32
	ProvParamCount uint32
	_              uint32
	ProvParams     uintptr
	KeySpec        uint32
	_              uint32
}

// readProviderBindings reads CERT_KEY_PROV_INFO_PROP_ID before the context is
// freed. It intentionally does not acquire a private-key handle, does not check
// a PIN and does not start a media dialog.
func readProviderBindings(ctx *windows.CertContext) protocol.ProviderBinding {
	binding := protocol.ProviderBinding{
		BindingState:       "absent",
		ProviderOwner:      licenseclass.ProviderOwnerUnknown,
		AttributionSource:  licenseclass.ProviderAttributionSource,
		AttributionVersion: licenseclass.ProviderAttributionVersion,
		PrivateKeyState:    "not_checked",
		ObservedAt:         time.Now().UTC().Format(time.RFC3339Nano),
	}
	if ctx == nil {
		binding.BindingState = "unreadable"
		binding.MetadataErrorCode = "nil_context"
		return binding
	}
	var size uint32
	ok, _, lastErr := procCertGetCertificateContextProperty.Call(
		uintptr(unsafe.Pointer(ctx)), certKeyProvInfoPropID, 0, uintptr(unsafe.Pointer(&size)))
	if ok == 0 {
		if errors.Is(lastErr, cryptENotFoundProvider) || errors.Is(lastErr, windows.ERROR_NOT_FOUND) {
			return readCNGKeyContext(ctx, binding)
		}
		binding.BindingState = "unreadable"
		binding.MetadataErrorCode = errorCode(lastErr)
		return binding
	}
	if size < uint32(unsafe.Sizeof(cryptKeyProvInfo{})) || size > 64*1024 {
		binding.BindingState = "unreadable"
		binding.MetadataErrorCode = "invalid_provider_info_size"
		return binding
	}
	raw := make([]byte, size)
	ok, _, lastErr = procCertGetCertificateContextProperty.Call(
		uintptr(unsafe.Pointer(ctx)), certKeyProvInfoPropID,
		uintptr(unsafe.Pointer(&raw[0])), uintptr(unsafe.Pointer(&size)))
	if ok == 0 {
		binding.BindingState = "unreadable"
		binding.MetadataErrorCode = errorCode(lastErr)
		return binding
	}
	if len(raw) < int(unsafe.Sizeof(cryptKeyProvInfo{})) {
		binding.BindingState = "unreadable"
		binding.MetadataErrorCode = "short_provider_info"
		return binding
	}
	info := (*cryptKeyProvInfo)(unsafe.Pointer(&raw[0]))
	providerName := ""
	if info.ProvName != nil {
		providerName = windows.UTF16PtrToString(info.ProvName)
	}
	api := "capi"
	if strings.HasSuffix(strings.ToLower(strings.TrimSpace(providerName)), "key storage provider") || info.KeySpec == certNCryptKeySpec {
		api = "cng"
	}
	owner, source, version := licenseclass.AttributeProvider(providerName, api, "present")
	binding.ProviderName = providerName
	binding.ProviderAPI = api
	binding.ProviderType = info.ProvType
	binding.KeySpec = info.KeySpec
	binding.BindingState = "present"
	binding.ProviderOwner = owner
	binding.AttributionSource = source
	binding.AttributionVersion = version
	if info.ProvName == nil && info.ContainerName == nil {
		// The property exists but carries no usable provider name. Record it as
		// unreadable metadata rather than claiming a non-CryptoPro provider.
		binding.BindingState = "unreadable"
		binding.MetadataErrorCode = "empty_provider_name"
	}
	return binding
}

func errorCode(err error) string {
	if err == nil {
		return "unknown"
	}
	var errno syscall.Errno
	if errors.As(err, &errno) {
		return fmt.Sprintf("0x%08X", uint32(errno))
	}
	return "windows_error"
}

type certKeyContext struct {
	Size      uint32
	Flags     uint32
	CryptProv uintptr
	KeySpec   uint32
	NCryptKey uintptr
}

// readCNGKeyContext handles certificates bound through a CNG/KSP key context
// when CERT_KEY_PROV_INFO is absent. The provider name may be unavailable, so
// attribution stays unknown unless a real provider table entry can be read.
func readCNGKeyContext(ctx *windows.CertContext, binding protocol.ProviderBinding) protocol.ProviderBinding {
	var size uint32
	ok, _, lastErr := procCertGetCertificateContextProperty.Call(
		uintptr(unsafe.Pointer(ctx)), certKeyContextPropID, 0, uintptr(unsafe.Pointer(&size)))
	if ok == 0 {
		if errors.Is(lastErr, cryptENotFoundProvider) || errors.Is(lastErr, windows.ERROR_NOT_FOUND) {
			return binding
		}
		binding.BindingState = "unreadable"
		binding.MetadataErrorCode = errorCode(lastErr)
		return binding
	}
	if size < uint32(unsafe.Sizeof(certKeyContext{})) || size > 64 {
		binding.BindingState = "unreadable"
		binding.MetadataErrorCode = "invalid_key_context_size"
		return binding
	}
	raw := make([]byte, size)
	ok, _, lastErr = procCertGetCertificateContextProperty.Call(
		uintptr(unsafe.Pointer(ctx)), certKeyContextPropID,
		uintptr(unsafe.Pointer(&raw[0])), uintptr(unsafe.Pointer(&size)))
	if ok == 0 {
		binding.BindingState = "unreadable"
		binding.MetadataErrorCode = errorCode(lastErr)
		return binding
	}
	contextInfo := (*certKeyContext)(unsafe.Pointer(&raw[0]))
	if contextInfo.KeySpec != certNCryptKeySpec && contextInfo.NCryptKey == 0 {
		return binding
	}
	binding.BindingState = "present"
	binding.ProviderAPI = "cng"
	binding.KeySpec = contextInfo.KeySpec
	binding.ProviderOwner = licenseclass.ProviderOwnerUnknown
	binding.AttributionSource = licenseclass.ProviderAttributionSource
	binding.AttributionVersion = licenseclass.ProviderAttributionVersion
	binding.MetadataErrorCode = "provider_name_unavailable"
	return binding
}
