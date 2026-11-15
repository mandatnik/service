//go:build windows

package agent

import (
	"fmt"
	"time"

	"mandatnik/internal/agent/winapi"
	"mandatnik/internal/protocol"
)

type windowsInstallExecutor struct{}

func newInstallExecutor() InstallExecutor { return windowsInstallExecutor{} }

func (windowsInstallExecutor) product(spec protocol.LicensePoolSpec) (winapi.LicenseProduct, error) {
	products, err := winapi.DiscoverLicenseProducts()
	if err != nil {
		return winapi.LicenseProduct{}, err
	}
	for _, product := range products {
		if product.Major == spec.CSPMajorVersion {
			return product, nil
		}
	}
	return winapi.LicenseProduct{}, fmt.Errorf("no installed CryptoPro CSP %d product branch", spec.CSPMajorVersion)
}

func (e windowsInstallExecutor) Inspect(expectedSerial string, spec protocol.LicensePoolSpec) (InstallSnapshot, error) {
	product, err := e.product(spec)
	if err != nil {
		return InstallSnapshot{}, err
	}
	info, serialMatch, licenseErr := winapi.LicenseObservation(product, expectedSerial)
	snapshot := InstallSnapshot{
		Present: true, ProductMajor: product.Major, ProductVersion: product.DisplayVersion,
		ProductGUID: product.ProperGUID, PackedProductGUID: product.PackedGUID,
		SerialMatch: serialMatch, License: info, Environment: winapi.DiscoverEnvironment(),
		CollectedAt: time.Now().UTC(),
	}
	current, valueType, present, readErr := winapi.ReadProductID(product)
	if readErr != nil {
		return snapshot, readErr
	}
	snapshot.OriginalType = valueType
	snapshot.OriginalPresent = present
	if present {
		if valueType != 1 { // REG_SZ
			return snapshot, fmt.Errorf("ProductID has unsupported registry type %d", valueType)
		}
		snapshot.CurrentSerial = current
	}
	return snapshot, licenseErr
}

func (e windowsInstallExecutor) Write(snapshot InstallSnapshot, serial string) error {
	product, err := e.product(protocol.LicensePoolSpec{CSPMajorVersion: snapshot.ProductMajor})
	if err != nil {
		return err
	}
	if product.PackedGUID != snapshot.PackedProductGUID || product.ProperGUID != snapshot.ProductGUID {
		return fmt.Errorf("installed CSP product branch changed")
	}
	return winapi.WriteProductID(product, serial)
}

func (e windowsInstallExecutor) Verify(expectedSerial string, spec protocol.LicensePoolSpec) (InstallSnapshot, bool, error) {
	snapshot, err := e.Inspect(expectedSerial, spec)
	if err != nil {
		return snapshot, false, err
	}
	ok := snapshot.SerialMatch && snapshot.License.State == "active" &&
		snapshot.License.Kind == spec.LicenseKind && winapi.CompareTerms(spec.Term, snapshot.License)
	return snapshot, ok, nil
}

func (e windowsInstallExecutor) Restore(snapshot InstallSnapshot) error {
	product, err := e.product(protocol.LicensePoolSpec{CSPMajorVersion: snapshot.ProductMajor})
	if err != nil {
		return err
	}
	if product.PackedGUID != snapshot.PackedProductGUID {
		return fmt.Errorf("installed CSP product branch changed")
	}
	return winapi.RestoreProductID(product, snapshot.CurrentSerial, snapshot.OriginalType, snapshot.OriginalPresent)
}
