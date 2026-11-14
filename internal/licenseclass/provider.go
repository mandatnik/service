package licenseclass

import "strings"

// Provider attribution is deliberately table-driven. Certificate issuer,
// public-key algorithm, subject substrings and a generic "crypto" token are
// never used: the only evidence is the provider registered on the certificate
// context.
const (
	ProviderOwnerCryptoPro = "cryptopro"
	ProviderOwnerOther     = "other"
	ProviderOwnerUnknown   = "unknown"

	ProviderAttributionSource  = "certificate_context_provider_name"
	ProviderAttributionVersion = "1"
)

var cryptoProProviderPrefixes = []string{
	"crypto-pro",
	"cryptopro",
	"crypto pro",
	"криптопро",
}

var otherProviderPrefixes = []string{
	"microsoft",
	"microsoft corporation",
}

// AttributeProvider maps an observed provider name to an owner. bindingState
// must be present; absent or unreadable metadata never becomes "other".
func AttributeProvider(providerName, providerAPI, bindingState string) (owner, source, version string) {
	if bindingState != "present" {
		return ProviderOwnerUnknown, ProviderAttributionSource, ProviderAttributionVersion
	}
	normalized := normalizeProviderName(providerName)
	if normalized == "" {
		return ProviderOwnerUnknown, ProviderAttributionSource, ProviderAttributionVersion
	}
	for _, prefix := range cryptoProProviderPrefixes {
		if strings.HasPrefix(normalized, prefix) {
			// A CryptoPro-named KSP is still CryptoPro; the API is recorded
			// separately by the observation.
			return ProviderOwnerCryptoPro, ProviderAttributionSource, ProviderAttributionVersion
		}
	}
	for _, prefix := range otherProviderPrefixes {
		if strings.HasPrefix(normalized, prefix) {
			return ProviderOwnerOther, ProviderAttributionSource, ProviderAttributionVersion
		}
	}
	return ProviderOwnerUnknown, ProviderAttributionSource, ProviderAttributionVersion
}

func normalizeProviderName(value string) string {
	fields := strings.Fields(strings.ToLower(strings.TrimSpace(value)))
	return strings.Join(fields, " ")
}
