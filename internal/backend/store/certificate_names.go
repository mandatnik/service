package store

import (
	"encoding/asn1"
	"strings"

	"mandatnik/internal/certparse"
)

// CertificateNameDetails keeps subject and issuer attributes separate. Values
// are read from DER, never by splitting the rendered distinguished name.
type CertificateNameDetails struct {
	CommonName   string `json:"common_name,omitempty"`
	Organization string `json:"organization,omitempty"`
	Title        string `json:"title,omitempty"`
	PersonName   string `json:"person_name,omitempty"`
	INN          string `json:"inn,omitempty"`
	INNLegal     string `json:"inn_legal,omitempty"`
	SNILS        string `json:"snils,omitempty"`
	Email        string `json:"email,omitempty"`
	OGRN         string `json:"ogrn,omitempty"`
	OGRNIP       string `json:"ogrnip,omitempty"`
	KPP          string `json:"kpp,omitempty"`
	LegalEntity  bool   `json:"legal_entity"`
}

func certificateNameDetails(name certparse.Name) CertificateNameDetails {
	attr := func(oid asn1.ObjectIdentifier) string {
		value, _ := name.FindAttribute(oid)
		return strings.TrimSpace(value)
	}
	details := CertificateNameDetails{
		CommonName:   name.CommonName(),
		Organization: attr(asn1.ObjectIdentifier{2, 5, 4, 10}),
		Title:        attr(asn1.ObjectIdentifier{2, 5, 4, 12}),
		INN:          attr(certparse.OIDINN),
		INNLegal:     attr(asn1.ObjectIdentifier{1, 2, 643, 100, 4}),
		SNILS:        attr(certparse.OIDSNILS),
		Email:        attr(asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 1}),
		OGRN:         attr(certparse.OIDOGRN),
		OGRNIP:       attr(certparse.OIDOGRNIP),
		KPP:          attr(asn1.ObjectIdentifier{1, 2, 643, 3, 131, 1, 2}),
	}
	details.PersonName = strings.TrimSpace(attr(asn1.ObjectIdentifier{2, 5, 4, 4}) + " " + attr(asn1.ObjectIdentifier{2, 5, 4, 42}))
	// A personal CN stays personal even if the employer has legal identifiers.
	// Legal-entity CNs normally match O, or have no separate personal CN.
	details.LegalEntity = details.INNLegal != "" || details.OGRN != "" ||
		(details.Organization != "" && strings.EqualFold(details.CommonName, details.Organization))
	if details.PersonName != "" && strings.EqualFold(details.CommonName, details.PersonName) {
		details.LegalEntity = false
	}
	return details
}

func enrichCertificateNames(item *CertificateSummary, der []byte) {
	parsed, err := certparse.Parse(der)
	if err != nil {
		return
	}
	item.OwnerDetails = certificateNameDetails(parsed.Subject)
	item.IssuerDetails = certificateNameDetails(parsed.Issuer)
	item.Organization = item.OwnerDetails.Organization
	item.Department, _ = parsed.Subject.FindAttribute(asn1.ObjectIdentifier{2, 5, 4, 11})
	item.IssuerCN = item.IssuerDetails.CommonName
}
