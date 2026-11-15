package store

import (
	"encoding/asn1"
	"mandatnik/internal/certparse"
	"testing"
)

func TestCertificateNameDetails(t *testing.T) {
	name := certparse.Name{RDNs: []certparse.RDN{{Attributes: []certparse.Attribute{
		{Type: asn1.ObjectIdentifier{2, 5, 4, 3}, Value: `ООО «КОМПАНИЯ»`},
		{Type: asn1.ObjectIdentifier{2, 5, 4, 4}, Value: "ПЕСТОВО"},
		{Type: asn1.ObjectIdentifier{2, 5, 4, 42}, Value: "ВЕРА БОРИСОВНА"},
		{Type: asn1.ObjectIdentifier{2, 5, 4, 12}, Value: "Директор"},
		{Type: asn1.ObjectIdentifier{1, 2, 643, 100, 4}, Value: "6658372383"},
		{Type: certparse.OIDINN, Value: "665907737544"},
		{Type: certparse.OIDSNILS, Value: "02271358019"},
		{Type: asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 1}, Value: "person@example.test"},
	}}}}
	details := certificateNameDetails(name)
	if !details.LegalEntity || details.Title != "Директор" || details.PersonName != "ПЕСТОВО ВЕРА БОРИСОВНА" || details.INNLegal != "6658372383" || details.INN != "665907737544" || details.SNILS != "02271358019" || details.Email != "person@example.test" {
		t.Fatalf("unexpected details: %+v", details)
	}
	// Employee certificates with a personal CN retain personal name presentation.
	name.RDNs[0].Attributes[0].Value = "ПЕСТОВО ВЕРА БОРИСОВНА"
	if certificateNameDetails(name).LegalEntity {
		t.Fatal("personal CN classified as a company")
	}
}
