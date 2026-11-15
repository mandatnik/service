package main

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"time"

	"mandatnik/internal/certparse"
	"mandatnik/internal/protocol"
)

const (
	acceptanceSID       = "S-1-5-21-1111111111-2222222222-3333333333-9001"
	acceptanceFolder    = `C:\Acceptance\certs`
	acceptanceProfileCN = "Acceptance User"
)

type fixtures struct {
	valid   []byte
	expired []byte
	future  []byte
	ip      []byte
}

func loadFixtures() (fixtures, error) {
	base := filepath.Join("test-data", "certificates-2026-11-14")
	read := func(name string) ([]byte, error) {
		return os.ReadFile(filepath.Join(base, "certificates", name))
	}
	var out fixtures
	var err error
	if out.valid, err = read("01-individual-valid.cer"); err != nil {
		return out, err
	}
	if out.expired, err = read("02-individual-expired.cer"); err != nil {
		return out, err
	}
	if out.future, err = read("03-individual-future.cer"); err != nil {
		return out, err
	}
	if out.ip, err = read("09-ip-valid.cer"); err != nil {
		return out, err
	}
	return out, nil
}

func observe(der []byte) (protocol.ObservedCertificate, error) {
	parsed, err := certparse.Parse(der)
	if err != nil {
		return protocol.ObservedCertificate{}, err
	}
	return protocol.ObservedCertificate{
		SHA256:             parsed.SHA256,
		DERBase64:          base64.StdEncoding.EncodeToString(der),
		SerialHex:          parsed.SerialHex,
		SerialNumber:       parsed.SerialNumber,
		Subject:            parsed.SubjectString,
		Issuer:             parsed.IssuerString,
		NotBefore:          parsed.NotBefore.Format(time.RFC3339),
		NotAfter:           parsed.NotAfter.Format(time.RFC3339),
		OwnerCN:            parsed.Subject.CommonName(),
		INN:                parsed.AttributeString(certparse.OIDINN),
		SNILS:              parsed.AttributeString(certparse.OIDSNILS),
		PublicKeyBits:      parsed.PublicKeyBits,
		SignatureAlgorithm: certparse.SignatureAlgorithmName(parsed.SignatureAlgorithm),
		EmbeddedLicense:    "absent",
	}, nil
}

func observedFixtures(data fixtures) ([]protocol.ObservedCertificate, error) {
	var out []protocol.ObservedCertificate
	for _, der := range [][]byte{data.valid, data.expired} {
		obs, err := observe(der)
		if err != nil {
			return nil, err
		}
		out = append(out, obs)
	}
	return out, nil
}

func baseReport(seq int64, status string, userCerts, folderCerts []protocol.ObservedCertificate, complete bool) protocol.Report {
	now := time.Now().UTC()
	profile := protocol.ProfileResult{
		SID: acceptanceSID, Name: acceptanceProfileCN, ProfilePath: `C:\Users\acceptance`,
		Loaded: false, StorePresent: true, Complete: complete,
	}
	userSource := protocol.SourceResult{
		SourceType: "user_store", SourceKey: acceptanceSID, DisplayName: acceptanceProfileCN,
		UserSID: acceptanceSID, Complete: complete, Certificates: userCerts,
	}
	if !complete {
		userSource.Error = "synthetic partial source"
	}
	var files []protocol.ObservedFile
	for _, cert := range folderCerts {
		files = append(files, protocol.ObservedFile{Path: acceptanceFolder + `\` + cert.SerialHex + ".cer", SHA256: cert.SHA256})
	}
	folderSource := protocol.SourceResult{
		SourceType: "folder", SourceKey: acceptanceFolder, DisplayName: acceptanceFolder,
		Path: acceptanceFolder, Complete: complete, Certificates: folderCerts, Files: files,
	}
	if !complete {
		folderSource.Error = "synthetic partial source"
	}
	return protocol.Report{
		ReportID:         protocol.NewUUID(),
		ScanSeq:          seq,
		CollectedAt:      now.Add(-2 * time.Second).Format(time.RFC3339Nano),
		StartedAt:        now.Add(-2 * time.Second).Format(time.RFC3339Nano),
		FinishedAt:       now.Format(time.RFC3339Nano),
		AgentVersion:     "acceptance-0.1.0",
		Hostname:         "unused",
		Status:           status,
		ProfilesComplete: true,
		Profiles:         []protocol.ProfileResult{profile},
		Sources:          []protocol.SourceResult{userSource, folderSource},
		CSP: protocol.CSPResult{
			Scanned: true, Complete: true, Present: true,
			ProductVersion: "5.0.13003", CoreVersion: "5.0.10013",
			Products: []protocol.CSPProduct{{ProductGUID: "{50F91F80-D397-437C-B0C8-62128DE3B55E}", DisplayName: "CryptoPro CSP", DisplayVersion: "5.0.13003", Branch: "5"}},
			License: protocol.LicenseInfo{
				Kind: "client", KindRaw: "0", KindSource: "CPCSPLicense.GetType", State: "active",
				ValidToRaw: "2027-02-14T18:59:59", ValidToUTC: "2027-02-14T13:59:59Z",
				TimeBasis: "system_local_assumed", TermKind: "time_limited", IsTrial: "unknown", Source: "CPCSPLicense",
			},
		},
	}
}

func withHostname(report protocol.Report, hostname string) protocol.Report {
	report.Hostname = hostname
	return report
}
