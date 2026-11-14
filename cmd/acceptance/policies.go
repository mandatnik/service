package main

import (
	"context"
	"telehack2026/internal/protocol"
)

func (c *contract) policyReportTransitions(ctx context.Context, id *identity, a, b protocol.ObservedCertificate) {
	send := func(label string, report protocol.Report) {
		_, result, err := c.client.report(ctx, id, report)
		c.expectStatus(label, result, err, 200, "", nil)
	}
	legacy := withHostname(baseReport(3, "complete", nil, []protocol.ObservedCertificate{a}, true), id.Hostname)
	send("legacy folder baseline", legacy)
	makePolicy := func(seq int64, certs []protocol.ObservedCertificate, complete bool) protocol.Report {
		report := withHostname(baseReport(seq, "complete", nil, certs, true), id.Hostname)
		source := report.Sources[1]
		source.SourceKey = "folder-policies"
		source.Path = "folder-policies"
		source.Complete = complete
		if !complete {
			source.Error = "synthetic partial policy traversal"
		}
		// Two certificates in a single .cer file are distinct observations.
		for i := range source.Files {
			source.Files[i].Path = `C:\Acceptance\bundle.cer`
		}
		report.Sources = []protocol.SourceResult{source}
		report.Status = report.ComputeStatus()
		return report
	}
	send("partial policy scan after legacy", makePolicy(5, nil, false))
	c.check("partial policy scan preserves legacy observations", c.observationAllActive(id.MachineID, []string{a.SHA256}), nil)
	send("successful empty policy scan revokes legacy folders", makePolicy(6, nil, true))
	c.check("legacy observations retired by successful policy scan", c.observationAllInactive(id.MachineID, []string{a.SHA256}), nil)
	delayed := withHostname(baseReport(4, "complete", nil, []protocol.ObservedCertificate{a}, true), id.Hostname)
	send("delayed legacy report after policy revocation", delayed)
	c.check("delayed legacy report cannot resurrect revoked certificate", c.observationAllInactive(id.MachineID, []string{a.SHA256}), nil)
	send("policy bundle with two certificates", makePolicy(7, []protocol.ObservedCertificate{a, b}, true))
	send("policy bundle removes one certificate", makePolicy(8, []protocol.ObservedCertificate{a}, true))
	c.check("remaining certificate in the same file stays active", c.observationAllActive(id.MachineID, []string{a.SHA256}), nil)
	c.check("missing certificate in the same file is retired", c.observationAllInactive(id.MachineID, []string{b.SHA256}), nil)
}
