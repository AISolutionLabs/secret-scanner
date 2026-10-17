// SPDX-License-Identifier: Apache-2.0

package triage

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/AISolutionLabs/secret-scanner/internal/detect"
	"github.com/AISolutionLabs/secret-scanner/internal/report"
)

// Triage output in SARIF keeps each finding's provenance: the tool that
// reported it, its triage status (a filtered finding must not read as a
// plain note) and its commit, and secretscan's SARIF can be triaged again
// without losing them.
func TestSARIFKeepsTriageProvenance(t *testing.T) {
	commit := "0123456789abcdef0123456789abcdef01234567"
	in := []detect.Finding{
		{RuleID: "generic-api-key", File: "a.py", StartLine: 3, Secret: "x", Commit: commit, Source: "gitleaks", Triage: "filtered: uuid", Confidence: detect.Low},
		{RuleID: "Github", File: "b.py", StartLine: 1, Secret: "y", Source: "trufflehog", Triage: Confirmed, Confidence: detect.High, Blocking: true},
	}
	var buf bytes.Buffer
	if err := report.SARIF(&buf, in, nil, "test"); err != nil {
		t.Fatal(err)
	}
	var log struct {
		Runs []struct {
			Results []struct {
				PartialFingerprints map[string]string `json:"partialFingerprints"`
				Properties          map[string]any    `json:"properties"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(buf.Bytes(), &log); err != nil {
		t.Fatal(err)
	}
	res := log.Runs[0].Results
	if res[0].Properties["triage"] != "filtered: uuid" || res[0].Properties["source"] != "gitleaks" || res[0].PartialFingerprints["commitSha"] != commit {
		t.Errorf("SARIF result lost provenance: %+v", res[0])
	}
	if res[1].Properties["triage"] != Confirmed || res[1].Properties["source"] != "trufflehog" {
		t.Errorf("SARIF result lost provenance: %+v", res[1])
	}
	kind, back, err := Parse(buf.Bytes())
	if err != nil || kind != "sarif" || len(back) != 2 {
		t.Fatalf("re-parse: %s %d %v", kind, len(back), err)
	}
	if back[0].Commit != commit || back[0].Tool != "gitleaks" || back[1].Tool != "trufflehog" || back[0].File != "a.py" || back[0].StartLine != 3 {
		t.Errorf("re-parsed inputs lost provenance: %+v", back)
	}
}
