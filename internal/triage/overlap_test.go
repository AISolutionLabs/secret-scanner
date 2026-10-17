// SPDX-License-Identifier: Apache-2.0

package triage

import (
	"strings"
	"testing"
)

// A value secretscan filtered explains a reported finding only when it
// covers the whole reported value. A shorter filtered candidate that
// merely occurs inside it (a placeholder password on the same line as a
// longer reported token) says nothing about the token.
func TestFilteredCandidateMustCoverReportedValue(t *testing.T) {
	token := "VAULT-admin123-" + tok("", 24, 41)
	tr := setup(t, map[string]string{"tests/conf.py": `password = "admin123"  # legacy: ` + token + "\n"})
	f := tr.Evaluate(Input{Tool: "gitleaks", RuleID: "custom-vault", File: "tests/conf.py", StartLine: 1, Secret: token})
	if strings.HasPrefix(f.Triage, Filtered) {
		t.Errorf("reported token filtered by a shorter candidate's reason: %q %v", f.Triage, f.Evidence)
	}
	// The candidate itself is still filtered.
	f = tr.Evaluate(Input{Tool: "gitleaks", RuleID: "generic-password", File: "tests/conf.py", StartLine: 1, Secret: "admin123"})
	if !strings.HasPrefix(f.Triage, Filtered) {
		t.Errorf("placeholder not filtered: %q %v", f.Triage, f.Evidence)
	}
}
