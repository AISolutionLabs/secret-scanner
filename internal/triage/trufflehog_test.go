// SPDX-License-Identifier: Apache-2.0

package triage

import (
	"fmt"
	"strings"
	"testing"
)

// permutations returns every ordering of xs.
func permutations(xs []string) [][]string {
	if len(xs) <= 1 {
		return [][]string{append([]string(nil), xs...)}
	}
	var out [][]string
	for i := range xs {
		rest := append(append([]string(nil), xs[:i]...), xs[i+1:]...)
		for _, p := range permutations(rest) {
			out = append(out, append([]string{xs[i]}, p...))
		}
	}
	return out
}

// thLine builds a trufflehog JSON line whose SourceMetadata.Data members
// appear in the given order.
func thLine(sourceName, secret string, members []string) string {
	return fmt.Sprintf(`{"SourceMetadata":{"Data":{%s}},"SourceName":%q,"DetectorName":"Github","Verified":false,"Raw":%q}`,
		strings.Join(members, ","), sourceName, secret)
}

// The location a trufflehog finding is checked against must not depend on
// the order of its metadata entries, and conflicting entries must never be
// resolved by picking one.
func TestTrufflehogSourceIsDeterministic(t *testing.T) {
	pat := tok("ghp_", 36, 7)
	tr := setup(t, map[string]string{
		"app.py":   "GH = \"" + pat + "\"\n",
		"other.py": "x = 1\n",
	})
	fs := `"Filesystem":{"file":"app.py","line":1}`
	fsOther := `"Filesystem":{"file":"other.py","line":1}`
	git := `"Git":{"file":"app.py","line":1,"commit":"","repository":"r"}`
	gitOther := `"Git":{"file":"other.py","line":1,"commit":""}`
	s3 := `"S3":{"bucket":"b","key":"k"}` // no file: never a candidate

	cases := []struct {
		name, sourceName string
		members          []string
		wantFile         string
		wantTriage       string
		wantEvidence     string
	}{
		{"single entry", "trufflehog - filesystem", []string{fs}, "app.py", Confirmed, ""},
		{"agreeing entries", "", []string{fs, git, s3}, "app.py", Confirmed, ""},
		{"disagreeing, origin picks one", "trufflehog - filesystem", []string{fs, gitOther}, "app.py", Confirmed, ""},
		{"disagreeing, origin picks the other", "trufflehog - git", []string{fsOther, git}, "app.py", Confirmed, ""},
		{"disagreeing, no origin", "", []string{fs, gitOther, s3}, "", Uncorroborated, "disagree"},
		{"disagreeing, unknown origin", "trufflehog - gcs", []string{fs, gitOther}, "", Uncorroborated, "disagree"},
		{"no file at all", "trufflehog - s3", []string{s3}, "", Uncorroborated, "names no file"},
	}
	for _, c := range cases {
		var first string
		for _, order := range permutations(c.members) {
			kind, ins, err := Parse([]byte(thLine(c.sourceName, pat, order)))
			if err != nil || kind != "trufflehog" || len(ins) != 1 {
				t.Fatalf("%s: parse %v %v %v", c.name, kind, ins, err)
			}
			in := ins[0]
			f := tr.Evaluate(in)
			got := fmt.Sprintf("%s|%d|%s|%s|%v", in.File, in.StartLine, in.Commit, f.Triage, f.Evidence)
			if first == "" {
				first = got
			} else if got != first {
				t.Errorf("%s: result depends on metadata order:\n  %s\n  %s", c.name, first, got)
			}
			if in.File != c.wantFile || !strings.HasPrefix(f.Triage, c.wantTriage) {
				t.Errorf("%s %v: file %q triage %q (%v), want %q %q", c.name, order, in.File, f.Triage, f.Evidence, c.wantFile, c.wantTriage)
			}
			if c.wantEvidence != "" && !strings.Contains(strings.Join(f.Evidence, " "), c.wantEvidence) {
				t.Errorf("%s: evidence %v lacks %q", c.name, f.Evidence, c.wantEvidence)
			}
		}
	}
}

// An unresolved location is never read: a conflicting entry pointing at a
// file whose content would filter the value must not suppress the finding.
func TestTrufflehogConflictingSourceCannotFilter(t *testing.T) {
	tr := setup(t, map[string]string{
		"real.env":  "API_SECRET=" + tok("", 40, 9) + "\n",
		"decoy.txt": "API_SECRET=isOnDemandRevalidate\n", // would be filtered as a word
	})
	line := thLine("", "isOnDemandRevalidate", []string{
		`"Filesystem":{"file":"decoy.txt","line":1}`, `"Git":{"file":"real.env","line":1}`})
	_, ins, err := Parse([]byte(line))
	if err != nil {
		t.Fatal(err)
	}
	f := tr.Evaluate(ins[0])
	if f.Triage != Uncorroborated || ins[0].File != "" {
		t.Errorf("conflicting sources: triage %q file %q, want uncorroborated with no file read", f.Triage, ins[0].File)
	}
}
