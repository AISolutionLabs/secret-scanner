// SPDX-License-Identifier: Apache-2.0

package triage

import (
	"encoding/json"
	"math/rand"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/AISolutionLabs/secret-scanner/internal/config"
	"github.com/AISolutionLabs/secret-scanner/internal/detect"
)

func tok(prefix string, n int, seed int64) string {
	r := rand.New(rand.NewSource(seed))
	const cs = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, n)
	for i := range b {
		b[i] = cs[r.Intn(len(cs))]
	}
	return prefix + string(b)
}

func setup(t *testing.T, files map[string]string) *Triager {
	t.Helper()
	dir := t.TempDir()
	for name, body := range files {
		p := filepath.Join(dir, name)
		os.MkdirAll(filepath.Dir(p), 0o755)
		os.WriteFile(p, []byte(body), 0o644)
	}
	cfg, _, _ := config.Resolve(config.Options{})
	rs, _ := config.Compile(cfg)
	return New(detect.New(rs, detect.Options{RecordSuppressed: true, MaxDecodeDepth: 2}), dir)
}

func TestEvaluate(t *testing.T) {
	pat := tok("ghp_", 36, 1)
	generic := tok("", 32, 2)
	tr := setup(t, map[string]string{
		"app.py":       "GH = \"" + pat + "\"\nAPI_SECRET = \"" + generic + "\"\n",
		"Jenkinsfile":  "    [envVar: 'TF_VAR_APPROLESECRETID', vaultKey: 'inf-vsqt-01-secret-id']]]]) {\n",
		"images.yaml":  "image: reg.io/aws-cli@sha256:eaaa7b11777babe28e6133a8b19ff71cea687e0d7f05158dee95a71f76ce3d00\n",
		"vendor/x.txt": "custom_value = \"" + tok("", 24, 3) + "\"\n",
		"words.py":     "gh = \"ghp_Example" + tok("", 29, 4) + "\"\n",
	})
	cases := []struct {
		name string
		in   Input
		want string
		conf string
	}{
		{"provider token confirmed", Input{Tool: "gitleaks", RuleID: "github-pat", File: "app.py", StartLine: 1, Secret: pat}, Confirmed, detect.High},
		{"generic secret confirmed", Input{Tool: "gitleaks", RuleID: "generic-api-key", File: "app.py", StartLine: 2, Secret: generic}, Confirmed, detect.High},
		{"vault key name filtered", Input{Tool: "gitleaks", RuleID: "generic-api-key", File: "Jenkinsfile", StartLine: 1, Secret: "inf-vsqt-01-secret-id"}, Filtered, detect.Low},
		{"digest slice filtered", Input{Tool: "gitleaks", RuleID: "square-access-token", File: "images.yaml", StartLine: 1, Secret: "EAAA7b11777babe28e6133a8b19ff71cea687e0d7f05158dee95a71f76ce3d"}, Filtered, detect.Low}, // secretscan:allow (gitleaks#1468 fixture)
		{"verified always kept", Input{Tool: "trufflehog", RuleID: "Github", File: "missing.py", StartLine: 1, Secret: "anything", Verified: true}, Verified, detect.High},
		{"redacted kept for review", Input{Tool: "gitleaks", RuleID: "x", File: "vendor/x.txt", StartLine: 1, Secret: "REDACTED", Redacted: true}, Uncorroborated, detect.Medium},
		{"unreadable source kept", Input{Tool: "gitleaks", RuleID: "x", File: "nope.txt", StartLine: 1, Secret: "abc"}, Uncorroborated, detect.Medium},
		{"provider shape never word-filtered", Input{Tool: "gitleaks", RuleID: "github-pat", File: "words.py", StartLine: 1, Secret: "ghp_Example" + tok("", 29, 4)}, Confirmed, detect.High},
	}
	for _, c := range cases {
		f := tr.Evaluate(c.in)
		if !strings.HasPrefix(f.Triage, c.want) || f.Confidence != c.conf || len(f.Evidence) == 0 {
			t.Errorf("%s: got %q/%s %v, want %s/%s", c.name, f.Triage, f.Confidence, f.Evidence, c.want, c.conf)
		}
	}
}

func TestParseFormats(t *testing.T) {
	gl, _ := json.Marshal([]map[string]any{{"RuleID": "github-pat", "File": "a.py", "StartLine": 3, "Secret": "ghp_x"}})
	kind, in, err := Parse(gl)
	if err != nil || kind != "gitleaks" || len(in) != 1 || in[0].StartLine != 3 {
		t.Errorf("gitleaks: %s %+v %v", kind, in, err)
	}
	th := `{"SourceMetadata":{"Data":{"Filesystem":{"file":"b.env","line":7}}},"DetectorName":"Slack","Verified":true,"Raw":"xoxb-1"}` + "\n" +
		`{"level":"info","msg":"finished scanning"}` + "\n"
	kind, in, err = Parse([]byte(th))
	if err != nil || kind != "trufflehog" || len(in) != 1 || in[0].File != "b.env" || !in[0].Verified {
		t.Errorf("trufflehog: %s %+v %v", kind, in, err)
	}
	sarif := `{"$schema":"x","version":"2.1.0","runs":[{"tool":{"driver":{"name":"gitleaks"}},"results":[{"ruleId":"r","locations":[{"physicalLocation":{"artifactLocation":{"uri":"c.go"},"region":{"startLine":2,"snippet":{"text":"abc"}}}}]}]}]}`
	kind, in, err = Parse([]byte(sarif))
	if err != nil || kind != "sarif" || len(in) != 1 || in[0].File != "c.go" || in[0].Secret != "abc" || in[0].Tool != "gitleaks" {
		t.Errorf("sarif: %s %+v %v", kind, in, err)
	}
}

func TestFileAccessIsContained(t *testing.T) {
	outside := t.TempDir()
	secret := tok("ghp_", 36, 9)
	os.WriteFile(filepath.Join(outside, "victim.py"), []byte("GH = \""+secret+"\"\n"), 0o644)
	tr := setup(t, map[string]string{"app.py": "x = 1\n"})
	os.Symlink(filepath.Join(outside, "victim.py"), filepath.Join(tr.Root, "link.py"))
	for name, file := range map[string]string{
		"absolute path outside root": filepath.Join(outside, "victim.py"),
		"dot-dot traversal":          "../" + filepath.Base(outside) + "/victim.py",
		"symlink escaping root":      "link.py",
	} {
		f := tr.Evaluate(Input{Tool: "gitleaks", RuleID: "github-pat", File: file, StartLine: 1, Secret: secret})
		if f.Triage != Uncorroborated || !strings.Contains(strings.Join(f.Evidence, " "), "outside --root") {
			t.Errorf("%s: must not be read: %s %v", name, f.Triage, f.Evidence)
		}
	}
}

func TestHistoryIsNeverSubstituted(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	secret := tok("ghp_", 36, 10)
	tr := setup(t, map[string]string{"app.py": "GH = \"" + secret + "\"\n"})
	exec.Command("git", "-C", tr.Root, "init", "-q").Run()
	// A commit that does not exist must not fall back to the working tree.
	f := tr.Evaluate(Input{Tool: "gitleaks", RuleID: "github-pat", File: "app.py", StartLine: 1, Secret: secret,
		Commit: "0123456789abcdef0123456789abcdef01234567"})
	if f.Triage != Uncorroborated || !strings.Contains(strings.Join(f.Evidence, " "), "no working-tree substitution") {
		t.Errorf("missing commit: %s %v", f.Triage, f.Evidence)
	}
	// Option-looking commit ids are rejected before reaching git.
	f = tr.Evaluate(Input{Tool: "gitleaks", RuleID: "github-pat", File: "app.py", StartLine: 1, Secret: secret, Commit: "--output=/tmp/x"})
	if f.Triage != Uncorroborated || !strings.Contains(strings.Join(f.Evidence, " "), "invalid commit") {
		t.Errorf("bad commit id: %s %v", f.Triage, f.Evidence)
	}
}

func TestStaleReportLines(t *testing.T) {
	secret := tok("ghp_", 36, 11)
	tr := setup(t, map[string]string{"app.py": "import os\n\n\n\nGH = \"" + secret + "\"\n"})
	f := tr.Evaluate(Input{Tool: "gitleaks", RuleID: "github-pat", File: "app.py", StartLine: 1, Secret: secret})
	if f.Triage != Uncorroborated || !strings.Contains(strings.Join(f.Evidence, " "), "source changed") {
		t.Errorf("stale line: %s %v", f.Triage, f.Evidence)
	}
	if f := tr.Evaluate(Input{Tool: "gitleaks", RuleID: "github-pat", File: "app.py", StartLine: 5, Secret: secret}); f.Triage != Confirmed {
		t.Errorf("current line should confirm: %s %v", f.Triage, f.Evidence)
	}
}

func TestPartiallyRedactedReports(t *testing.T) {
	secret := tok("ghp_", 36, 12)
	tr := setup(t, map[string]string{
		"app.py":      "GH = \"" + secret + "\"\n",
		"Jenkinsfile": "    [envVar: 'TF_VAR_APPROLESECRETID', vaultKey: 'inf-vsqt-01-secret-id']]]]) {\n",
	})
	// gitleaks --redact=50 style ("prefix...") and secretscan style ("prefixREDACTED").
	in := finish(Input{Tool: "gitleaks", RuleID: "github-pat", File: "app.py", StartLine: 1, Secret: secret[:20] + "..."})
	if f := tr.Evaluate(in); f.Triage != Confirmed {
		t.Errorf("prefix-redacted provider token should confirm: %s %v", f.Triage, f.Evidence)
	}
	in = finish(Input{Tool: "gitleaks", RuleID: "generic-api-key", File: "Jenkinsfile", StartLine: 1, Secret: "inf-vsqt-0REDACTED"})
	if f := tr.Evaluate(in); !strings.HasPrefix(f.Triage, Filtered) {
		t.Errorf("prefix-redacted noise should be filtered: %s %v", f.Triage, f.Evidence)
	}
	// Fully redacted: can only confirm, never filter.
	in = finish(Input{Tool: "gitleaks", RuleID: "generic-api-key", File: "Jenkinsfile", StartLine: 1, Secret: "REDACTED"})
	if f := tr.Evaluate(in); f.Triage != Uncorroborated {
		t.Errorf("fully redacted noise must stay for review: %s", f.Triage)
	}
	// Too-short prefixes are treated as fully redacted.
	if in := finish(Input{Secret: "gh..."}); in.Prefix != "" || !in.Redacted {
		t.Errorf("short prefix: %+v", in)
	}
}
