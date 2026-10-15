// SPDX-License-Identifier: Apache-2.0

package triage

import (
	"encoding/json"
	"math/rand"
	"os"
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
