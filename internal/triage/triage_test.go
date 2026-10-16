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
		{"redacted kept for review", Input{Tool: "gitleaks", RuleID: "x", File: "vendor/x.txt", StartLine: 1, Secret: "REDACTED", Redacted: true}, Uncorroborated, detect.Low},
		{"unreadable source kept", Input{Tool: "gitleaks", RuleID: "x", File: "nope.txt", StartLine: 1, Secret: "abc"}, Uncorroborated, detect.Low},
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

func git(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-C", dir, "-c", "user.email=t@example.com", "-c", "user.name=t", "-c", "commit.gpgsign=false"}, args...)...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
	return strings.TrimSpace(string(out))
}

// With --root on a subdirectory, a history finding must be checked against
// that subdirectory's file at the commit, not a same-named file at the top
// of the repository, and never against today's working tree.
func TestHistoryReadsTheReportedFileUnderRoot(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	secret := tok("ghp_", 36, 21)
	repo := t.TempDir()
	os.MkdirAll(filepath.Join(repo, "sub"), 0o755)
	os.WriteFile(filepath.Join(repo, "config.py"), []byte("NAME = \"top-level file\"\n"), 0o644)
	os.WriteFile(filepath.Join(repo, "sub", "config.py"), []byte("GH = \""+secret+"\"\n"), 0o644)
	git(t, repo, "init", "-q")
	git(t, repo, "add", ".")
	git(t, repo, "commit", "-qm", "c1")
	c1 := git(t, repo, "rev-parse", "HEAD")
	os.WriteFile(filepath.Join(repo, "sub", "config.py"), []byte("GH = os.environ[\"GH\"]\n"), 0o644) // removed since
	git(t, repo, "commit", "-qam", "c2")

	tr := setup(t, nil)
	tr.Root = filepath.Join(repo, "sub")
	f := tr.Evaluate(Input{Tool: "gitleaks", RuleID: "github-pat", File: "config.py", StartLine: 1, Secret: secret, Commit: c1})
	if f.Triage != Confirmed {
		t.Errorf("secret in sub/config.py at %s should be confirmed from history: %s %v", c1[:7], f.Triage, f.Evidence)
	}
	// The same report without the commit is checked against today's file and
	// no longer matches.
	f = tr.Evaluate(Input{Tool: "gitleaks", RuleID: "github-pat", File: "config.py", StartLine: 1, Secret: secret})
	if f.Triage == Confirmed {
		t.Errorf("working tree no longer contains the secret: %s %v", f.Triage, f.Evidence)
	}
}

func TestResolveContainment(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	os.MkdirAll(filepath.Join(root, "a"), 0o755)
	os.WriteFile(filepath.Join(root, "a", "f.py"), []byte("x"), 0o644)
	os.Symlink(outside, filepath.Join(root, "linkdir"))
	tr := &Triager{Root: root}
	for path, ok := range map[string]bool{
		"a/f.py":                         true,
		filepath.Join(root, "a", "f.py"): true, // absolute, but inside --root
		"a/../a/f.py":                    true,
		"../x.py":                        false,
		"a/../../x.py":                   false,
		filepath.Join(outside, "x.py"):   false,
		"linkdir/x.py":                   false, // a directory symlink that leaves --root
		"/etc/passwd":                    false,
	} {
		_, _, err := tr.resolve(path)
		if (err == nil) != ok {
			t.Errorf("resolve(%q): err=%v, want allowed=%v", path, err, ok)
		}
	}
}

// Whatever path a report contains, resolve never returns one outside Root.
func FuzzResolveStaysInRoot(f *testing.F) {
	for _, s := range []string{"a.py", "../a", "/etc/passwd", "a/../../b", "./x", "..", "a/./../..", `..\..\x`, "a//b"} {
		f.Add(s)
	}
	root := f.TempDir()
	f.Fuzz(func(t *testing.T, p string) {
		tr := &Triager{Root: root}
		abs, rel, err := tr.resolve(p)
		if err != nil {
			return
		}
		r, _ := filepath.Rel(root, abs)
		if r == ".." || strings.HasPrefix(r, ".."+string(filepath.Separator)) || filepath.IsAbs(r) || strings.HasPrefix(rel, "../") {
			t.Fatalf("resolve(%q) escaped root: %s (%s)", p, abs, rel)
		}
	})
}

func uuidv(seed int64) string {
	r := rand.New(rand.NewSource(seed))
	const hx = "0123456789abcdef"
	b := make([]byte, 36)
	for i := range b {
		b[i] = hx[r.Intn(16)]
	}
	b[8], b[13], b[18], b[23] = '-', '-', '-', '-'
	return string(b)
}

func hexv(n int, seed int64) string {
	r := rand.New(rand.NewSource(seed))
	b := make([]byte, n)
	for i := range b {
		b[i] = "0123456789abcdef"[r.Intn(16)]
	}
	return string(b)
}

// One case per class of real secret that standard triage filtered on
// CredData, plus the false positives that must stay filtered. Conservative
// (the default) keeps values under credential-named keys; standard applies
// every filter.
func TestConservativeTriageMissedClasses(t *testing.T) {
	type tc struct {
		name, file, body, secret string
		keepConservative         bool
		keepStandard             bool
	}
	u, h := uuidv(31), hexv(32, 32)
	b64 := tok("", 40, 33) + "+/" + tok("", 20, 34) + "=="
	nextTok := tok("", 56, 35)
	cases := []tc{
		{"uuid under a token key", "a.json", `{"access_token": "` + u + `"}`, u, true, false},
		{"uuid under tokenValue", "a.js", `const tokenValue = "` + u + `";`, u, true, false},
		{"uuid under Go :=", "a.go", `secretVal := "` + u + `"`, u, true, false},
		{"unquoted hex value", "vectors.txt", "Key = " + h, h, true, true}, // identifier bug fixed for both modes
		{"pagination-named token", "resp.json", `"nextToken": "` + nextTok + `"`, nextTok, true, false},
		{"base64 under key = (operator heuristic)", "conf.txt", "key = " + b64, b64, true, false},
		{"literal default of getenv", "settings.py", `"cookie_secret": os.getenv("cookie_secret", "` + tok("", 32, 36) + `"),`, tok("", 32, 36), true, false},
		// Must stay filtered in both modes.
		{"value that names a secret", "Jenkinsfile", "    [envVar: 'TF_VAR_APPROLESECRETID', vaultKey: 'inf-vsqt-01-secret-id']]]]) {", "inf-vsqt-01-secret-id", false, false},
		{"snake-case identifier under a key", "ecdh.txt", "PrivateKey=ALICE_secp112r2", "ALICE_secp112r2", false, false},
		{"uuid under a non-credential key", "a.json", `{"requestId": "` + uuidv(37) + `"}`, uuidv(37), false, false},
		{"uuid request token (trufflehog#3578 class)", "a.json", `{"request_token": "` + uuidv(38) + `"}`, uuidv(38), false, false},
		{"uuid idempotency key", "a.json", `{"idempotency_key": "` + uuidv(39) + `"}`, uuidv(39), false, false},
		{"random secret reference under a key (gitleaks#1468 class)", "Jenkinsfile", "    [envVar: 'TF_VAR_JISLRBFA', vaultKey: 'oqi-lumo-08-secret-id']", "oqi-lumo-08-secret-id", false, false},
	}
	for _, c := range cases {
		for _, mode := range []string{Conservative, Standard} {
			tr := setup(t, map[string]string{c.file: c.body + "\n"})
			tr.Mode = mode
			f := tr.Evaluate(Input{Tool: "gitleaks", RuleID: "generic-api-key", File: c.file, StartLine: 1, Secret: c.secret})
			kept := !strings.HasPrefix(f.Triage, Filtered)
			want := c.keepStandard
			if mode == Conservative {
				want = c.keepConservative
			}
			if kept != want {
				t.Errorf("%s [%s]: triage=%q evidence=%v, want kept=%v", c.name, mode, f.Triage, f.Evidence, want)
			}
		}
	}
}
