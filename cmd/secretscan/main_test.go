// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"math/rand"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

var bin string

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "secretscan-bin")
	if err != nil {
		panic(err)
	}
	bin = filepath.Join(dir, "secretscan")
	if out, err := exec.Command("go", "build", "-o", bin, ".").CombinedOutput(); err != nil {
		panic(string(out))
	}
	code := m.Run()
	os.RemoveAll(dir)
	os.Exit(code)
}

func pat() string {
	r := rand.New(rand.NewSource(99))
	const cs = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, 36)
	for i := range b {
		b[i] = cs[r.Intn(len(cs))]
	}
	return "ghp_" + string(b)
}

type result struct {
	code           int
	stdout, stderr string
}

func run(t *testing.T, dir, stdin string, args ...string) result {
	t.Helper()
	cmd := exec.Command(bin, args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "NO_COLOR=1")
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}
	var so, se strings.Builder
	cmd.Stdout, cmd.Stderr = &so, &se
	err := cmd.Run()
	code := 0
	if ee, ok := err.(*exec.ExitError); ok {
		code = ee.ExitCode()
	} else if err != nil {
		t.Fatal(err)
	}
	return result{code, so.String(), se.String()}
}

func writeFile(t *testing.T, path, body string) {
	t.Helper()
	os.MkdirAll(filepath.Dir(path), 0o755)
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestDirScanReportsAndRedacts(t *testing.T) {
	dir := t.TempDir()
	p := pat()
	writeFile(t, filepath.Join(dir, "app/settings.py"), "DEBUG = True\nGITHUB = '"+p+"'\n")
	r := run(t, dir, "", "dir", ".", "-f", "json")
	if r.code != 1 {
		t.Fatalf("exit %d, stderr=%s", r.code, r.stderr)
	}
	var fs []map[string]any
	if err := json.Unmarshal([]byte(r.stdout), &fs); err != nil {
		t.Fatal(err, r.stdout)
	}
	if len(fs) != 1 || fs[0]["RuleID"] != "github-pat" || fs[0]["StartLine"] != 2.0 {
		t.Fatalf("findings = %v", fs)
	}
	if strings.Contains(r.stdout, p) || !strings.Contains(fs[0]["Secret"].(string), "REDACTED") {
		t.Error("secret must be redacted by default")
	}
	if r := run(t, dir, "", "dir", ".", "-f", "json", "--redact=0"); !strings.Contains(r.stdout, p) {
		t.Error("--redact=0 should reveal")
	}
	if r := run(t, dir, "", "dir", ".", "--exit-code", "0", "-q"); r.code != 0 || r.stdout != "" {
		t.Errorf("--exit-code 0 -q: %+v", r)
	}
	if r := run(t, dir, "", "dir", ".", "--min-severity", "critical"); r.code != 1 {
		t.Error("github-pat is critical; should still fail")
	}
	if r := run(t, dir, "", "dir", ".", "--disable-rule", "github-pat"); r.code != 0 {
		t.Errorf("disabled rule still fired: %s", r.stdout)
	}
}

func TestCustomPatternsAndConfig(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "x.txt"), "corp token: CORP-"+"ABCD1234EFGH5678\nbadge=itk_9f8e7d6c5b4a39281706f5e4d3c2b1a0\n")
	r := run(t, dir, "", "dir", ".", "--no-default-rules", "--pattern", `corp=CORP-[A-Z0-9]{16} ;; severity=high`, "-f", "json")
	if r.code != 1 || !strings.Contains(r.stdout, `"RuleID": "corp"`) {
		t.Fatalf("pattern flag: %+v", r)
	}
	writeFile(t, filepath.Join(dir, ".secretscan.toml"), `
[[rules]]
id = "internal-badge"
description = "Internal badge token"
regex = '''\b(itk_[0-9a-f]{32})\b'''
severity = "critical"
examples = ["x = itk_00112233445566778899aabbccddeeff"]
negatives = ["itk_short"]
`)
	r = run(t, dir, "", "dir", ".", "-f", "json")
	if r.code != 1 || !strings.Contains(r.stdout, "internal-badge") {
		t.Fatalf("auto-discovered config: %+v", r)
	}
	if v := run(t, dir, "", "validate"); v.code != 0 || !strings.Contains(v.stdout, "2 self-tests, 0 failures") {
		t.Errorf("validate: %+v", v)
	}
	writeFile(t, filepath.Join(dir, ".secretscan.toml"), "[[rules]]\nid='broken'\nregex='itk_'\nexamples=['nothing here']\n")
	if v := run(t, dir, "", "validate"); v.code != 1 {
		t.Errorf("validate should fail on bad example: %+v", v)
	}
	writeFile(t, filepath.Join(dir, ".secretscan.toml"), "[[rules]]\nid='broken'\nregex='('\n")
	if v := run(t, dir, "", "dir", "."); v.code != 2 || !strings.Contains(v.stderr, "bad regex") {
		t.Errorf("bad regex should exit 2: %+v", v)
	}
}

func TestIgnoreFileAndBaseline(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "a.env"), "T="+pat()+"\n")
	r := run(t, dir, "", "dir", ".", "-r", "baseline.json")
	if r.code != 1 {
		t.Fatal("expected finding")
	}
	if r := run(t, dir, "", "dir", ".", "-b", "baseline.json", "--exclude-path", `baseline\.json$`); r.code != 0 {
		t.Errorf("baseline should suppress: %s %s", r.stdout, r.stderr)
	}
	writeFile(t, filepath.Join(dir, ".secretscanignore"), "# accepted\na.env:github-pat:1\nbaseline.json\n")
	if r := run(t, dir, "", "dir", ".", "--exclude-path", `baseline\.json$`); r.code != 0 {
		t.Errorf("ignore file should suppress: %s", r.stdout)
	}
}

func TestStdinDiffAndSARIF(t *testing.T) {
	diff := "diff --git a/x b/x\n+++ b/x\n@@ -1 +1,2 @@\n-old\n+ok\n+tok=" + pat() + "\n"
	r := run(t, t.TempDir(), diff, "stdin", "--diff", "-f", "sarif")
	if r.code != 1 {
		t.Fatalf("exit %d %s", r.code, r.stderr)
	}
	var log struct {
		Version string `json:"version"`
		Runs    []struct {
			Results []struct {
				RuleID    string `json:"ruleId"`
				Locations []struct {
					PhysicalLocation struct {
						Region struct {
							StartLine int `json:"startLine"`
						} `json:"region"`
					} `json:"physicalLocation"`
				} `json:"locations"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal([]byte(r.stdout), &log); err != nil {
		t.Fatal(err)
	}
	res := log.Runs[0].Results
	if log.Version != "2.1.0" || len(res) != 1 || res[0].Locations[0].PhysicalLocation.Region.StartLine != 2 {
		t.Errorf("sarif = %s", r.stdout)
	}
}

func gitCmd(t *testing.T, dir string, args ...string) (string, error) {
	cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
	cmd.Env = append(os.Environ(), "GIT_AUTHOR_NAME=Dev", "GIT_AUTHOR_EMAIL=d@x", "GIT_COMMITTER_NAME=Dev",
		"GIT_COMMITTER_EMAIL=d@x", "GIT_CONFIG_GLOBAL=/dev/null", "NO_COLOR=1")
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func TestHooksBlockCommitAndPush(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	root := t.TempDir()
	remote := filepath.Join(root, "remote.git")
	repo := filepath.Join(root, "repo")
	must := func(out string, err error) string {
		t.Helper()
		if err != nil {
			t.Fatalf("%v: %s", err, out)
		}
		return out
	}
	must(gitCmd(t, root, "init", "-q", "--bare", remote))
	must(gitCmd(t, root, "init", "-q", "-b", "main", repo))
	must(gitCmd(t, repo, "remote", "add", "origin", remote))

	// A pre-existing hook must be preserved and chained.
	writeFile(t, filepath.Join(repo, ".git/hooks/pre-commit"), "#!/bin/sh\necho legacy-hook-ran\n")
	os.Chmod(filepath.Join(repo, ".git/hooks/pre-commit"), 0o755)
	if r := run(t, repo, "", "install-hook", "--type", "both"); r.code != 0 || !strings.Contains(r.stdout, "kept as pre-commit.local") {
		t.Fatalf("install-hook: %+v", r)
	}

	writeFile(t, filepath.Join(repo, "ok.txt"), "fine\n")
	must(gitCmd(t, repo, "add", "."))
	out := must(gitCmd(t, repo, "commit", "-qm", "clean"))
	if !strings.Contains(out, "legacy-hook-ran") {
		t.Errorf("chained hook did not run: %s", out)
	}

	p := pat()
	writeFile(t, filepath.Join(repo, "leak.py"), "TOKEN = '"+p+"'\n")
	must(gitCmd(t, repo, "add", "leak.py"))
	out, err := gitCmd(t, repo, "commit", "-qm", "leak")
	if err == nil || !strings.Contains(out, "github-pat") || !strings.Contains(out, "Blocked") {
		t.Fatalf("pre-commit should block: %v %s", err, out)
	}

	// Inline allow passes the pre-commit hook.
	writeFile(t, filepath.Join(repo, "leak.py"), "TOKEN = '"+p+"'  # secretscan:allow\n")
	must(gitCmd(t, repo, "add", "leak.py"))
	must(gitCmd(t, repo, "commit", "-qm", "allowed inline"))

	// Sneak a secret past pre-commit with --no-verify; pre-push must catch it.
	writeFile(t, filepath.Join(repo, "sneaky.env"), "GH="+p+"\n")
	must(gitCmd(t, repo, "add", "sneaky.env"))
	must(gitCmd(t, repo, "commit", "-qm", "sneaky", "--no-verify"))
	out, err = gitCmd(t, repo, "push", "-q", "origin", "main")
	if err == nil || !strings.Contains(out, "sneaky.env") {
		t.Fatalf("pre-push should block: %v %s", err, out)
	}
	if strings.Contains(out, "leak.py") {
		t.Errorf("inline-allowed line should not be reported on push: %s", out)
	}

	// Fail closed when the binary is gone, unless explicitly optional.
	hook := filepath.Join(repo, ".git/hooks/pre-commit")
	body, _ := os.ReadFile(hook)
	os.WriteFile(hook, []byte(strings.Replace(string(body), bin, "/nonexistent/secretscan", 1)), 0o755)
	cmd := exec.Command("sh", hook)
	cmd.Dir = repo
	cmd.Env = []string{"PATH=/usr/bin:/bin"}
	if out, err := cmd.CombinedOutput(); err == nil || !strings.Contains(string(out), "binary not found") {
		t.Errorf("hook should fail closed: %v %s", err, out)
	}
	cmd = exec.Command("sh", hook)
	cmd.Dir = repo
	cmd.Env = []string{"PATH=/usr/bin:/bin", "SECRETSCAN_OPTIONAL=1"}
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Errorf("optional mode should pass: %v %s", err, out)
	}
}

func TestRemediationOutputs(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "app.py"), "import logging\nTOKEN = \""+pat()+"\"\n")
	r := run(t, dir, "", "dir", ".", "-f", "json")
	var fs []struct {
		Remediation struct{ Urgency, Family, EnvVar, Replace, Language string }
	}
	if err := json.Unmarshal([]byte(r.stdout), &fs); err != nil || len(fs) != 1 {
		t.Fatalf("json: %v %s", err, r.stdout)
	}
	if g := fs[0].Remediation; g.Family != "GitHub" || g.EnvVar != "GITHUB_TOKEN" || g.Replace != `os.environ["GITHUB_TOKEN"]` || g.Urgency != "rotate" {
		t.Errorf("remediation = %+v", g)
	}
	r = run(t, dir, "", "dir", ".")
	if !strings.Contains(r.stdout, "code:    os.environ[\"GITHUB_TOKEN\"]") || !strings.Contains(r.stdout, "secretscan explain github-pat --lang python") {
		t.Errorf("text remediation missing:\n%s", r.stdout)
	}
	r = run(t, dir, "", "dir", ".", "--remediation", "full", "--secret-store", "azure")
	if !strings.Contains(r.stdout, "DefaultAzureCredential") || !strings.Contains(r.stdout, "1. Rotate:") {
		t.Errorf("full remediation missing:\n%s", r.stdout)
	}
	r = run(t, dir, "", "dir", ".", "-f", "sarif")
	if !strings.Contains(r.stdout, `"help"`) || !strings.Contains(r.stdout, `"remediation"`) {
		t.Errorf("sarif help/remediation missing")
	}
	// Org defaults from config.
	writeFile(t, filepath.Join(dir, ".secretscan.toml"), "[remediation]\nstore = \"vault\"\nrunbook = \"https://wiki.example.com/secrets\"\n")
	r = run(t, dir, "", "dir", ".", "--remediation", "full")
	if !strings.Contains(r.stdout, "hvac") || !strings.Contains(r.stdout, "wiki.example.com/secrets") {
		t.Errorf("config store/runbook not applied:\n%s", r.stdout)
	}
}

func TestExplain(t *testing.T) {
	r := run(t, t.TempDir(), "", "explain", "azure-devops-pat", "--lang", "csharp", "--store", "azure")
	if r.code != 0 || !strings.Contains(r.stdout, "workload identity federation") || !strings.Contains(r.stdout, "AddAzureKeyVault") {
		t.Errorf("explain: %+v", r)
	}
	if r := run(t, t.TempDir(), "", "explain", "no-such-rule"); r.code != 2 {
		t.Errorf("unknown rule should exit 2: %+v", r)
	}
	if r := run(t, t.TempDir(), "", "explain", "github-pat", "--lang", "all", "--store", "all"); r.code != 0 || strings.Count(r.stdout, "--- ") < 40 {
		t.Errorf("explain all: code %d, %d sections", r.code, strings.Count(r.stdout, "--- "))
	}
}

func TestFixStagedAndPatchWarning(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	repo := t.TempDir()
	if out, err := gitCmd(t, repo, "init", "-q", "-b", "main"); err != nil {
		t.Fatal(out)
	}
	writeFile(t, filepath.Join(repo, "svc/main.go"), "package main\n\nimport \"fmt\"\n\nfunc main() {\n\tkey := \""+pat()+"\"\n\tfmt.Println(len(key))\n}\n")
	if out, err := gitCmd(t, repo, "add", "."); err != nil {
		t.Fatal(out)
	}
	r := run(t, repo, "", "git", "--staged", "--fix-patch", "fix.diff")
	if !strings.Contains(r.stderr, "contains the old secrets") {
		t.Errorf("expected in-tree patch warning: %s", r.stderr)
	}
	if fi, err := os.Stat(filepath.Join(repo, "fix.diff")); err != nil || fi.Mode().Perm() != 0o600 {
		t.Errorf("patch file should be 0600: %v", err)
	}
	os.Remove(filepath.Join(repo, "fix.diff"))
	// Non-interactive --fix without --yes refuses to touch files.
	r = run(t, repo, "", "git", "--staged", "--fix")
	if r.code != 2 || !strings.Contains(r.stderr, "refusing to rewrite") {
		t.Fatalf("--fix without review should refuse: %+v", r)
	}
	r = run(t, repo, "", "git", "--staged", "--fix", "--yes")
	if !strings.Contains(r.stderr, "fixed 1 literal(s)") || !strings.Contains(r.stderr, `os.Getenv returns ""`) {
		t.Fatalf("fix: %s", r.stderr)
	}
	b, _ := os.ReadFile(filepath.Join(repo, "svc/main.go"))
	if !strings.Contains(string(b), `os.Getenv("GITHUB_TOKEN")`) || !strings.Contains(string(b), `"os"`) {
		t.Errorf("fixed file:\n%s", b)
	}
	writeFile(t, filepath.Join(repo, "svc/go.mod"), "module demo\n\ngo 1.24\n")
	cmd := exec.Command("go", "vet", ".")
	cmd.Dir = filepath.Join(repo, "svc")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Errorf("fixed Go code does not build: %s\n%s", out, b)
	}
	if r := run(t, repo, "", "dir", "."); r.code != 0 {
		t.Errorf("rescan after fix should be clean: %s", r.stdout)
	}
	if r := run(t, repo, "", "git", "--fix"); r.code != 2 {
		t.Errorf("--fix on history should be refused")
	}
}

func TestPoliciesAndLedger(t *testing.T) {
	dir := t.TempDir()
	// Only an ambiguous finding: a short generic value in a test file.
	writeFile(t, filepath.Join(dir, "tests/test_cfg.py"), "client_secret = \"Zq7wPv2kLm9xR4\"\nauth_provider = \"isOnDemandRevalidate\"\n")
	if r := run(t, dir, "", "dir", "."); r.code != 1 {
		t.Errorf("strict should block the ambiguous finding: %+v", r)
	}
	r := run(t, dir, "", "dir", ".", "--policy", "balanced")
	if r.code != 0 || !strings.Contains(r.stdout, "Needs review") || !strings.Contains(r.stderr, "0 blocking, 1 to review") {
		t.Errorf("balanced should report but not block:\n%s\n%s", r.stdout, r.stderr)
	}
	if !strings.Contains(r.stderr, "1 candidates filtered as noise (1 word-like") {
		t.Errorf("suppression counts missing: %s", r.stderr)
	}
	r = run(t, dir, "", "dir", ".", "--show-suppressed", "-q")
	if !strings.Contains(r.stderr, "tests/test_cfg.py:2") || !strings.Contains(r.stderr, "word-like") {
		t.Errorf("ledger not listed: %s", r.stderr)
	}
	r = run(t, dir, "", "dir", ".", "--min-confidence", "high")
	if r.code != 0 || !strings.Contains(r.stderr, "1 below --min-confidence hidden") {
		t.Errorf("min-confidence should hide and count: %+v", r)
	}
	// A provider token blocks under balanced too, even in a test file.
	writeFile(t, filepath.Join(dir, "tests/test_gh.py"), "GH = \""+pat()+"\"\n")
	if r := run(t, dir, "", "dir", ".", "--policy", "balanced"); r.code != 1 {
		t.Errorf("high-confidence finding must block under balanced: %+v", r)
	}
	// Policy from config.
	writeFile(t, filepath.Join(dir, ".secretscan.toml"), "policy = \"balanced\"\n")
	os.Remove(filepath.Join(dir, "tests/test_gh.py"))
	if r := run(t, dir, "", "dir", "."); r.code != 0 {
		t.Errorf("config policy not applied: %+v", r)
	}
	if r := run(t, dir, "", "dir", ".", "--policy", "lenient"); r.code != 2 {
		t.Errorf("unknown policy should exit 2")
	}
}

func TestBalancedHook(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	repo := t.TempDir()
	if out, err := gitCmd(t, repo, "init", "-q", "-b", "main"); err != nil {
		t.Fatal(out)
	}
	// Hooks default to balanced (no --policy needed) and say so.
	if r := run(t, repo, "", "install-hook"); r.code != 0 || !strings.Contains(r.stdout, "policy: balanced") || !strings.Contains(r.stdout, "do NOT") {
		t.Fatalf("install: %+v", r)
	}
	writeFile(t, filepath.Join(repo, "tests/test_cfg.py"), "client_secret = \"Zq7wPv2kLm9xR4\"\n")
	gitCmd(t, repo, "add", ".")
	out, err := gitCmd(t, repo, "commit", "-qm", "ambiguous")
	if err != nil || !strings.Contains(out, "Needs review") {
		t.Fatalf("balanced hook should let the commit through with a review note: %v\n%s", err, out)
	}
	writeFile(t, filepath.Join(repo, "app.py"), "GH = \""+pat()+"\"\n")
	gitCmd(t, repo, "add", ".")
	out, err = gitCmd(t, repo, "commit", "-qm", "token")
	if err == nil {
		t.Fatalf("balanced hook must block a provider token:\n%s", out)
	}
	if !strings.Contains(out, "why:") || !strings.Contains(out, "provider-specific format") {
		t.Errorf("hook must explain every blocked finding:\n%s", out)
	}
	// A repo config policy overrides the hook default.
	writeFile(t, filepath.Join(repo, ".secretscan.toml"), "policy = \"strict\"\n")
	os.Remove(filepath.Join(repo, "app.py"))
	gitCmd(t, repo, "add", "-A")
	writeFile(t, filepath.Join(repo, "tests/test_more.py"), "client_secret = \"Kq8wPv2kLm9xR5\"\n")
	gitCmd(t, repo, "add", ".")
	if out, err := gitCmd(t, repo, "commit", "-qm", "strict via config"); err == nil {
		t.Errorf("config strict should override hook default:\n%s", out)
	}
	if r := run(t, repo, "", "install-hook", "--policy", "yolo"); r.code != 2 {
		t.Errorf("bad hook policy should exit 2")
	}
}

func TestTriageCLI(t *testing.T) {
	dir := t.TempDir()
	p := pat()
	writeFile(t, filepath.Join(dir, "app.py"), "GH = \""+p+"\"\n")
	writeFile(t, filepath.Join(dir, "Jenkinsfile"), "    [envVar: 'TF_VAR_APPROLESECRETID', vaultKey: 'inf-vsqt-01-secret-id']]]]) {\n")
	rep, _ := json.Marshal([]map[string]any{
		{"RuleID": "github-pat", "File": "app.py", "StartLine": 1, "Secret": p},
		{"RuleID": "generic-api-key", "File": "Jenkinsfile", "StartLine": 1, "Secret": "inf-vsqt-01-secret-id"},
	})
	writeFile(t, filepath.Join(dir, "gl.json"), string(rep))
	r := run(t, dir, "", "triage", "gl.json")
	if r.code != 1 || !strings.Contains(r.stderr, "1 confirmed") || !strings.Contains(r.stderr, "1 filtered as noise") ||
		!strings.Contains(r.stdout, "Filtered as noise (1") {
		t.Errorf("triage: %+v", r)
	}
	r = run(t, dir, "", "triage", "gl.json", "-f", "json")
	var fs []map[string]any
	if err := json.Unmarshal([]byte(r.stdout), &fs); err != nil || len(fs) != 2 {
		t.Fatalf("triage json must include filtered findings too: %v %s", err, r.stdout)
	}
	rep, _ = json.Marshal([]map[string]any{{"RuleID": "generic-api-key", "File": "Jenkinsfile", "StartLine": 1, "Secret": "inf-vsqt-01-secret-id"}})
	writeFile(t, filepath.Join(dir, "gl2.json"), string(rep))
	if r := run(t, dir, "", "triage", "gl2.json"); r.code != 0 {
		t.Errorf("only noise should not block: %+v", r)
	}
}

func TestTriageReportHandling(t *testing.T) {
	dir := t.TempDir()
	p := pat()
	writeFile(t, filepath.Join(dir, "app.py"), "GH = \""+p+"\"\n")
	rep, _ := json.Marshal([]map[string]any{{"RuleID": "github-pat", "File": "app.py", "StartLine": 1, "Secret": p}})
	writeFile(t, filepath.Join(dir, "gl.json"), string(rep))
	os.Chmod(filepath.Join(dir, "gl.json"), 0o644)
	r := run(t, dir, "", "triage", "gl.json")
	if !strings.Contains(r.stderr, "contains 1 unredacted secret") || !strings.Contains(r.stderr, "readable by other users") {
		t.Errorf("expected unredacted/permission warnings: %s", r.stderr)
	}
	r = run(t, dir, "", "triage", "gl.json", "--delete-input")
	if _, err := os.Stat(filepath.Join(dir, "gl.json")); !os.IsNotExist(err) || r.code != 1 {
		t.Errorf("--delete-input should remove the report and still triage: %+v", r)
	}
	// Streaming from stdin keeps nothing on disk.
	r = run(t, dir, string(rep), "triage", "-")
	if r.code != 1 || !strings.Contains(r.stderr, "1 confirmed") || strings.Contains(r.stderr, "unredacted") {
		t.Errorf("stdin triage: %+v", r)
	}
	// Partially redacted report (gitleaks --redact=50 format).
	red, _ := json.Marshal([]map[string]any{{"RuleID": "github-pat", "File": "app.py", "StartLine": 1, "Secret": p[:20] + "..."}})
	if r := run(t, dir, string(red), "triage", "-"); !strings.Contains(r.stderr, "1 confirmed") {
		t.Errorf("partially redacted: %s", r.stderr)
	}
}

// The stats format is for sharing results publicly: counts only.
func TestStatsReportIsAnonymous(t *testing.T) {
	dir := t.TempDir()
	tok := pat()
	writeFile(t, filepath.Join(dir, "secret-dir/app.py"), "GH = \""+tok+"\"\n")
	r := run(t, dir, "", "dir", ".", "-f", "stats", "--policy", "balanced", "--no-color")
	if r.code != 1 {
		t.Fatalf("exit code %d: %+v", r.code, r)
	}
	var s struct {
		Findings, Blocking int
		Policy             string
		ByRule             map[string]int
		ByFileType         map[string]int
	}
	if err := json.Unmarshal([]byte(r.stdout), &s); err != nil {
		t.Fatalf("%v\n%s", err, r.stdout)
	}
	if s.Findings != 1 || s.Blocking != 1 || s.Policy != "balanced" || s.ByFileType[".py"] != 1 || len(s.ByRule) != 1 {
		t.Errorf("stats = %+v", s)
	}
	for _, leak := range []string{tok[:12], "secret-dir", "app.py", "Fingerprint"} {
		if strings.Contains(r.stdout, leak) {
			t.Errorf("stats output leaks %q:\n%s", leak, r.stdout)
		}
	}
}

// Writing a report over an existing, world-readable file must not keep the
// old permissions: the report contains secrets (with --redact=0).
func TestReportPermissionsAreTightened(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permissions")
	}
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "app.py"), "GH = \""+pat()+"\"\n")
	rp := filepath.Join(t.TempDir(), "report.json")
	os.WriteFile(rp, []byte("old"), 0o644)
	run(t, dir, "", "dir", ".", "-r", rp, "--redact=0", "-q")
	fi, err := os.Stat(rp)
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("report mode = %v (%v), want 0600", fi.Mode().Perm(), err)
	}
	if b, _ := os.ReadFile(rp); !strings.HasPrefix(strings.TrimSpace(string(b)), "[") {
		t.Errorf("report not rewritten: %q", b)
	}
}
