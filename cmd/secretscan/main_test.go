package main

import (
	"encoding/json"
	"math/rand"
	"os"
	"os/exec"
	"path/filepath"
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
