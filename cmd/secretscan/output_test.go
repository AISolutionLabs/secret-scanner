// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// victim is a file that must survive untouched: same content, same mode.
type victim struct {
	path string
	body string
}

func newVictim(t *testing.T, dir, name string) victim {
	t.Helper()
	v := victim{filepath.Join(dir, name), "important data, do not truncate\n"}
	writeFile(t, v.path, v.body)
	if err := os.Chmod(v.path, 0o644); err != nil {
		t.Fatal(err)
	}
	return v
}

func (v victim) check(t *testing.T, how string) {
	t.Helper()
	b, err := os.ReadFile(v.path)
	if err != nil || string(b) != v.body {
		t.Errorf("%s: %s was modified: %q (%v)", how, v.path, b, err)
	}
	if fi, err := os.Stat(v.path); err == nil && runtime.GOOS != "windows" && fi.Mode().Perm() != 0o644 {
		t.Errorf("%s: %s mode changed to %v", how, v.path, fi.Mode().Perm())
	}
}

func symlinkOrSkip(t *testing.T, target, link string) {
	t.Helper()
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
}

// A symlink planted at a report or patch path (for example in a branch CI
// checks out) must not let secretscan truncate, rewrite or chmod its target,
// whether the target is inside the repository or outside it.
func TestOutputPathsDoNotFollowSymlinks(t *testing.T) {
	repo := t.TempDir()
	outside := t.TempDir()
	tok := pat()
	writeFile(t, filepath.Join(repo, "app.py"), "GH = \""+tok+"\"\n")
	rep, _ := json.Marshal([]map[string]any{{"RuleID": "github-pat", "File": "app.py", "StartLine": 1, "Secret": tok}})
	writeFile(t, filepath.Join(repo, "gl.json"), string(rep))

	targets := map[string]victim{
		"inside":          newVictim(t, repo, "README.md"),
		"outside":         newVictim(t, outside, "notes.txt"),
		"existing-report": newVictim(t, repo, "old-report.json"),
	}
	commands := map[string]func(link string) []string{
		"dir --report":    func(l string) []string { return []string{"dir", ".", "-r", l, "-q"} },
		"triage --report": func(l string) []string { return []string{"triage", "gl.json", "-r", l} },
		"--fix-patch":     func(l string) []string { return []string{"dir", ".", "--fix-patch", l, "-q"} },
	}
	for tname, v := range targets {
		for cname, args := range commands {
			link := filepath.Join(repo, "out-"+strings.ReplaceAll(tname+cname, " ", "_"))
			symlinkOrSkip(t, v.path, link)
			r := run(t, repo, "", args(link)...)
			how := cname + " -> " + tname
			if !strings.Contains(r.stderr, "symbolic link") {
				t.Errorf("%s: expected a refusal, got code %d: %s", how, r.code, r.stderr)
			}
			if r.code == 0 {
				t.Errorf("%s: refused output must not exit 0", how)
			}
			v.check(t, how)
			if fi, err := os.Lstat(link); err != nil || fi.Mode()&os.ModeSymlink == 0 {
				t.Errorf("%s: the link itself should be left in place", how)
			}
		}
	}
}

// A hard link at the report path is replaced, not written through.
func TestReportReplacesHardLink(t *testing.T) {
	repo := t.TempDir()
	writeFile(t, filepath.Join(repo, "app.py"), "GH = \""+pat()+"\"\n")
	v := newVictim(t, t.TempDir(), "victim.txt")
	rp := filepath.Join(repo, "report.json")
	if err := os.Link(v.path, rp); err != nil {
		t.Skipf("hard links unavailable: %v", err)
	}
	if r := run(t, repo, "", "dir", ".", "-r", rp, "-q"); r.code != 1 {
		t.Fatalf("scan: %+v", r)
	}
	v.check(t, "hard link")
	if b, _ := os.ReadFile(rp); !strings.HasPrefix(strings.TrimSpace(string(b)), "[") {
		t.Errorf("report not written: %q", b)
	}
	if runtime.GOOS != "windows" {
		if fi, _ := os.Stat(rp); fi.Mode().Perm() != 0o600 {
			t.Errorf("report mode %v, want 0600", fi.Mode().Perm())
		}
	}
	// No temporary files are left behind.
	if m, _ := filepath.Glob(filepath.Join(repo, ".report.json.secretscan-*")); len(m) != 0 {
		t.Errorf("temporary files left: %v", m)
	}
}

// /dev/stdout is a symlink to a pipe or terminal on Linux; writing a report
// there must keep working.
func TestReportToDevStdout(t *testing.T) {
	if _, err := os.Stat("/dev/stdout"); err != nil {
		t.Skip("no /dev/stdout")
	}
	repo := t.TempDir()
	writeFile(t, filepath.Join(repo, "app.py"), "GH = \""+pat()+"\"\n")
	r := run(t, repo, "", "dir", ".", "-r", "/dev/stdout", "-f", "json", "-q")
	if r.code != 1 || !strings.Contains(r.stdout, "github-pat") {
		t.Errorf("report to /dev/stdout: %+v", r)
	}
}

// --fix never rewrites a file through a symlink.
func TestFixDoesNotFollowSymlinkedSource(t *testing.T) {
	repo := t.TempDir()
	outside := t.TempDir()
	v := victim{filepath.Join(outside, "config.py"), "TOKEN = \"" + pat() + "\"\n"}
	writeFile(t, v.path, v.body)
	os.Chmod(v.path, 0o644)
	symlinkOrSkip(t, v.path, filepath.Join(repo, "config.py"))
	run(t, repo, "", "dir", ".", "--fix", "--yes", "-q")
	v.check(t, "--fix through symlink")
}

// install-hook replaces a symlinked hook with a regular file; the link's
// target is never written, even when it carries the secretscan marker.
func TestInstallHookDoesNotWriteThroughSymlink(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX hooks")
	}
	repo := t.TempDir()
	if out, err := gitCmd(t, repo, "init", "-q"); err != nil {
		t.Skip(out)
	}
	outside := t.TempDir()
	v := victim{filepath.Join(outside, "shared-hook"), "#!/bin/sh\n" + hookMarker + "\necho shared\n"}
	writeFile(t, v.path, v.body)
	os.Chmod(v.path, 0o644)
	hook := filepath.Join(repo, ".git", "hooks", "pre-commit")
	os.MkdirAll(filepath.Dir(hook), 0o755)
	symlinkOrSkip(t, v.path, hook)
	if r := run(t, repo, "", "install-hook"); r.code != 0 {
		t.Fatalf("install-hook: %+v", r)
	}
	v.check(t, "install-hook through symlink")
	fi, err := os.Lstat(hook)
	if err != nil || !fi.Mode().IsRegular() || fi.Mode().Perm()&0o100 == 0 {
		t.Errorf("hook should now be an executable regular file: %v %v", fi.Mode(), err)
	}
}

// A triage report over the size limit is an error, never a clean result.
func TestTriageRejectsOversizedReport(t *testing.T) {
	dir := t.TempDir()
	big := "[" + strings.Repeat(`{"RuleID":"x","File":"a","StartLine":1,"Secret":"y"},`, 40000) + `{"RuleID":"x"}]`
	writeFile(t, filepath.Join(dir, "big.json"), big)
	for _, stdin := range []bool{false, true} {
		args := []string{"triage", "big.json", "--max-report-megabytes", "1"}
		in := ""
		if stdin {
			args[1], in = "-", big
		}
		r := run(t, dir, in, args...)
		if r.code != 2 || !strings.Contains(r.stderr, "larger than 1 MiB") {
			t.Errorf("stdin=%v: oversized report should fail with exit 2: %+v", stdin, r.code)
			t.Log(r.stderr)
		}
	}
	// Under the limit the same report is triaged.
	if r := run(t, dir, "", "triage", "big.json", "--max-report-megabytes", "8"); r.code == 2 {
		t.Errorf("report under the limit failed: %s", r.stderr)
	}
}
