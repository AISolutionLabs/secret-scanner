// SPDX-License-Identifier: Apache-2.0

package sources

import (
	"context"
	"math/rand"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/AISolutionLabs/secret-scanner/internal/config"
	"github.com/AISolutionLabs/secret-scanner/internal/detect"
)

func fakePAT() string {
	r := rand.New(rand.NewSource(7))
	const cs = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, 36)
	for i := range b {
		b[i] = cs[r.Intn(len(cs))]
	}
	return "ghp_" + string(b)
}

func collect() (func(detect.Fragment), func() []detect.Fragment) {
	var mu sync.Mutex
	var fs []detect.Fragment
	return func(f detect.Fragment) { mu.Lock(); fs = append(fs, f); mu.Unlock() },
		func() []detect.Fragment { mu.Lock(); defer mu.Unlock(); return fs }
}

func TestParseDiffLineNumbersAndTrickyLines(t *testing.T) {
	diff := "diff --git a/app.py b/app.py\n" +
		"--- a/app.py\n" +
		"+++ b/app.py\n" +
		"@@ -10,2 +10,4 @@ def f():\n" +
		" context\n" +
		"-old = 1\n" +
		"+new = 2\n" +
		"++++ this added line starts with +++\n" +
		"+@@ looks like a hunk\n" +
		" tail\n" +
		"@@ -40 +42 @@\n" +
		"-x\n" +
		"+y\n" +
		"\\ No newline at end of file\n" +
		"diff --git a/gone.txt b/gone.txt\n" +
		"--- a/gone.txt\n" +
		"+++ /dev/null\n" +
		"@@ -1 +0,0 @@\n" +
		"-bye\n"
	emit, got := collect()
	if err := ParseDiff(strings.NewReader(diff), 0, emit); err != nil {
		t.Fatal(err)
	}
	fs := got()
	if len(fs) != 2 {
		t.Fatalf("want 2 fragments, got %d: %+v", len(fs), fs)
	}
	if fs[0].FilePath != "app.py" || fs[0].StartLine != 11 ||
		fs[0].Raw != "new = 2\n+++ this added line starts with +++\n@@ looks like a hunk\n" {
		t.Errorf("fragment 0 = %+v", fs[0])
	}
	if fs[1].StartLine != 42 || fs[1].Raw != "y\n" {
		t.Errorf("fragment 1 = %+v", fs[1])
	}
}

func TestParseDiffQuotedPaths(t *testing.T) {
	diff := "diff --git \"a/sp ace/\\303\\251.txt\" \"b/sp ace/\\303\\251.txt\"\n+++ \"b/sp ace/\\303\\251.txt\"\n@@ -0,0 +1 @@\n+hi\n"
	emit, got := collect()
	_ = ParseDiff(strings.NewReader(diff), 0, emit)
	if fs := got(); len(fs) != 1 || fs[0].FilePath != "sp ace/é.txt" {
		t.Errorf("got %+v", fs)
	}
}

func git(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
	cmd.Env = append(os.Environ(), "GIT_AUTHOR_NAME=Dev", "GIT_AUTHOR_EMAIL=dev@example.com",
		"GIT_COMMITTER_NAME=Dev", "GIT_COMMITTER_EMAIL=dev@example.com", "GIT_CONFIG_GLOBAL=/dev/null")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
	return strings.TrimSpace(string(out))
}

func detector(t *testing.T) *detect.Detector {
	cfg, _, err := config.Resolve(config.Options{})
	if err != nil {
		t.Fatal(err)
	}
	rs, err := config.Compile(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return detect.New(rs, detect.Options{MaxDecodeDepth: 1})
}

func scan(t *testing.T, o GitOptions) []detect.Finding {
	d := detector(t)
	var mu sync.Mutex
	var out []detect.Finding
	err := Git(context.Background(), o, func(f detect.Fragment) {
		fs := d.Detect(f)
		mu.Lock()
		out = append(out, fs...)
		mu.Unlock()
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestGitHistoryStagedAndPrePush(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	dir := t.TempDir()
	git(t, dir, "init", "-q", "-b", "main")
	pat := fakePAT()

	os.WriteFile(filepath.Join(dir, "README.md"), []byte("hello\n"), 0o644)
	git(t, dir, "add", ".")
	git(t, dir, "commit", "-qm", "init")
	base := git(t, dir, "rev-parse", "HEAD")

	os.WriteFile(filepath.Join(dir, "config.py"), []byte("x = 1\nGH = '"+pat+"'\n"), 0o644)
	git(t, dir, "add", ".")
	git(t, dir, "commit", "-qm", "add config")
	leak := git(t, dir, "rev-parse", "HEAD")

	os.WriteFile(filepath.Join(dir, "config.py"), []byte("x = 1\nGH = os.environ['GH']\n"), 0o644)
	git(t, dir, "commit", "-qam", "remove secret")
	head := git(t, dir, "rev-parse", "HEAD")

	// History still contains the secret even though HEAD does not.
	fs := scan(t, GitOptions{Repo: dir})
	if len(fs) != 1 || fs[0].Commit != leak || fs[0].StartLine != 2 || fs[0].File != "config.py" || fs[0].Author != "Dev" {
		t.Fatalf("history scan = %+v", fs)
	}

	// Range via log opts excludes the leaking commit.
	if fs := scan(t, GitOptions{Repo: dir, LogOpts: []string{leak + ".." + head}}); len(fs) != 0 {
		t.Errorf("ranged scan should be clean, got %d", len(fs))
	}

	// Pre-push: new branch with no remote refs => all commits; update => range.
	in := "refs/heads/main " + head + " refs/heads/main 0000000000000000000000000000000000000000\n"
	if fs := scan(t, GitOptions{Repo: dir, PrePush: true, Stdin: strings.NewReader(in)}); len(fs) != 1 {
		t.Errorf("pre-push new branch: want 1, got %d", len(fs))
	}
	in = "refs/heads/main " + head + " refs/heads/main " + base + "\n"
	if fs := scan(t, GitOptions{Repo: dir, PrePush: true, Stdin: strings.NewReader(in)}); len(fs) != 1 {
		t.Errorf("pre-push range: want 1, got %d", len(fs))
	}
	in = "(delete) 0000000000000000000000000000000000000000 refs/heads/old " + head + "\n"
	if fs := scan(t, GitOptions{Repo: dir, PrePush: true, Stdin: strings.NewReader(in)}); len(fs) != 0 {
		t.Errorf("pre-push delete should scan nothing")
	}

	// Staged: only the index, with real line numbers.
	os.WriteFile(filepath.Join(dir, "new.env"), []byte("A=1\nB=2\nTOKEN="+pat+"\n"), 0o644)
	if fs := scan(t, GitOptions{Repo: dir, Staged: true}); len(fs) != 0 {
		t.Errorf("unstaged file must not be scanned")
	}
	git(t, dir, "add", "new.env")
	fs = scan(t, GitOptions{Repo: dir, Staged: true})
	if len(fs) != 1 || fs[0].File != "new.env" || fs[0].StartLine != 3 || fs[0].Commit != "" {
		t.Errorf("staged scan = %+v", fs)
	}
}

func TestEmptyRepo(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	dir := t.TempDir()
	git(t, dir, "init", "-q")
	if fs := scan(t, GitOptions{Repo: dir, Staged: true}); len(fs) != 0 {
		t.Error("empty repo staged")
	}
}

func TestFilesSkipsBinaryAllowlistedAndLarge(t *testing.T) {
	dir := t.TempDir()
	pat := fakePAT()
	os.MkdirAll(filepath.Join(dir, "node_modules/x"), 0o755)
	os.MkdirAll(filepath.Join(dir, ".git"), 0o755)
	os.WriteFile(filepath.Join(dir, "a.txt"), []byte(pat), 0o644)
	os.WriteFile(filepath.Join(dir, "bin.dat2"), append([]byte(pat), 0, 1, 2), 0o644)
	os.WriteFile(filepath.Join(dir, "node_modules/x/b.js"), []byte(pat), 0o644)
	os.WriteFile(filepath.Join(dir, ".git/config"), []byte(pat), 0o644)
	os.WriteFile(filepath.Join(dir, "big.txt"), []byte(strings.Repeat("a", 2048)+pat), 0o644)
	d := detector(t)
	emit, got := collect()
	st, err := Files(context.Background(), []string{dir}, FileOptions{MaxBytes: 1024, Skip: d.SkipPath}, emit)
	if err != nil {
		t.Fatal(err)
	}
	fs := got()
	if len(fs) != 1 || fs[0].FilePath != "a.txt" || st.Files != 1 {
		t.Errorf("files = %+v stats=%+v", fs, st)
	}
}
