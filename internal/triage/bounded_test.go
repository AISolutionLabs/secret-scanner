// SPDX-License-Identifier: Apache-2.0

package triage

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// allocated returns the bytes allocated while f runs.
func allocated(f func()) uint64 {
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	f()
	runtime.ReadMemStats(&after)
	return after.TotalAlloc - before.TotalAlloc
}

func bigFile(t *testing.T, path string, size int) string {
	t.Helper()
	secret := tok("ghp_", 36, 41)
	line := "GH = \"" + secret + "\"\n"
	b := bytes.Repeat([]byte("x = 1\n"), (size-len(line))/6)
	os.MkdirAll(filepath.Dir(path), 0o755)
	if err := os.WriteFile(path, append([]byte(line), b...), 0o644); err != nil {
		t.Fatal(err)
	}
	return secret
}

// An oversized working-tree file is rejected without being read.
func TestOversizedWorkingTreeFileIsNotLoaded(t *testing.T) {
	tr := setup(t, nil)
	tr.MaxSource = 1 << 20
	secret := bigFile(t, filepath.Join(tr.Root, "big.py"), 64<<20)
	var f = Input{}
	n := allocated(func() {
		f = Input{Tool: "gitleaks", RuleID: "github-pat", File: "big.py", StartLine: 1, Secret: secret}
		got := tr.Evaluate(f)
		if got.Triage != Uncorroborated || !strings.Contains(strings.Join(got.Evidence, " "), "too large") {
			t.Errorf("oversized file: %s %v", got.Triage, got.Evidence)
		}
	})
	if n > 4<<20 {
		t.Errorf("allocated %d MiB for a 64 MiB file with a 1 MiB limit", n>>20)
	}
}

// An oversized blob in history is rejected without being loaded.
func TestOversizedHistoricalBlobIsNotLoaded(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	repo := t.TempDir()
	secret := bigFile(t, filepath.Join(repo, "big.py"), 32<<20)
	git(t, repo, "init", "-q")
	git(t, repo, "add", ".")
	git(t, repo, "commit", "-qm", "big")
	commit := git(t, repo, "rev-parse", "HEAD")
	os.Remove(filepath.Join(repo, "big.py"))
	tr := setup(t, nil)
	tr.Root = repo
	tr.MaxSource = 1 << 20
	n := allocated(func() {
		got := tr.Evaluate(Input{Tool: "gitleaks", RuleID: "github-pat", File: "big.py", StartLine: 1, Secret: secret, Commit: commit})
		if got.Triage != Uncorroborated || !strings.Contains(strings.Join(got.Evidence, " "), "too large") {
			t.Errorf("oversized blob: %s %v", got.Triage, got.Evidence)
		}
	})
	if n > 4<<20 {
		t.Errorf("allocated %d MiB for a 32 MiB blob with a 1 MiB limit", n>>20)
	}
	// Within the limit, the same history path still reads and confirms
	// (a fresh triager: results are cached per file).
	tr = setup(t, nil)
	tr.Root = repo
	tr.MaxSource = 64 << 20
	if got := tr.Evaluate(Input{Tool: "gitleaks", RuleID: "github-pat", File: "big.py", StartLine: 1, Secret: secret, Commit: commit}); got.Triage != Confirmed {
		t.Errorf("blob within the limit: %s %v", got.Triage, got.Evidence)
	}
}

// The capped reader itself never returns more than the limit.
func TestReadBoundedStopsAtLimit(t *testing.T) {
	p := filepath.Join(t.TempDir(), "f")
	os.WriteFile(p, bytes.Repeat([]byte("a"), 2048), 0o644)
	if _, err := readBounded(p, 1024); err != errTooLarge {
		t.Errorf("err = %v, want errTooLarge", err)
	}
	if s, err := readBounded(p, 4096); err != nil || len(s) != 2048 {
		t.Errorf("within limit: %d bytes, %v", len(s), err)
	}
	if _, err := readBounded(t.TempDir(), 4096); err == nil {
		t.Error("a directory must not be read")
	}
}
