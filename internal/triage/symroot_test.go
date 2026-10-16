// SPDX-License-Identifier: Apache-2.0

package triage

import (
	"os"
	"path/filepath"
	"testing"
)

// --root reached through a symlink (macOS: /var -> /private/var) must accept
// absolute report paths spelled through the same symlink.
func TestResolveThroughSymlinkedRoot(t *testing.T) {
	real := t.TempDir()
	os.MkdirAll(filepath.Join(real, "a"), 0o755)
	os.WriteFile(filepath.Join(real, "a", "f.py"), []byte("x"), 0o644)
	link := filepath.Join(t.TempDir(), "root")
	if err := os.Symlink(real, link); err != nil {
		t.Skip(err)
	}
	tr := &Triager{Root: link}
	for path, ok := range map[string]bool{
		filepath.Join(link, "a", "f.py"): true,
		filepath.Join(real, "a", "f.py"): true,
		"a/f.py":                         true,
		filepath.Join(link, "..", "x"):   false,
	} {
		if _, _, err := tr.resolve(path); (err == nil) != ok {
			t.Errorf("resolve(%q): err=%v, want allowed=%v", path, err, ok)
		}
	}
}
