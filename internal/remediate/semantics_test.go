// SPDX-License-Identifier: Apache-2.0

package remediate

import (
	"os/exec"
	"strings"
	"testing"
)

// A literal that is text (inside a comment, a multi-line string or a
// heredoc) or that must stay a constant is never rewritten: the result
// would still parse, but the program's data would silently change, or it
// would stop compiling. Each case used to be patched.
func TestPatchPreservesBehaviour(t *testing.T) {
	const s = "SECRET0123456789abcdef" // secretscan:allow (fixture)
	cases := []struct {
		name, file, src string
		needs           string // interpreter the case relies on ("" = none)
	}{
		{"Go raw string (embedded YAML)", "a.go", "package main\n\nimport \"fmt\"\n\nvar cfg = `\ndb:\n  token: \"" + s + "\"\n`\n\nfunc main() { fmt.Println(cfg) }\n", ""},
		{"Go comment (would add an unused import)", "b.go", "package main\n\n// client := New(\"" + s + "\")\nfunc main() {}\n", ""},
		{"Go block comment", "c.go", "package main\n\n/*\n  token := \"" + s + "\"\n*/\nfunc main() {}\n", ""},
		{"Python triple-quoted SQL", "a.py", "SQL = \"\"\"\nINSERT INTO t VALUES ('k', \"" + s + "\");\n\"\"\"\n", ""},
		{"Python comment", "b.py", "# token = \"" + s + "\"\nx = 1\n", ""},
		{"Python bytes literal (str would change the type)", "c.py", "x = rb\"" + s + "\"\n", ""},
		{"JavaScript template literal", "a.js", "const tpl = `\n  token: \"" + s + "\"\n`;\n", ""},
		{"quoted shell heredoc", "a.sh", "#!/bin/sh\ncat > x.conf <<'EOF'\ntoken=\"" + s + "\"\nEOF\n", ""},
		{"PHP property default", "a.php", "<?php\nclass C {\n    private $t = \"" + s + "\";\n}\n", ""},
		{"PHP parameter default", "b.php", "<?php\nfunction f($t = '" + s + "') { return $t; }\n", ""},
		{"C# case label mid-line", "A.cs", "class A { void M(string x) { switch (x) { case \"" + s + "\": break; } } }\n", ""},
		{"C# optional parameter", "B.cs", "class B { void M(string t = \"" + s + "\") {} }\n", ""},
		{"Java constant used in a case label", "A.java", "class A {\n  static final String T = \"" + s + "\";\n  void m(String x) { switch (x) { case T: break; } }\n}\n", ""},
		{"TypeScript string enum", "a.ts", "enum K {\n  Main = \"" + s + "\",\n}\n", ""},
		{"Ruby symbol-style hash key", "a.rb", "h = { \"" + s + "\": 1 }\n", "ruby"},
	}
	for _, c := range cases {
		if c.needs != "" {
			if _, err := exec.LookPath(c.needs); err != nil {
				continue
			}
		}
		dir := t.TempDir()
		write(t, dir, c.file, c.src)
		line := strings.Count(c.src[:strings.Index(c.src, s)], "\n") + 1
		res := BuildPatch(dir, []PatchItem{{File: c.file, Line: line, Secret: s, EnvVar: "APP_TOKEN"}})
		if len(res.Patched) != 0 || len(res.Skipped) != 1 {
			t.Errorf("%s: must be left for a manual edit, got patched=%d skipped=%v\n%s", c.name, len(res.Patched), res.Skipped, res.Diff)
		}
	}
	// Ordinary literals next to such constructs are still patched.
	for _, c := range []struct{ file, src string }{
		{"ok.go", "package main\n\n// see https://example.org/docs\nvar t = \"" + s + "\" // the \"token\"\n"},
		{"ok.py", "\"\"\"Module docstring.\"\"\"\nimport os\nT = f\"" + s + "\"  # comment\n"},
		{"ok.js", "const a = `x`; // comment\nconst t = \"" + s + "\";\n"},
		{"ok.sh", "#!/bin/sh\ncat <<EOF\nhello\nEOF\nTOKEN=\"" + s + "\"\necho \"$#\"\n"},
		{"ok.php", "<?php\nfunction f() { $t = '" + s + "'; return $t; }\n"},
	} {
		dir := t.TempDir()
		write(t, dir, c.file, c.src)
		line := strings.Count(c.src[:strings.Index(c.src, s)], "\n") + 1
		res := BuildPatch(dir, []PatchItem{{File: c.file, Line: line, Secret: s, EnvVar: "APP_TOKEN"}})
		if len(res.Patched) != 1 {
			t.Errorf("%s: plain literal not patched: %v", c.file, res.Skipped)
		}
	}
}

func TestCodeAt(t *testing.T) {
	src := "x = \"a\" // \"b\"\ny = `\n\"c\"\n`\n/* \"d\" */ z = \"e\"\n"
	for lit, want := range map[string]bool{`"a"`: true, `"b"`: false, `"c"`: false, `"d"`: false, `"e"`: true} {
		if got := codeAt("javascript", src, strings.Index(src, lit)); got != want {
			t.Errorf("codeAt(%s) = %v, want %v", lit, got, want)
		}
	}
}
