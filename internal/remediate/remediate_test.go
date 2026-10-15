// SPDX-License-Identifier: Apache-2.0

package remediate

import (
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/AISolutionLabs/secret-scanner/internal/config"
)

func TestEveryDefaultRuleHasAFamily(t *testing.T) {
	for _, r := range config.DefaultRules() {
		generic := false
		for _, tag := range r.Tags {
			generic = generic || tag == "generic"
		}
		fam := FamilyFor(r.ID)
		if fam.Name == genericFamily.Name && !generic && !strings.Contains(strings.Join(r.Tags, ","), "observability") &&
			!strings.Contains(strings.Join(r.Tags, ","), "comms") {
			t.Logf("rule %s uses the generic family", r.ID) // informational: issuer-agnostic guidance
		}
		g := For(Input{RuleID: r.ID, File: "app.py", Line: `x = "s"`, Secret: "s"})
		if g.Rotate == "" || g.EnvVar == "" || len(g.Steps) < 3 {
			t.Errorf("rule %s: incomplete guidance %+v", r.ID, g)
		}
	}
}

func TestUrgencyAndSDKChain(t *testing.T) {
	g := For(Input{RuleID: "github-pat", File: "a.py", Verification: "verified"})
	if g.Urgency != "revoke-now" || !strings.HasPrefix(g.Steps[0], "LIVE") {
		t.Errorf("verified should be revoke-now: %+v", g)
	}
	if g := For(Input{RuleID: "aws-access-key-id", File: "a.py"}); !strings.Contains(g.Replace, "credential chain") {
		t.Errorf("AWS should recommend the SDK chain, got %q", g.Replace)
	}
	if g := For(Input{RuleID: "azure-ad-client-secret", File: "Program.cs"}); !strings.Contains(g.Replace, "DefaultAzureCredential") {
		t.Errorf("Entra secret should recommend DefaultAzureCredential, got %q", g.Replace)
	}
	if g := For(Input{RuleID: "github-pat", File: "a.go"}); g.Replace != `os.Getenv("GITHUB_TOKEN")` {
		t.Errorf("go replace = %q", g.Replace)
	}
}

func TestEnvName(t *testing.T) {
	cases := []struct{ rule, line, secret, want string }{
		{"github-pat", `x = "ghp_1"`, "ghp_1", "GITHUB_TOKEN"},
		{"generic-api-key", `paymentApiSecret = "abc123xyz"`, "abc123xyz", "PAYMENT_API_SECRET"},
		{"password-assignment", `spring.datasource.password=hunter22`, "hunter22", "PASSWORD"},
		{"generic-api-key", `  "client-secret": "abc123xyz",`, "abc123xyz", "CLIENT_SECRET"},
		{"generic-api-key", `abc123xyz`, "abc123xyz", "GENERIC_API_SECRET"},
	}
	for _, c := range cases {
		if got := EnvName(c.rule, c.line, c.secret, FamilyFor(c.rule)); got != c.want {
			t.Errorf("EnvName(%s, %q) = %s, want %s", c.rule, c.line, got, c.want)
		}
	}
}

func TestLanguageFor(t *testing.T) {
	for path, want := range map[string]string{
		"src/app.py": "python", "cmd/main.go": "go", "web/App.tsx": "typescript", "Dockerfile.prod": "dockerfile",
		".env.local": "dotenv", ".github/workflows/ci.yml": "github-actions", "azure-pipelines.yml": "azure-pipelines",
		"deploy/values.yaml": "kubernetes", "web.config": "dotnet-config", "main.tf": "terraform", "x.unknown": "",
	} {
		if got := LanguageFor(path); got != want {
			t.Errorf("LanguageFor(%s) = %q, want %q", path, got, want)
		}
	}
}

// Every snippet renders, and code snippets are syntactically valid.
func TestSnippetsAreValid(t *testing.T) {
	dir := t.TempDir()
	py, _ := exec.LookPath("python3")
	node, _ := exec.LookPath("node")
	for _, lang := range Languages() {
		for _, store := range Stores {
			src, ok := Snippet(lang, store, "GITHUB_TOKEN")
			if !ok || strings.Contains(src, "{{") && !strings.Contains(src, "${{") {
				t.Fatalf("%s/%s: unrendered snippet:\n%s", lang, store, src)
			}
			switch lang {
			case "python":
				if py == "" {
					continue
				}
				f := filepath.Join(dir, lang+store+".py")
				os.WriteFile(f, []byte(src), 0o644)
				if out, err := exec.Command(py, "-m", "py_compile", f).CombinedOutput(); err != nil {
					t.Errorf("python/%s does not compile: %s\n%s", store, out, src)
				}
			case "javascript":
				if node == "" {
					continue
				}
				f := filepath.Join(dir, lang+store+".mjs")
				os.WriteFile(f, []byte(src), 0o644)
				if out, err := exec.Command(node, "--check", f).CombinedOutput(); err != nil {
					t.Errorf("javascript/%s does not parse: %s\n%s", store, out, src)
				}
			case "go":
				body, decls := src, ""
				if i := strings.Index(src, "// CachedSecret:"); i >= 0 {
					body, decls = src[:i], src[i:]
				}
				file := "package x\n\nfunc f(ctx context.Context, cfg *Config) error {\n" + body + "\n\treturn nil\n}\n" + decls
				if strings.HasPrefix(strings.TrimSpace(body), "// Read once") {
					file = "package x\n\n" + src // declarations-only snippet
				}
				if _, err := parser.ParseFile(token.NewFileSet(), "x.go", file, 0); err != nil {
					t.Errorf("go/%s does not parse: %v\n%s", store, err, file)
				}
			}
		}
	}
}

func write(t *testing.T, dir, name, body string) {
	t.Helper()
	p := filepath.Join(dir, name)
	os.MkdirAll(filepath.Dir(p), 0o755)
	os.WriteFile(p, []byte(body), 0o644)
}

func TestBuildPatch(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "a.py", "#!/usr/bin/env python3\n\"\"\"doc\"\"\"\nimport sys\nTOKEN = 'SECRET1'\n")
	write(t, dir, "b.py", "import os\nX = \"SECRET2\"\n")
	write(t, dir, "c.go", "package c\n\nvar k = \"SECRET3\"")                      // no import block, no trailing newline
	write(t, dir, "d.ts", "const k = `SECRET4`;\nconst h = \"Bearer SECRET5\";\n") // second is a partial string
	write(t, dir, "e.yaml", "token: SECRET6\n")
	res := BuildPatch(dir, []PatchItem{
		{File: "a.py", Line: 4, Secret: "SECRET1", EnvVar: "TOKEN"},
		{File: "b.py", Line: 2, Secret: "SECRET2", EnvVar: "X_KEY"},
		{File: "c.go", Line: 3, Secret: "SECRET3", EnvVar: "K"},
		{File: "d.ts", Line: 1, Secret: "SECRET4", EnvVar: "K"},
		{File: "d.ts", Line: 2, Secret: "SECRET5", EnvVar: "H"},
		{File: "e.yaml", Line: 1, Secret: "SECRET6", EnvVar: "T"},
	})
	if len(res.Patched) != 4 || len(res.Skipped) != 2 {
		t.Fatalf("patched %d skipped %v", len(res.Patched), res.Skipped)
	}
	want := map[string]string{
		"a.py": "#!/usr/bin/env python3\n\"\"\"doc\"\"\"\nimport os\nimport sys\nTOKEN = os.environ[\"TOKEN\"]\n",
		"b.py": "import os\nX = os.environ[\"X_KEY\"]\n",
		"c.go": "package c\n\nimport \"os\"\n\nvar k = os.Getenv(\"K\")",
		"d.ts": "const k = process.env.K!;\nconst h = \"Bearer SECRET5\";\n",
	}
	for f, w := range want {
		if res.Files[f] != w {
			t.Errorf("%s:\n got %q\nwant %q", f, res.Files[f], w)
		}
	}
	if _, err := exec.LookPath("git"); err != nil {
		return
	}
	// The diff must apply cleanly and produce exactly the in-place result.
	if out, err := exec.Command("git", "-C", dir, "init", "-q").CombinedOutput(); err != nil {
		t.Fatal(string(out))
	}
	os.WriteFile(filepath.Join(dir, "fix.diff"), []byte(res.Diff), 0o600)
	if out, err := exec.Command("git", "-C", dir, "apply", "fix.diff").CombinedOutput(); err != nil {
		t.Fatalf("git apply failed: %s\n%s", out, res.Diff)
	}
	for f, w := range want {
		got, _ := os.ReadFile(filepath.Join(dir, f))
		if string(got) != w {
			t.Errorf("after git apply %s = %q, want %q", f, got, w)
		}
	}
}

func TestPatchSkipsEditsThatWouldNotParse(t *testing.T) {
	dir := t.TempDir()
	// The literal is inside a Go raw-string/struct tag context where an
	// expression is not allowed: replacing it would not compile.
	write(t, dir, "tag.go", "package x\n\ntype T struct {\n\tF string `json:\"f\" default:\"SECRET1\"`\n}\n\nvar k = \"SECRET2\"\n")
	res := BuildPatch(dir, []PatchItem{
		{File: "tag.go", Line: 4, Secret: "SECRET1", EnvVar: "A"},
		{File: "tag.go", Line: 7, Secret: "SECRET2", EnvVar: "B"},
	})
	// The tag literal is nested inside a raw string: never rewritten.
	if len(res.Patched) != 1 || res.Patched[0].Line != 7 || strings.Contains(res.Files["tag.go"], `default:os.Getenv`) {
		t.Fatalf("nested literal must be left alone: %+v", res)
	}
	if len(res.Skipped) != 1 || !strings.Contains(res.Skipped[0], "not a standalone quoted literal") {
		t.Errorf("skipped = %v", res.Skipped)
	}
	// Valid edits in a validated language go through.
	write(t, dir, "ok.py", "def f():\n    return {'k': \"SECRET8\"}\n")
	res = BuildPatch(dir, []PatchItem{{File: "ok.py", Line: 2, Secret: "SECRET8", EnvVar: "K8"}})
	if len(res.Patched) != 1 || !strings.Contains(res.Files["ok.py"], `os.environ["K8"]`) {
		t.Errorf("valid python edit: %+v", res)
	}
	// Unvalidated languages are flagged for manual review.
	write(t, dir, "Config.java", "class C { String k = \"SECRET3\"; }\n")
	res = BuildPatch(dir, []PatchItem{{File: "Config.java", Line: 1, Secret: "SECRET3", EnvVar: "K"}})
	if len(res.Patched) != 1 || len(res.Unchecked) != 1 {
		t.Errorf("java should be patched but marked unchecked: %+v", res)
	}
}

func TestInsideString(t *testing.T) {
	cases := map[string]bool{
		"x := \"SECRET\"":                    false,
		"F string `json:\"f\" d:\"SECRET\"`": true,
		`q = "SELECT 'SECRET' FROM t"`:       true,
		`a = "x\"y"; b = "SECRET"`:           false,
	}
	for line, want := range cases {
		i := strings.LastIndex(line, "SECRET") - 1
		if got := insideString(line, i); got != want {
			t.Errorf("insideString(%q) = %v, want %v", line, got, want)
		}
	}
}

func TestValidateRejectsBrokenEdits(t *testing.T) {
	if ok, err := Validate("go", "package x\nvar k = os.Getenv(\"K\""); !ok || err == nil {
		t.Error("broken Go should fail validation")
	}
	if _, err := exec.LookPath("python3"); err == nil {
		if ok, err := Validate("python", "x = os.environ[\"K\"\n"); !ok || err == nil {
			t.Error("broken Python should fail validation")
		}
	}
}
