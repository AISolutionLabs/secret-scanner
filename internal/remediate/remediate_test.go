package remediate

import (
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/anirudh/secretscan/internal/config"
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
