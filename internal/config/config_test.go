package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func write(t *testing.T, dir, name, body string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func ruleIDs(c *Config) map[string]Rule {
	m := map[string]Rule{}
	for _, r := range c.Rules {
		m[r.ID] = r
	}
	return m
}

func TestDefaultsCompile(t *testing.T) {
	rs, err := Compile(Default())
	if err != nil {
		t.Fatal(err)
	}
	if len(rs.Rules) < 100 {
		t.Errorf("expected 100+ default rules, got %d", len(rs.Rules))
	}
	for _, r := range rs.Rules {
		if r.Re != nil && len(r.LowerKeys) == 0 {
			t.Errorf("default rule %s has no keywords (slow path)", r.ID)
		}
	}
}

func TestCustomRulesAreAdditiveAndOverride(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, ".secretscan.toml", `
[extend]
disabledRules = ["jwt"]

[[rules]]
id = "acme-token"
regex = '''\b(acme_[a-z0-9]{24})\b'''
keywords = ["acme_"]
severity = "critical"
examples = ["key = acme_abcdefghijklmnop12345678"]

[[rules]]
id = "github-pat"
description = "overridden"
regex = 'ghp_[0-9a-zA-Z]{36}'
`)
	c, _, err := Resolve(Options{SearchDirs: []string{dir}})
	if err != nil {
		t.Fatal(err)
	}
	ids := ruleIDs(c)
	if _, ok := ids["acme-token"]; !ok {
		t.Error("custom rule missing")
	}
	if _, ok := ids["aws-access-key-id"]; !ok {
		t.Error("defaults should be kept (additive)")
	}
	if _, ok := ids["jwt"]; ok {
		t.Error("disabledRules not applied")
	}
	if ids["github-pat"].Description != "overridden" {
		t.Error("same-id rule should override default")
	}
}

func TestUseDefaultFalseAndExtendPath(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "base.toml", `
[extend]
useDefault = false
[[rules]]
id = "base-rule"
regex = 'base_[0-9]{8}'
`)
	p := write(t, dir, "child.toml", `
[extend]
path = "base.toml"
[[rules]]
id = "child-rule"
regex = 'child_[0-9]{8}'
`)
	c, _, err := Resolve(Options{ConfigPath: p})
	if err != nil {
		t.Fatal(err)
	}
	ids := ruleIDs(c)
	if len(ids) != 2 || ids["base-rule"].ID == "" || ids["child-rule"].ID == "" {
		t.Errorf("got rules %v", ids)
	}
}

func TestPatternsFlagsAndFile(t *testing.T) {
	dir := t.TempDir()
	pf := write(t, dir, "patterns.txt", "# comment\ncorp-key=corp_[A-Z0-9]{20} ;; severity=critical ;; entropy=3\n\nraw_[0-9]{10}\n")
	c, _, err := Resolve(Options{
		NoDefaults:    true,
		Patterns:      []string{`tenant-id=(?i)tenant[_-]?secret\s*=\s*([a-z0-9]{16}) ;; group=1 ;; keywords=tenant`},
		PatternsFiles: []string{pf},
	})
	if err != nil {
		t.Fatal(err)
	}
	ids := ruleIDs(c)
	if r := ids["tenant-id"]; r.SecretGroup != 1 || r.Keywords[0] != "tenant" {
		t.Errorf("tenant-id = %+v", r)
	}
	if r := ids["corp-key"]; r.Severity != "critical" || r.Entropy != 3 {
		t.Errorf("corp-key = %+v", r)
	}
	if _, ok := ids["custom-pattern-3"]; !ok {
		t.Errorf("bare regex should get an id, got %v", ids)
	}
	rs, err := Compile(c)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range rs.Rules {
		if r.ID == "corp-key" && (len(r.LowerKeys) == 0 || r.LowerKeys[0] != "corp_") {
			t.Errorf("literal prefix keyword not derived: %v", r.LowerKeys)
		}
	}
}

func TestFilters(t *testing.T) {
	c, _, err := Resolve(Options{Tags: []string{"aws"}, DisableRules: []string{"aws-session-token"}})
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range c.Rules {
		if !strings.HasPrefix(r.ID, "aws-") || r.ID == "aws-session-token" {
			t.Errorf("unexpected rule %s", r.ID)
		}
	}
	c, _, _ = Resolve(Options{EnableRules: []string{"github-pat,gitlab-pat"}})
	if len(c.Rules) != 2 {
		t.Errorf("enable-rule: got %d rules", len(c.Rules))
	}
}

func TestCompileErrors(t *testing.T) {
	bad := []Rule{
		{ID: "", Regex: "x"},
		{ID: "a", Regex: "("},
		{ID: "b", Regex: "x", SecretGroup: 2},
		{ID: "c", Regex: "x", Severity: "urgent"},
		{ID: "d"},
	}
	for _, r := range bad {
		if _, err := Compile(&Config{Rules: []Rule{r}}); err == nil {
			t.Errorf("expected compile error for %+v", r)
		}
	}
	if _, err := Compile(&Config{Rules: []Rule{{ID: "x", Regex: "y", Allowlists: []Allowlist{{TargetRules: []string{"z"}, Paths: []string{"p"}}}}}}); err == nil {
		t.Error("targetRules in rule allowlist should fail")
	}
}

func TestAllowlistConditions(t *testing.T) {
	or, _ := compileAllowlist(Allowlist{Paths: []string{`^test/`}, Regexes: []string{`^dummy`}}, true)
	and, _ := compileAllowlist(Allowlist{Condition: "AND", Paths: []string{`^test/`}, Regexes: []string{`^dummy`}}, true)
	if !or.Allowed("test/a.go", "", "real", "", "") || !or.Allowed("src/a.go", "", "dummy1", "", "") {
		t.Error("OR semantics")
	}
	if and.Allowed("test/a.go", "", "real", "", "") || !and.Allowed("test/a.go", "", "dummy1", "", "") {
		t.Error("AND semantics")
	}
	line, _ := compileAllowlist(Allowlist{RegexTarget: "line", Regexes: []string{`getenv`}}, false)
	if !line.Allowed("a", "", "s", "m", `x = getenv("A")`) {
		t.Error("line target")
	}
	commit, _ := compileAllowlist(Allowlist{Commits: []string{"abcdef1"}}, true)
	if !commit.Allowed("a", "abcdef1234567890", "s", "", "") {
		t.Error("commit prefix match")
	}
}

func TestUnknownKeysWarn(t *testing.T) {
	_, warnings, err := Load([]byte("[[rules]]\nid='a'\nregex='b'\nminVersion='1'\n"), false)
	if err != nil {
		t.Fatal(err)
	}
	if len(warnings) == 0 {
		t.Error("expected a warning for unknown key")
	}
}
