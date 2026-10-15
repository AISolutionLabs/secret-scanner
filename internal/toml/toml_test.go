// SPDX-License-Identifier: Apache-2.0

package toml

import (
	"reflect"
	"testing"
)

func TestGitleaksStyleConfig(t *testing.T) {
	src := `
title = "custom"   # trailing comment

[extend]
useDefault = true
disabledRules = ["generic-api-key",
  "jwt", # multi-line array with comment
]

[[rules]]
id = "internal-token"
description = "Internal \"svc\" token!"
regex = '''(?i)\b(itk_[a-z0-9]{32})\b'''
secretGroup = 1
entropy = 3.5
keywords = ['itk_']
tags = ["internal"]

  [rules.allowlist]
  regexes = ['''itk_0{32}''']
  paths = ['(?:^|/)testdata/']

[[rules]]
id = "second"
regex = "x"
inline = { a = 1, b.c = 'd' }

[[allowlists]]
description = "fixtures"
paths = ['''(?:^|/)fixtures/''']
commits = [ "abc1234", ]
num = 1_000
neg = -3.5e2
hex = 0xff
`
	got, err := Parse([]byte(src))
	if err != nil {
		t.Fatal(err)
	}
	if got["title"] != "custom" {
		t.Errorf("title = %v", got["title"])
	}
	ext := got["extend"].(map[string]any)
	if !reflect.DeepEqual(ext["disabledRules"], []any{"generic-api-key", "jwt"}) {
		t.Errorf("disabledRules = %#v", ext["disabledRules"])
	}
	rules := got["rules"].([]any)
	if len(rules) != 2 {
		t.Fatalf("want 2 rules, got %d", len(rules))
	}
	r0 := rules[0].(map[string]any)
	if r0["regex"] != `(?i)\b(itk_[a-z0-9]{32})\b` || r0["secretGroup"] != int64(1) || r0["entropy"] != 3.5 {
		t.Errorf("rule0 = %#v", r0)
	}
	if r0["description"] != `Internal "svc" token!` {
		t.Errorf("escape handling: %q", r0["description"])
	}
	al := r0["allowlist"].(map[string]any)
	if !reflect.DeepEqual(al["regexes"], []any{"itk_0{32}"}) {
		t.Errorf("rule allowlist attached to wrong table: %#v", r0)
	}
	inl := rules[1].(map[string]any)["inline"].(map[string]any)
	if inl["a"] != int64(1) || inl["b"].(map[string]any)["c"] != "d" {
		t.Errorf("inline table = %#v", inl)
	}
	gal := got["allowlists"].([]any)[0].(map[string]any)
	if gal["num"] != int64(1000) || gal["neg"] != -350.0 || gal["hex"] != int64(255) {
		t.Errorf("numbers = %#v", gal)
	}
}

func TestMultilineStrings(t *testing.T) {
	got, err := Parse([]byte("a = \"\"\"\nline1\\\n   line2\"\"\"\nb = '''\nraw\\n'''\n"))
	if err != nil {
		t.Fatal(err)
	}
	if got["a"] != "line1line2" || got["b"] != `raw\n` {
		t.Errorf("got %#v", got)
	}
}

func TestErrors(t *testing.T) {
	for _, src := range []string{
		"a = ",
		"a = 'unterminated",
		"a = 1\na = 2",
		`a = "bad \d escape"`,
		"[tbl\nx=1",
		"a = [1, 2",
		"a = 1 b = 2",
	} {
		if _, err := Parse([]byte(src)); err == nil {
			t.Errorf("expected error for %q", src)
		}
	}
}
