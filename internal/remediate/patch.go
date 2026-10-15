// SPDX-License-Identifier: Apache-2.0

package remediate

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// PatchItem is one literal to replace.
type PatchItem struct {
	File   string // relative to Root
	Line   int    // 1-based
	Secret string
	EnvVar string
}

// PatchResult is a unified diff plus what could not be patched.
type PatchResult struct {
	Diff    string
	Patched []PatchItem
	Skipped []string          // human-readable reasons
	EnvVars []string          // variables the patched code now expects
	Files   map[string]string // new content per file (for in-place --fix)
	// Unchecked lists files whose language has no syntax validator here.
	Unchecked []string
	Langs     []string // languages touched (for caveats)
}

func appendUnique(xs []string, x string) []string {
	for _, y := range xs {
		if y == x {
			return xs
		}
	}
	return append(xs, x)
}

// patchable languages: literal -> expression, plus an optional import.
var patchExpr = map[string]func(env string) string{
	"python":     func(e string) string { return `os.environ["` + e + `"]` },
	"go":         func(e string) string { return `os.Getenv("` + e + `")` },
	"javascript": func(e string) string { return `process.env.` + e },
	"typescript": func(e string) string { return `process.env.` + e + `!` },
	"java":       func(e string) string { return `System.getenv("` + e + `")` },
	"csharp":     func(e string) string { return `Environment.GetEnvironmentVariable("` + e + `")` },
	"ruby":       func(e string) string { return `ENV.fetch("` + e + `")` },
	"php":        func(e string) string { return `getenv('` + e + `')` },
	"shell":      func(e string) string { return `"${` + e + `:?not set}"` },
}

// BuildPatch replaces each quoted secret literal with an environment lookup
// in the file's language and returns a unified diff for `git apply`.
// Unquoted values (YAML, .env, properties) are reported as skipped: they need
// moving to a secret store rather than a code change.
func BuildPatch(root string, items []PatchItem) PatchResult {
	res := PatchResult{Files: map[string]string{}}
	byFile := map[string][]PatchItem{}
	for _, it := range items {
		byFile[it.File] = append(byFile[it.File], it)
	}
	files := make([]string, 0, len(byFile))
	for f := range byFile {
		files = append(files, f)
	}
	sort.Strings(files)
	envSeen := map[string]bool{}
	for _, file := range files {
		lang := LanguageFor(file)
		mk, ok := patchExpr[lang]
		if !ok {
			for _, it := range byFile[file] {
				res.Skipped = append(res.Skipped, fmt.Sprintf("%s:%d: not code (%s); move the value to your secret store and reference %s", file, it.Line, nonEmpty(lang, "unknown type"), it.EnvVar))
			}
			continue
		}
		data, err := os.ReadFile(filepath.Join(root, file))
		if err != nil {
			res.Skipped = append(res.Skipped, fmt.Sprintf("%s: %v", file, err))
			continue
		}
		oldLines, trailingNL := splitLines(string(data))
		patchedBefore, envBefore := len(res.Patched), len(res.EnvVars)
		envSeenBefore := map[string]bool{}
		for k := range envSeen {
			envSeenBefore[k] = true
		}
		newLines := append([]string(nil), oldLines...)
		changed := map[int]bool{}
		for _, it := range byFile[file] {
			i := it.Line - 1
			if i < 0 || i >= len(newLines) || it.Secret == "" {
				res.Skipped = append(res.Skipped, fmt.Sprintf("%s:%d: line not found (file changed since scan?)", file, it.Line))
				continue
			}
			repl, ok := replaceQuoted(newLines[i], it.Secret, mk(it.EnvVar), lang)
			if !ok {
				res.Skipped = append(res.Skipped, fmt.Sprintf("%s:%d: secret is not a standalone quoted literal; edit by hand and use %s", file, it.Line, EnvExpr(lang, it.EnvVar)))
				continue
			}
			newLines[i] = repl
			changed[i] = true
			res.Patched = append(res.Patched, it)
			if !envSeen[it.EnvVar] {
				envSeen[it.EnvVar] = true
				res.EnvVars = append(res.EnvVars, it.EnvVar)
			}
		}
		if len(changed) == 0 {
			continue
		}
		insertAt, importLine := importFor(lang, newLines)
		// Never emit a change that breaks the file: validate the result
		// (when the original itself parses).
		final := append([]string(nil), newLines...)
		if insertAt >= 0 {
			final = append(final[:insertAt], append(strings.Split(importLine, "\n"), final[insertAt:]...)...)
		}
		content := strings.Join(final, "\n")
		if trailingNL {
			content += "\n"
		}
		if okOrig, origErr := Validate(lang, string(data)); okOrig && origErr == nil {
			if _, err := Validate(lang, content); err != nil {
				for _, it := range byFile[file] {
					res.Skipped = append(res.Skipped, fmt.Sprintf("%s:%d: automatic edit would not parse (%v); edit by hand using %s", file, it.Line, err, EnvExpr(lang, it.EnvVar)))
				}
				// Roll back this file's bookkeeping.
				res.Patched, res.EnvVars = res.Patched[:patchedBefore], res.EnvVars[:envBefore]
				envSeen = envSeenBefore
				continue
			}
		} else if !okOrig {
			res.Unchecked = append(res.Unchecked, file)
		}
		res.Langs = appendUnique(res.Langs, lang)
		res.Diff += unifiedDiff(file, oldLines, newLines, changed, insertAt, importLine, trailingNL)
		res.Files[file] = content
	}
	sort.Strings(res.EnvVars)
	return res
}

func nonEmpty(s, def string) string {
	if s == "" {
		return def
	}
	return s
}

func splitLines(s string) ([]string, bool) {
	trailing := strings.HasSuffix(s, "\n")
	s = strings.TrimSuffix(s, "\n")
	if s == "" {
		return nil, trailing
	}
	return strings.Split(s, "\n"), trailing
}

// replaceQuoted swaps "secret" (with its quotes) for expr. The literal must
// be exactly the secret, so partial strings like "Bearer xyz" are left alone.
func replaceQuoted(line, secret, expr, lang string) (string, bool) {
	quotes := `"'`
	if lang == "javascript" || lang == "typescript" {
		quotes += "`"
	}
	for _, q := range quotes {
		lit := string(q) + secret + string(q)
		if i := strings.Index(line, lit); i >= 0 {
			if insideString(line, i) {
				return line, false // nested in another literal (struct tag, template, SQL...): not an expression slot
			}
			if lang == "python" && i > 0 && strings.ContainsRune("rRbBuUfF", rune(line[i-1])) && (i < 2 || !isIdent(line[i-2])) {
				i-- // r"..." / b"..." prefixes
				lit = line[i:i+1] + lit
			}
			return line[:i] + expr + line[i+len(lit):], true
		}
	}
	return line, false
}

func isIdent(c byte) bool {
	return c == '_' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9'
}

var (
	pyImportOS = regexp.MustCompile(`(?m)^\s*(?:import\s+(?:[\w.]+\s*,\s*)*os(?:\s*,|\s*$|\s+as\s)|from\s+os\s+import)`)
	pyTopImp   = regexp.MustCompile(`^(?:import|from)\s`)
	goImportOS = regexp.MustCompile(`(?m)^\s*(?:import\s+)?(?:\w+\s+)?"os"\s*$`)
)

// importFor returns where to insert an import line (index in the new file,
// before that line) or -1 when none is needed.
func importFor(lang string, lines []string) (int, string) {
	text := strings.Join(lines, "\n")
	switch lang {
	case "python":
		if pyImportOS.MatchString(text) {
			return -1, ""
		}
		for i, l := range lines {
			if pyTopImp.MatchString(l) && !strings.HasPrefix(l, "from __future__") {
				return i, "import os"
			}
		}
		i := 0
		for i < len(lines) && (strings.HasPrefix(lines[i], "#") || strings.HasPrefix(lines[i], "from __future__")) {
			i++
		}
		return i, "import os"
	case "go":
		if goImportOS.MatchString(text) {
			return -1, ""
		}
		for i, l := range lines {
			if strings.TrimSpace(l) == "import (" {
				// Keep the block sorted: insert before the first path that sorts after "os".
				j := i + 1
				for ; j < len(lines) && strings.TrimSpace(lines[j]) != ")"; j++ {
					t := strings.TrimSpace(lines[j])
					if t == "" {
						break // stop at the end of the first (stdlib) group
					}
					if q := strings.Index(t, `"`); q >= 0 && t[q:] > `"os"` {
						break
					}
				}
				return j, "\t\"os\""
			}
		}
		for i, l := range lines {
			if strings.HasPrefix(l, "package ") {
				return i + 1, "\nimport \"os\""
			}
		}
	}
	return -1, ""
}

// unifiedDiff renders replacements (changed lines) and one optional inserted
// line as a git-style unified diff with 3 lines of context.
func unifiedDiff(file string, oldL, newL []string, changed map[int]bool, insertAt int, insert string, trailingNL bool) string {
	type op struct {
		kind byte // ' ', '-', '+'
		text string
	}
	// Edit points in old-line coordinates.
	var points []int
	for i := range changed {
		points = append(points, i)
	}
	if insertAt >= 0 {
		points = append(points, insertAt)
	}
	sort.Ints(points)
	// Group points into hunks.
	type span struct{ a, b int } // old-line range [a,b)
	var spans []span
	for _, p := range points {
		a, b := max(0, p-3), min(len(oldL), p+4)
		if len(spans) > 0 && a <= spans[len(spans)-1].b {
			spans[len(spans)-1].b = max(spans[len(spans)-1].b, b)
		} else {
			spans = append(spans, span{a, b})
		}
	}
	var out strings.Builder
	fmt.Fprintf(&out, "diff --git a/%s b/%s\n--- a/%s\n+++ b/%s\n", file, file, file, file)
	delta := 0
	for _, sp := range spans {
		var ops []op
		for i := sp.a; i <= sp.b; i++ {
			if i == insertAt && insert != "" {
				for _, l := range strings.Split(insert, "\n") {
					ops = append(ops, op{'+', l})
				}
			}
			if i == sp.b {
				break
			}
			if changed[i] {
				ops = append(ops, op{'-', oldL[i]}, op{'+', newL[i]})
			} else {
				ops = append(ops, op{' ', oldL[i]})
			}
		}
		oldN, newN := 0, 0
		for _, o := range ops {
			if o.kind != '+' {
				oldN++
			}
			if o.kind != '-' {
				newN++
			}
		}
		oldStart, newStart := sp.a+1, sp.a+1+delta
		if oldN == 0 {
			oldStart--
		}
		if newN == 0 {
			newStart--
		}
		fmt.Fprintf(&out, "@@ -%d,%d +%d,%d @@\n", oldStart, oldN, newStart, newN)
		// The final old-side and new-side lines get git's no-newline marker
		// when the file lacks a trailing newline and the hunk reaches EOF.
		lastOldIdx, lastNewIdx := -1, -1
		for idx, o := range ops {
			if o.kind != '+' {
				lastOldIdx = idx
			}
			if o.kind != '-' {
				lastNewIdx = idx
			}
		}
		atEOF := sp.b == len(oldL) && !trailingNL
		for idx, o := range ops {
			out.WriteByte(o.kind)
			out.WriteString(o.text)
			out.WriteByte('\n')
			if atEOF && (idx == lastOldIdx && o.kind != '+' || idx == lastNewIdx && o.kind != '-') {
				out.WriteString("\\ No newline at end of file\n")
			}
		}
		delta += newN - oldN
	}
	return out.String()
}

// insideString reports whether byte offset i of line falls inside a string
// literal that started earlier on the line (", ', or `), honoring escapes.
func insideString(line string, i int) bool {
	var open byte
	for j := 0; j < i; j++ {
		c := line[j]
		switch {
		case open == 0 && (c == '"' || c == '\'' || c == '`'):
			open = c
		case open != 0 && c == '\\' && open != '`':
			j++ // skip escaped char
		case open != 0 && c == open:
			open = 0
		}
	}
	return open != 0
}
