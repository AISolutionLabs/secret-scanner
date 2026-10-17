// SPDX-License-Identifier: Apache-2.0

package remediate

import (
	"regexp"
	"strings"
)

// Comment and string syntax per patchable language, for codeAt.
var (
	lineComments = map[string][]string{
		"go": {"//"}, "javascript": {"//"}, "typescript": {"//"}, "java": {"//"}, "csharp": {"//"},
		"php": {"//", "#"}, "python": {"#"}, "ruby": {"#"}, "shell": {"#"},
	}
	blockComments = map[string]bool{"go": true, "javascript": true, "typescript": true, "java": true, "csharp": true, "php": true}
	// Triple-quoted strings: Python, Java text blocks, C# raw string literals.
	tripleQuotes = map[string]bool{"python": true, "java": true, "csharp": true}
	// Backtick strings: Go raw strings, JavaScript/TypeScript templates.
	backticks = map[string]bool{"go": true, "javascript": true, "typescript": true}
	// Ordinary quoted strings may span lines only in these languages.
	multilineQuotes = map[string]bool{"shell": true, "ruby": true, "php": true}
	heredocStart    = map[string]*regexp.Regexp{
		"shell": regexp.MustCompile(`^<<-?[ \t]*(?:'([A-Za-z_]\w*)'|"([A-Za-z_]\w*)"|\\?([A-Za-z_]\w*))`),
		"ruby":  regexp.MustCompile(`^<<[~-]?(?:'([A-Za-z_]\w*)'|"([A-Za-z_]\w*)"|([A-Z_][A-Z0-9_]*))`),
		"php":   regexp.MustCompile(`^<<<[ \t]*(?:'([A-Za-z_]\w*)'|"([A-Za-z_]\w*)"|([A-Za-z_]\w*))`),
	}
)

// codeAt reports whether byte offset off of src is in code, that is not
// inside a comment, a string, a multi-line string (Go raw strings,
// JavaScript templates, Python and Java/C# triple quotes, C# verbatim
// strings) or a heredoc body that started before it. A quoted secret there
// is text, not an expression slot: replacing it would still parse but would
// silently change the program's data.
//
// It is a small lexer for --fix only, and it errs towards "not code": a
// construct it does not model (a regex literal, a template expression)
// makes it skip the edit, never rewrite text.
func codeAt(lang, src string, off int) bool {
	if off < 0 || off > len(src) {
		return false
	}
	lineC := lineComments[lang]
	lineEnd := func(i int) int {
		if j := strings.IndexByte(src[i:], '\n'); j >= 0 {
			return i + j
		}
		return len(src)
	}
	// closing returns the offset just past the quote that closes a string
	// opened at i (whose opening delimiter is open), honoring backslash
	// escapes when esc is set.
	closing := func(i int, open, close string, esc, multiline bool) int {
		j := i + len(open)
		for j < len(src) {
			switch {
			case esc && src[j] == '\\':
				j += 2
				continue
			case strings.HasPrefix(src[j:], close):
				return j + len(close)
			case src[j] == '\n' && !multiline:
				return j
			}
			j++
		}
		return len(src)
	}
	pending := "" // heredoc terminator: the body starts on the next line
	for i := 0; i < off; {
		c, rest := src[i], src[i:]
		atLineStart := i == 0 || src[i-1] == '\n'
		switch {
		case c == '\n':
			i++
			if pending == "" {
				continue
			}
			for i < len(src) { // heredoc body, up to and including its terminator line
				end := lineEnd(i)
				if off >= i && off <= end {
					return false
				}
				done := strings.TrimSpace(src[i:end]) == pending
				i = min(end+1, len(src))
				if done {
					break
				}
			}
			pending = ""
			continue
		case lang == "ruby" && atLineStart && strings.HasPrefix(rest, "=begin"):
			e := len(src)
			if j := strings.Index(rest, "\n=end"); j >= 0 {
				e = lineEnd(i + j + 1)
			}
			if off < e {
				return false
			}
			i = e
			continue
		case blockComments[lang] && strings.HasPrefix(rest, "/*"):
			e := len(src)
			if j := strings.Index(src[i+2:], "*/"); j >= 0 {
				e = i + 2 + j + 2
			}
			if off < e {
				return false
			}
			i = e
			continue
		case tripleQuotes[lang] && (strings.HasPrefix(rest, `"""`) || lang == "python" && strings.HasPrefix(rest, "'''")):
			if e := closing(i, rest[:3], rest[:3], lang != "csharp", true); off < e {
				return false
			} else {
				i = e
			}
			continue
		case lang == "csharp" && (strings.HasPrefix(rest, `@"`) || strings.HasPrefix(rest, `$@"`) || strings.HasPrefix(rest, `@$"`)):
			open := rest[:strings.IndexByte(rest, '"')+1]
			e := len(src)
			for j := i + len(open); j < len(src); j++ {
				if src[j] == '"' {
					if j+1 < len(src) && src[j+1] == '"' {
						j++ // "" is an escaped quote
						continue
					}
					e = j + 1
					break
				}
			}
			if off < e {
				return false
			}
			i = e
			continue
		case backticks[lang] && c == '`':
			if e := closing(i, "`", "`", lang != "go", true); off < e {
				return false
			} else {
				i = e
			}
			continue
		case c == '"' || c == '\'':
			esc := !(lang == "shell" && c == '\'')
			if e := closing(i, string(c), string(c), esc, multilineQuotes[lang]); off < e {
				return false
			} else {
				i = e
			}
			continue
		case c == '<' && heredocStart[lang] != nil && !strings.HasPrefix(rest, "<<<") || c == '<' && lang == "php":
			if m := heredocStart[lang].FindStringSubmatch(rest); m != nil {
				pending = m[1] + m[2] + m[3]
				i += len(m[0])
				continue
			}
		}
		if lc := lineComment(lang, lineC, src, i); lc {
			if e := lineEnd(i); off < e {
				return false
			} else {
				i = e
			}
			continue
		}
		i++
	}
	return true
}

// lineComment reports a line comment starting at i. A shell # starts a
// comment only at the start of a word ($#, ${#x} and a#b do not); PHP #[
// is an attribute.
func lineComment(lang string, markers []string, src string, i int) bool {
	for _, m := range markers {
		if !strings.HasPrefix(src[i:], m) {
			continue
		}
		if m == "#" && lang == "shell" && i > 0 && !strings.ContainsRune(" \t\n;|&(", rune(src[i-1])) {
			continue
		}
		if m == "#" && lang == "php" && strings.HasPrefix(src[i:], "#[") {
			continue
		}
		return true
	}
	return false
}
