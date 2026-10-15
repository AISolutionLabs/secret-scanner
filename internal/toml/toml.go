// SPDX-License-Identifier: Apache-2.0

// Package toml implements a dependency-free parser for the subset of TOML v1.0
// used by scanner configuration files (including gitleaks-style configs):
// tables, arrays of tables, dotted and quoted keys, all four string forms,
// integers, floats, booleans, nested/multi-line arrays and inline tables.
// Date/time values are returned as their literal string.
package toml

import (
	"fmt"
	"strconv"
	"strings"
	"unicode/utf8"
)

// Parse decodes TOML into a tree of map[string]any, []any, string, int64,
// float64 and bool values.
func Parse(data []byte) (map[string]any, error) {
	if !utf8.Valid(data) {
		return nil, fmt.Errorf("toml: input is not valid UTF-8")
	}
	p := &parser{s: string(data)}
	p.root = map[string]any{}
	p.cur = p.root
	if err := p.run(); err != nil {
		return nil, err
	}
	return p.root, nil
}

type parser struct {
	s    string
	i    int
	root map[string]any
	cur  map[string]any
}

func (p *parser) errf(format string, a ...any) error {
	line := 1 + strings.Count(p.s[:min(p.i, len(p.s))], "\n")
	return fmt.Errorf("toml: line %d: %s", line, fmt.Sprintf(format, a...))
}

func (p *parser) eof() bool { return p.i >= len(p.s) }
func (p *parser) peek() byte {
	if p.eof() {
		return 0
	}
	return p.s[p.i]
}
func (p *parser) has(prefix string) bool { return strings.HasPrefix(p.s[p.i:], prefix) }

func (p *parser) skipSpaces() {
	for !p.eof() && (p.s[p.i] == ' ' || p.s[p.i] == '\t') {
		p.i++
	}
}

func (p *parser) skipComment() {
	if p.peek() == '#' {
		for !p.eof() && p.s[p.i] != '\n' {
			p.i++
		}
	}
}

// skipAll skips whitespace, newlines and comments.
func (p *parser) skipAll() {
	for !p.eof() {
		switch p.s[p.i] {
		case ' ', '\t', '\r', '\n':
			p.i++
		case '#':
			p.skipComment()
		default:
			return
		}
	}
}

func (p *parser) expectEOL() error {
	p.skipSpaces()
	p.skipComment()
	if p.eof() {
		return nil
	}
	if p.has("\r\n") {
		p.i += 2
		return nil
	}
	if p.peek() == '\n' {
		p.i++
		return nil
	}
	return p.errf("unexpected %q after value", p.peek())
}

func (p *parser) run() error {
	for {
		p.skipAll()
		if p.eof() {
			return nil
		}
		if p.has("[[") {
			p.i += 2
			key, err := p.parseKey()
			if err != nil {
				return err
			}
			p.skipSpaces()
			if !p.has("]]") {
				return p.errf("expected ]] to close array-of-tables header")
			}
			p.i += 2
			if err := p.openArrayTable(key); err != nil {
				return err
			}
		} else if p.peek() == '[' {
			p.i++
			key, err := p.parseKey()
			if err != nil {
				return err
			}
			p.skipSpaces()
			if p.peek() != ']' {
				return p.errf("expected ] to close table header")
			}
			p.i++
			t, err := p.descend(p.root, key)
			if err != nil {
				return err
			}
			p.cur = t
		} else {
			key, err := p.parseKey()
			if err != nil {
				return err
			}
			p.skipSpaces()
			if p.peek() != '=' {
				return p.errf("expected = after key %q", strings.Join(key, "."))
			}
			p.i++
			p.skipSpaces()
			v, err := p.parseValue()
			if err != nil {
				return err
			}
			if err := p.set(p.cur, key, v); err != nil {
				return err
			}
		}
		if err := p.expectEOL(); err != nil {
			return err
		}
	}
}

// descend walks/creates tables along key. Arrays of tables resolve to their
// last element, which is how [rules.allowlist] attaches to the latest [[rules]].
func (p *parser) descend(t map[string]any, key []string) (map[string]any, error) {
	for _, k := range key {
		switch v := t[k].(type) {
		case nil:
			n := map[string]any{}
			t[k] = n
			t = n
		case map[string]any:
			t = v
		case []any:
			if len(v) == 0 {
				return nil, p.errf("key %q is an empty array", k)
			}
			last, ok := v[len(v)-1].(map[string]any)
			if !ok {
				return nil, p.errf("key %q is not a table", k)
			}
			t = last
		default:
			return nil, p.errf("key %q already defined as a value", k)
		}
	}
	return t, nil
}

func (p *parser) openArrayTable(key []string) error {
	parent, err := p.descend(p.root, key[:len(key)-1])
	if err != nil {
		return err
	}
	last := key[len(key)-1]
	n := map[string]any{}
	switch v := parent[last].(type) {
	case nil:
		parent[last] = []any{n}
	case []any:
		parent[last] = append(v, n)
	default:
		return p.errf("key %q is not an array of tables", last)
	}
	p.cur = n
	return nil
}

func (p *parser) set(t map[string]any, key []string, v any) error {
	t, err := p.descend(t, key[:len(key)-1])
	if err != nil {
		return err
	}
	last := key[len(key)-1]
	if _, exists := t[last]; exists {
		return p.errf("duplicate key %q", strings.Join(key, "."))
	}
	t[last] = v
	return nil
}

func isBare(c byte) bool {
	return c == '_' || c == '-' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
}

func (p *parser) parseKey() ([]string, error) {
	var parts []string
	for {
		p.skipSpaces()
		var part string
		switch c := p.peek(); {
		case c == '"':
			s, err := p.basicString()
			if err != nil {
				return nil, err
			}
			part = s
		case c == '\'':
			s, err := p.literalString()
			if err != nil {
				return nil, err
			}
			part = s
		case isBare(c):
			start := p.i
			for !p.eof() && isBare(p.s[p.i]) {
				p.i++
			}
			part = p.s[start:p.i]
		default:
			return nil, p.errf("invalid key character %q", c)
		}
		parts = append(parts, part)
		p.skipSpaces()
		if p.peek() != '.' {
			return parts, nil
		}
		p.i++
	}
}

func (p *parser) parseValue() (any, error) {
	switch {
	case p.has(`"""`):
		return p.multiBasicString()
	case p.has(`'''`):
		return p.multiLiteralString()
	case p.peek() == '"':
		return p.basicString()
	case p.peek() == '\'':
		return p.literalString()
	case p.peek() == '[':
		return p.array()
	case p.peek() == '{':
		return p.inlineTable()
	case p.has("true") && p.boundary(4):
		p.i += 4
		return true, nil
	case p.has("false") && p.boundary(5):
		p.i += 5
		return false, nil
	}
	return p.scalar()
}

func (p *parser) boundary(n int) bool {
	j := p.i + n
	return j >= len(p.s) || strings.IndexByte(" \t\r\n,]}#", p.s[j]) >= 0
}

func (p *parser) scalar() (any, error) {
	start := p.i
	for !p.eof() && strings.IndexByte(" \t\r\n,]}#", p.s[p.i]) < 0 {
		p.i++
	}
	tok := p.s[start:p.i]
	if tok == "" {
		return nil, p.errf("missing value")
	}
	if n, err := strconv.ParseInt(tok, 0, 64); err == nil {
		return n, nil
	}
	clean := strings.ReplaceAll(tok, "_", "")
	if f, err := strconv.ParseFloat(clean, 64); err == nil {
		return f, nil
	}
	switch clean {
	case "inf", "+inf", "-inf", "nan", "+nan", "-nan":
		f, _ := strconv.ParseFloat(strings.Replace(clean, "inf", "Inf", 1), 64)
		return f, nil
	}
	if len(tok) >= 8 && tok[0] >= '0' && tok[0] <= '9' && strings.ContainsAny(tok, "-:") {
		// Offset/local date-time (date and time separated by a space is
		// not supported; use the 'T' form).
		return tok, nil
	}
	return nil, p.errf("invalid value %q", tok)
}

func (p *parser) array() ([]any, error) {
	p.i++ // [
	out := []any{}
	for {
		p.skipAll()
		if p.peek() == ']' {
			p.i++
			return out, nil
		}
		if p.eof() {
			return nil, p.errf("unterminated array")
		}
		v, err := p.parseValue()
		if err != nil {
			return nil, err
		}
		out = append(out, v)
		p.skipAll()
		switch p.peek() {
		case ',':
			p.i++
		case ']':
			p.i++
			return out, nil
		default:
			return nil, p.errf("expected , or ] in array, got %q", p.peek())
		}
	}
}

func (p *parser) inlineTable() (map[string]any, error) {
	p.i++ // {
	out := map[string]any{}
	p.skipSpaces()
	if p.peek() == '}' {
		p.i++
		return out, nil
	}
	for {
		key, err := p.parseKey()
		if err != nil {
			return nil, err
		}
		p.skipSpaces()
		if p.peek() != '=' {
			return nil, p.errf("expected = in inline table")
		}
		p.i++
		p.skipSpaces()
		v, err := p.parseValue()
		if err != nil {
			return nil, err
		}
		if err := p.set(out, key, v); err != nil {
			return nil, err
		}
		p.skipSpaces()
		switch p.peek() {
		case ',':
			p.i++
		case '}':
			p.i++
			return out, nil
		default:
			return nil, p.errf("expected , or } in inline table")
		}
	}
}

func (p *parser) literalString() (string, error) {
	p.i++
	end := strings.IndexAny(p.s[p.i:], "'\n")
	if end < 0 || p.s[p.i+end] != '\'' {
		return "", p.errf("unterminated literal string")
	}
	s := p.s[p.i : p.i+end]
	p.i += end + 1
	return s, nil
}

func (p *parser) multiLiteralString() (string, error) {
	p.i += 3
	if p.has("\r\n") {
		p.i += 2
	} else if p.peek() == '\n' {
		p.i++
	}
	end := strings.Index(p.s[p.i:], "'''")
	if end < 0 {
		return "", p.errf("unterminated multi-line literal string")
	}
	// Allow up to two extra quotes immediately before the closing delimiter.
	for k := 0; k < 2 && p.i+end+3 < len(p.s) && p.s[p.i+end+3] == '\''; k++ {
		end++
	}
	s := p.s[p.i : p.i+end]
	p.i += end + 3
	return s, nil
}

func (p *parser) basicString() (string, error) {
	p.i++
	var b strings.Builder
	for {
		if p.eof() || p.peek() == '\n' {
			return "", p.errf("unterminated string")
		}
		c := p.s[p.i]
		switch c {
		case '"':
			p.i++
			return b.String(), nil
		case '\\':
			if err := p.escape(&b, false); err != nil {
				return "", err
			}
		default:
			b.WriteByte(c)
			p.i++
		}
	}
}

func (p *parser) multiBasicString() (string, error) {
	p.i += 3
	if p.has("\r\n") {
		p.i += 2
	} else if p.peek() == '\n' {
		p.i++
	}
	var b strings.Builder
	for {
		if p.eof() {
			return "", p.errf("unterminated multi-line string")
		}
		if p.has(`"""`) {
			extra := 0
			for extra < 2 && p.i+3+extra < len(p.s) && p.s[p.i+3+extra] == '"' {
				extra++
			}
			b.WriteString(strings.Repeat(`"`, extra))
			p.i += 3 + extra
			return b.String(), nil
		}
		c := p.s[p.i]
		if c == '\\' {
			if err := p.escape(&b, true); err != nil {
				return "", err
			}
			continue
		}
		b.WriteByte(c)
		p.i++
	}
}

func (p *parser) escape(b *strings.Builder, multiline bool) error {
	p.i++ // backslash
	if p.eof() {
		return p.errf("invalid escape at end of input")
	}
	c := p.s[p.i]
	p.i++
	switch c {
	case 'b':
		b.WriteByte('\b')
	case 't':
		b.WriteByte('\t')
	case 'n':
		b.WriteByte('\n')
	case 'f':
		b.WriteByte('\f')
	case 'r':
		b.WriteByte('\r')
	case 'e':
		b.WriteByte(0x1b)
	case '"':
		b.WriteByte('"')
	case '\\':
		b.WriteByte('\\')
	case 'u', 'U':
		n := 4
		if c == 'U' {
			n = 8
		}
		if p.i+n > len(p.s) {
			return p.errf("short unicode escape")
		}
		r, err := strconv.ParseUint(p.s[p.i:p.i+n], 16, 32)
		if err != nil {
			return p.errf("invalid unicode escape")
		}
		b.WriteRune(rune(r))
		p.i += n
	case ' ', '\t', '\r', '\n':
		if !multiline {
			return p.errf("invalid escape \\%c", c)
		}
		// Line-ending backslash: trim all whitespace up to the next
		// non-whitespace character.
		p.i--
		for !p.eof() && strings.IndexByte(" \t\r\n", p.s[p.i]) >= 0 {
			p.i++
		}
	default:
		return p.errf("invalid escape \\%c (use single quotes for regexes)", c)
	}
	return nil
}
