// Package detect runs compiled rules over text fragments and produces findings.
package detect

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"math"
	"net/url"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/AISolutionLabs/secret-scanner/internal/config"
	"github.com/AISolutionLabs/secret-scanner/internal/remediate"
	"github.com/AISolutionLabs/secret-scanner/internal/wordy"
)

// Fragment is a unit of text to scan, with its origin.
type Fragment struct {
	Raw       string
	FilePath  string
	StartLine int // 1-based line number of the first line of Raw
	Commit    string
	Author    string
	Email     string
	Date      string
	Message   string
}

// Finding is one detected secret.
type Finding struct {
	RuleID       string   `json:"RuleID"`
	Description  string   `json:"Description"`
	Severity     string   `json:"Severity"`
	Tags         []string `json:"Tags"`
	File         string   `json:"File"`
	StartLine    int      `json:"StartLine"`
	EndLine      int      `json:"EndLine"`
	StartColumn  int      `json:"StartColumn"`
	EndColumn    int      `json:"EndColumn"`
	Match        string   `json:"Match"`
	Secret       string   `json:"Secret"`
	Line         string   `json:"Line,omitempty"`
	Entropy      float64  `json:"Entropy"`
	Decoded      string   `json:"Decoded,omitempty"` // encoding chain, e.g. "base64"
	Commit       string   `json:"Commit,omitempty"`
	Author       string   `json:"Author,omitempty"`
	Email        string   `json:"Email,omitempty"`
	Date         string   `json:"Date,omitempty"`
	Message      string   `json:"Message,omitempty"`
	Fingerprint  string   `json:"Fingerprint"`
	SecretHash   string   `json:"SecretHash"` // sha256 of the raw secret; stable across redaction
	Verification string   `json:"Verification,omitempty"`
	// Remediation is filled in after detection (rotation, keyless
	// alternative, replacement expression); see package remediate.
	Remediation *remediate.Guidance `json:"Remediation,omitempty"`

	sStart, sEnd int  // secret span in the fragment (for overlap checks)
	generic      bool // produced by a generic rule
}

// Options tune detection.
type Options struct {
	MaxDecodeDepth int      // 0 disables base64/hex/percent decoding
	IgnoreMarkers  []string // inline markers that suppress a finding on that line
	NoNoiseFilters bool     // audit mode: disable heuristic false-positive filters
}

// DefaultIgnoreMarkers are recognized inline suppressions from common tools.
var DefaultIgnoreMarkers = []string{
	"secretscan:allow", "gitleaks:allow", "pragma: allowlist secret", "trufflehog:ignore", "nosecret", "noqa: secret",
}

const nextLineMarker = "secretscan:allow-next-line"

// Detector applies a ruleset.
type Detector struct {
	rs       *config.Ruleset
	opts     Options
	ac       *matcher
	ruleKeys [][]int // per rule (by index in rs.Rules): keyword indices in ac
}

// New creates a detector.
func New(rs *config.Ruleset, opts Options) *Detector {
	if opts.IgnoreMarkers == nil {
		opts.IgnoreMarkers = DefaultIgnoreMarkers
	}
	for i, m := range opts.IgnoreMarkers {
		opts.IgnoreMarkers[i] = strings.ToLower(m)
	}
	d := &Detector{rs: rs, opts: opts, ruleKeys: make([][]int, len(rs.Rules))}
	idx := map[string]int{}
	var keys []string
	for i, r := range rs.Rules {
		for _, k := range r.LowerKeys {
			ki, ok := idx[k]
			if !ok {
				ki = len(keys)
				idx[k] = ki
				keys = append(keys, k)
			}
			d.ruleKeys[i] = append(d.ruleKeys[i], ki)
		}
	}
	d.ac = newMatcher(keys)
	return d
}

// Ruleset returns the compiled rules.
func (d *Detector) Ruleset() *config.Ruleset { return d.rs }

// SkipPath reports whether a path is globally allowlisted, so sources can
// avoid reading it at all.
func (d *Detector) SkipPath(path string) bool {
	path = filepath.ToSlash(path)
	for _, a := range d.rs.Allowlists {
		if a.PathAllowed(path) {
			return true
		}
	}
	return false
}

type hit struct {
	rule          *config.CompiledRule
	mStart, mEnd  int
	sStart, sEnd  int
	match, secret string
	entropy       float64
}

// Detect scans one fragment.
func (d *Detector) Detect(f Fragment) []Finding {
	f.FilePath = filepath.ToSlash(f.FilePath)
	if f.StartLine < 1 {
		f.StartLine = 1
	}
	if d.SkipPath(f.FilePath) {
		return nil
	}
	var out []Finding

	// File-name rules.
	for _, rule := range d.rs.Rules {
		if rule.Re == nil && rule.PathRe != nil && rule.PathRe.MatchString(f.FilePath) {
			fd := d.newFinding(rule, f, hit{rule: rule}, 0, 0, "")
			if !d.allowed(rule, f, "", "", "") {
				out = append(out, fd)
			}
		}
	}

	lower := asciiLower(f.Raw)
	for _, h := range d.hits(f.Raw, lower, f.FilePath) {
		line := lineText(f.Raw, h.sStart)
		if d.inlineIgnored(f.Raw, h.sStart, h.sEnd) || d.allowed(h.rule, f, h.secret, h.match, line) {
			continue
		}
		out = append(out, d.newFinding(h.rule, f, h, h.sStart, h.sEnd, ""))
	}

	if d.opts.MaxDecodeDepth > 0 {
		d.decodePass(f, f.Raw, 1, "", -1, -1, &out)
	}
	return dedupe(out)
}

// hits runs every applicable rule. Rules with keywords only run their regex
// over line windows around keyword occurrences, which keeps throughput high
// with Go's linear-time (but DFA-less) regexp engine.
func (d *Detector) hits(text, lower, path string) []hit {
	var hs []hit
	occ := d.ac.find(lower) // all keyword occurrences in one pass
	dropInBlobs(text, occ)
	for ri, rule := range d.rs.Rules {
		if rule.Re == nil {
			continue
		}
		if rule.PathRe != nil && !rule.PathRe.MatchString(path) {
			continue
		}
		windows := [][2]int{{0, len(text)}}
		if len(rule.LowerKeys) > 0 {
			windows = keywordWindows(lower, d.ruleKeys[ri], d.ac.lens, rule, occ)
			if len(windows) == 0 {
				continue
			}
		}
		for _, w := range windows {
			sub := text[w[0]:w[1]]
			for _, m := range rule.Re.FindAllStringSubmatchIndex(sub, -1) {
				if rule.Bounded {
					a, b := w[0]+m[0], w[0]+m[1]
					if (a > 0 && config.IsTokenChar(text[a-1])) || (b < len(text) && config.IsTokenChar(text[b])) {
						continue
					}
				}
				s, e := secretSpan(rule, m)
				if s < 0 || e <= s {
					continue
				}
				secret := sub[s:e]
				quoted := s > 0 && isQuote(sub[s-1])
				filters := !d.opts.NoNoiseFilters
				if filters && rule.Generic && rule.Entropy > 0 && (looksLikeIdentifier(secret, quoted) || genericNoise(secret, quoted, path)) {
					continue // code reference, words, path, UUID, kwargs...
				}
				ent := Shannon(secret)
				if rule.Entropy > 0 && ent < entropyFloor(rule, secret) {
					continue
				}
				if filters && (isKnownPublic(secret) || (rule.Generic && isSequential(secret))) {
					continue
				}
				if filters && rule.ID == "password-assignment" && weakPasswordNoise(secret) {
					continue
				}
				hs = append(hs, hit{rule: rule, mStart: w[0] + m[0], mEnd: w[0] + m[1], sStart: w[0] + s, sEnd: w[0] + e,
					match: strings.TrimSpace(sub[m[0]:m[1]]), secret: secret, entropy: ent})
			}
		}
	}
	return hs
}

const multilineSpan = 16 << 10

// blobMin is the length of an unbroken base64 run (embedded wasm, fonts,
// images) beyond which keyword hits inside it are treated as chance.
const blobMin = 64 << 10

// dropInBlobs removes keyword occurrences that fall inside huge base64
// blobs; random data contains short keywords like "sk" thousands of times.
func dropInBlobs(text string, occ [][]int) {
	if len(text) < blobMin {
		return
	}
	var blobs [][2]int
	scanRuns(text, isB64, blobMin, func(a, b int) { blobs = append(blobs, [2]int{a, b}) })
	if len(blobs) == 0 {
		return
	}
	for k, offs := range occ {
		kept := offs[:0]
		for _, o := range offs {
			in := false
			for _, bl := range blobs {
				if o >= bl[0] && o < bl[1] {
					in = true
					break
				}
			}
			if !in {
				kept = append(kept, o)
			}
		}
		occ[k] = kept
	}
}

// keywordWindows returns merged, line-aligned [start,end) windows covering
// each keyword occurrence plus one line of context on either side (or up to
// 16 KiB after it for multi-line rules such as private keys).
func keywordWindows(lower string, keys []int, lens []int, rule *config.CompiledRule, occ [][]int) [][2]int {
	multiline, windowBefore, windowAfter := rule.Multiline, rule.Before, rule.After
	if windowBefore == 0 {
		windowBefore, windowAfter = 256, 2048
	}
	var ws [][2]int
	for _, ki := range keys {
		offs := occ[ki]
		for _, o := range offs {
			// One line of context either side, but never more than a fixed
			// radius: minified files can have multi-megabyte single lines.
			lo := max(0, o-windowBefore) // bounded search keeps this linear
			s := o
			if j := strings.LastIndexByte(lower[lo:o], '\n'); j >= 0 { // start of keyword line - 1
				s = lo + j
				if k := strings.LastIndexByte(lower[lo:s], '\n'); k >= 0 { // previous line
					s = lo + k + 1
				} else {
					s = lo
				}
			} else {
				s = lo
			}
			end := o + lens[ki]
			limit := min(len(lower), end+windowAfter)
			if multiline {
				end = min(len(lower), o+multilineSpan)
				limit = end
			}
			e := end
			for n := 0; n < 2 && e < limit; n++ { // finish this line and the next
				j := strings.IndexByte(lower[e:limit], '\n')
				if j < 0 {
					e = limit
					break
				}
				e += j + 1
			}
			e = min(max(e, end), limit)
			ws = append(ws, [2]int{s, e})
		}
	}
	if len(ws) <= 1 {
		return ws
	}
	sort.Slice(ws, func(i, j int) bool { return ws[i][0] < ws[j][0] })
	merged := ws[:1]
	for _, w := range ws[1:] {
		last := &merged[len(merged)-1]
		if w[0] <= last[1] {
			last[1] = max(last[1], w[1])
		} else {
			merged = append(merged, w)
		}
	}
	return merged
}

var envishPath = regexp.MustCompile(`(?i)(?:^|/)(?:\.env(?:\.[\w-]+)?|[\w.-]*\.env|[\w.-]*(?:dockerfile|containerfile)[\w.-]*)$|\.(?:ya?ml|properties|ini|conf|cfg|toml|sh|bash|zsh|ps1|tfvars|hcl|config|xml)$`)

const pwSymbols = "!@#%^&*+~?$"

// genericNoise applies structural filters (after gitleaks, detect-secrets
// and trufflehog) to values caught by entropy-gated generic rules.
func genericNoise(secret string, quoted bool, path string) bool {
	core := strings.TrimRight(secret, "=")
	if strings.Contains(core, "=") {
		return true // kwargs / config pairs: func=submit_row, Region=eu-west-1
	}
	if isUUID(secret) {
		return true // identifiers far more often than credentials
	}
	if numLiteral.MatchString(secret) || dateLike.MatchString(secret) || strings.Contains(secret, "...") || segmentsAreWords(secret) {
		return true // numbers, timestamps, truncated doc examples, oauth-2025-04-20
	}
	hasDigit := strings.IndexFunc(secret, unicode.IsDigit) >= 0
	if !hasDigit && isSingleCaseLetters(secret) {
		return true // nextkeyfrompreviousresponse, SOMECONSTANT (gitleaks rejects all letter-only values)
	}
	w := wordy.Wordiness(secret)
	if w >= 0.6 {
		return true // made of words: SecurityProfiles, key-2024-primary
	}
	if !hasDigit && (strings.ContainsAny(secret, "./_-") || w >= 0.35) {
		return true // digit-free dotted names and paths: esnext.map.group-by
	}
	if strings.ContainsAny(secret, pwSymbols) && !quoted && !envishPath.MatchString(path) {
		return true // operators in code: a*b+c; symbols only count in literals/env files
	}
	return false
}

func isKnownPublic(secret string) bool {
	sum := sha256.Sum256([]byte(secret))
	return knownPublic[hex.EncodeToString(sum[:])]
}

// isSequential flags keyboard/alphabet runs like 0123456789 or abcdefgh,
// directly or after base64-decoding (detect-secrets' sequential filter).
func isSequential(secret string) bool {
	check := func(s string) bool {
		s = strings.ToLower(s)
		run := 1
		for i := 1; i < len(s); i++ {
			if s[i] == s[i-1]+1 {
				run++
				if run >= 8 {
					return true
				}
			} else {
				run = 1
			}
		}
		return false
	}
	if len(secret) < 8 {
		return false
	}
	if check(secret) {
		return true
	}
	if len(secret) >= 8 && len(secret)%4 == 0 {
		if b, err := base64.StdEncoding.DecodeString(secret); err == nil && printable(string(b)) {
			d := string(b)
			// Encoded prose or JSON ("a secret", {"foo": "bar"}) is test data.
			return check(d) || Shannon(d) < 3.0 || strings.ContainsAny(d, " {}") || wordy.Wordiness(d) >= 0.6
		}
	}
	if strings.Count(secret, "%") >= 2 {
		if d, err := url.QueryUnescape(secret); err == nil && d != secret {
			return utf8.RuneCountInString(d) < 10 || Shannon(d) < 3.0
		}
	}
	return false
}

var (
	dateLike   = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}(?:[T ][\d:.]+(?:Z|[+-]\d{2}:?\d{2})?)?$`)
	numLiteral = regexp.MustCompile(`^-?(?:0[xX][0-9a-fA-F]+|0[oO]?[0-7]+|0[bB][01]+|\d+(?:\.\d+)?(?:[eE][+-]?\d+)?)$`)
)

// segmentsAreWords reports values like "oauth-2025-04-20" or "v2-beta":
// separator-delimited parts that are each numbers or dictionary-like words.
func segmentsAreWords(s string) bool {
	parts := strings.FieldsFunc(s, func(r rune) bool { return r == '-' || r == '_' || r == '.' })
	if len(parts) < 2 {
		return false
	}
	for _, p := range parts {
		digits, letters := 0, 0
		for i := 0; i < len(p); i++ {
			switch c := p[i]; {
			case c >= '0' && c <= '9':
				digits++
			case c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z':
				letters++
			}
		}
		switch {
		case digits == len(p):
		case letters == len(p) && (len(p) <= 3 || wordy.Score(p) > wordy.Threshold):
		default:
			return false
		}
	}
	return true
}

// weakPasswordNoise drops "passwords" that are really labels, error codes
// or timestamps; leet-speak and mixed values (hunter2, s00pers3cret) stay.
func weakPasswordNoise(v string) bool {
	if dateLike.MatchString(v) || numLiteral.MatchString(v) || strings.Contains(v, "...") {
		return true
	}
	hasDigit := strings.IndexFunc(v, unicode.IsDigit) >= 0
	if !hasDigit && (strings.ContainsAny(v, "-_.") || wordy.Wordiness(v) >= 0.6) {
		return true // invalid-password, INVALID_PASSWORD, mynewpassword
	}
	return segmentsAreWords(v)
}

func isUUID(s string) bool {
	if len(s) != 36 {
		return false
	}
	for i := 0; i < 36; i++ {
		c := s[i]
		if i == 8 || i == 13 || i == 18 || i == 23 {
			if c != '-' {
				return false
			}
		} else if !isHexByte(c) {
			return false
		}
	}
	return true
}

// entropyFloor lowers the entropy gate for generic rules when the value's
// alphabet is small (hex) or clearly mixed (3+ character classes), as
// detect-secrets does with per-charset limits.
func entropyFloor(rule *config.CompiledRule, secret string) float64 {
	if !rule.Generic {
		return rule.Entropy
	}
	if isAllHex(secret) || charClasses(secret) >= 3 {
		return min(rule.Entropy, 3.0)
	}
	return rule.Entropy
}

func isSingleCaseLetters(s string) bool {
	var lo, up bool
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z':
			lo = true
		case c >= 'A' && c <= 'Z':
			up = true
		default:
			return false
		}
	}
	return lo != up
}

func charClasses(s string) int {
	var lo, up, dg, sy bool
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z':
			lo = true
		case c >= 'A' && c <= 'Z':
			up = true
		case c >= '0' && c <= '9':
			dg = true
		default:
			sy = true
		}
	}
	n := 0
	for _, b := range []bool{lo, up, dg, sy} {
		if b {
			n++
		}
	}
	return n
}

func isQuote(c byte) bool { return c == '"' || c == '\'' || c == '`' }

// looksLikeIdentifier reports whether s reads like a code identifier or a
// dotted member path made of real words (KeyUsageCRLSign, crypto.SHA256,
// C.GO_RSA_PKCS1_OAEP_PADDING) rather than random token characters, whose
// case and digit changes produce mostly 1-2 character "words".
//
// Quoted values must look even more like prose identifiers (at least three
// words, none of them short) to be skipped.
func looksLikeIdentifier(s string, quoted bool) bool {
	if s == "" || !(s[0] == '_' || s[0] >= 'A' && s[0] <= 'Z' || s[0] >= 'a' && s[0] <= 'z') {
		return false
	}
	var words []string
	start := 0
	class := func(c byte) int {
		switch {
		case c >= 'a' && c <= 'z':
			return 1
		case c >= 'A' && c <= 'Z':
			return 2
		case c >= '0' && c <= '9':
			return 3
		case c == '_' || c == '.':
			return 0
		}
		return -1
	}
	for i := 0; i < len(s); i++ {
		if class(s[i]) < 0 {
			return false
		}
	}
	flush := func(end int) {
		if end > start {
			words = append(words, s[start:end])
		}
	}
	for i := 1; i <= len(s); i++ {
		if i == len(s) {
			flush(i)
			break
		}
		a, b := class(s[i-1]), class(s[i])
		switch {
		case b == 0:
			flush(i)
			start = i + 1
		case a == 0:
			start = i
		case a == 1 && b == 2, a == 3 && b != 3, a != 3 && b == 3:
			flush(i)
			start = i
		case a == 2 && b == 1 && i-1 > start: // "CRLSign" -> "CRL", "Sign"
			flush(i - 1)
			start = i - 1
		}
	}
	if len(words) == 0 {
		return false
	}
	short := 0
	for _, w := range words {
		if len(w) < 3 && class(w[0]) != 3 {
			short++
		}
	}
	if quoted {
		return short == 0 && len(words) >= 3
	}
	return short*3 <= len(words)
}

// asciiLower lowercases ASCII letters only, preserving byte offsets.
func asciiLower(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			b[i] = c + 32
		}
	}
	return string(b)
}

func secretSpan(rule *config.CompiledRule, m []int) (int, int) {
	if g := rule.SecretGroup; g > 0 {
		return m[2*g], m[2*g+1]
	}
	for g := 1; g <= rule.NumGroups(); g++ {
		if m[2*g] >= 0 && m[2*g+1] > m[2*g] {
			return m[2*g], m[2*g+1]
		}
	}
	return m[0], m[1]
}

func (d *Detector) allowed(rule *config.CompiledRule, f Fragment, secret, match, line string) bool {
	for _, a := range rule.Allowlists {
		if a.Allowed(f.FilePath, f.Commit, secret, match, line) {
			return true
		}
	}
	for _, a := range d.rs.Allowlists {
		if len(a.TargetRules) > 0 && !a.TargetRules[rule.ID] {
			continue
		}
		if secret == "" && len(a.Paths) == 0 && len(a.Commits) == 0 {
			continue // secret-only allowlists don't apply to file-name findings
		}
		if a.Allowed(f.FilePath, f.Commit, secret, match, line) {
			return true
		}
	}
	return false
}

// inlineIgnored checks the lines spanned by the secret (and the line before,
// for the allow-next-line marker).
func (d *Detector) inlineIgnored(text string, s, e int) bool {
	ls, le := lineBounds(text, s, e, 512)
	span := strings.ToLower(text[ls:le])
	for _, m := range d.opts.IgnoreMarkers {
		if strings.Contains(span, m) {
			return true
		}
	}
	if ls > 0 {
		pls := strings.LastIndexByte(text[:ls-1], '\n') + 1
		if strings.Contains(strings.ToLower(text[pls:ls-1]), nextLineMarker) {
			return true
		}
	}
	return false
}

func lineText(text string, off int) string {
	ls, le := lineBounds(text, off, off, 1024)
	return strings.TrimRight(text[ls:le], "\r")
}

// lineBounds returns the line around [s,e), clipped to radius bytes on each
// side so minified multi-megabyte lines stay cheap.
func lineBounds(text string, s, e, radius int) (int, int) {
	lo := max(0, s-radius)
	ls := lo
	if j := strings.LastIndexByte(text[lo:s], '\n'); j >= 0 {
		ls = lo + j + 1
	}
	hi := min(len(text), e+radius)
	le := hi
	if j := strings.IndexByte(text[e:hi], '\n'); j >= 0 {
		le = e + j
	}
	return ls, le
}

func (d *Detector) newFinding(rule *config.CompiledRule, f Fragment, h hit, s, e int, decoded string) Finding {
	fd := Finding{
		RuleID: rule.ID, Description: rule.Description, Severity: rule.Severity, Tags: rule.Tags,
		File: f.FilePath, Match: h.match, Secret: h.secret, Entropy: round2(h.entropy), Decoded: decoded,
		Commit: f.Commit, Author: f.Author, Email: f.Email, Date: f.Date, Message: f.Message,
		sStart: s, sEnd: e, generic: rule.Generic,
	}
	if rule.Re != nil {
		fd.StartLine, fd.StartColumn = position(f.Raw, s, f.StartLine)
		fd.EndLine, fd.EndColumn = position(f.Raw, e, f.StartLine)
		fd.Line = truncate(lineText(f.Raw, s), 300)
	}
	if fd.Secret != "" {
		sum := sha256.Sum256([]byte(fd.Secret))
		fd.SecretHash = hex.EncodeToString(sum[:])
	}
	fd.Fingerprint = Fingerprint(fd)
	return fd
}

// Fingerprint is gitleaks-compatible: [commit:]file:rule:line.
func Fingerprint(f Finding) string {
	fp := fmt.Sprintf("%s:%s:%d", f.File, f.RuleID, f.StartLine)
	if f.Commit != "" {
		fp = f.Commit + ":" + fp
	}
	return fp
}

func position(text string, off, startLine int) (line, col int) {
	if off > len(text) {
		off = len(text)
	}
	line = startLine + strings.Count(text[:off], "\n")
	ls := strings.LastIndexByte(text[:off], '\n') + 1
	col = utf8.RuneCountInString(text[ls:off]) + 1
	return
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

func round2(f float64) float64 { return math.Round(f*100) / 100 }

// Shannon returns the Shannon entropy (bits per character) of s.
func Shannon(s string) float64 {
	if s == "" {
		return 0
	}
	counts := map[rune]int{}
	n := 0
	for _, r := range s {
		counts[r]++
		n++
	}
	var h float64
	for _, c := range counts {
		p := float64(c) / float64(n)
		h -= p * math.Log2(p)
	}
	return h
}

// ---------------------------------------------------------------------------
// Decoding

var ()

const maxSegments = 2000

func (d *Detector) decodePass(f Fragment, text string, depth int, chain string, os, oe int, out *[]Finding) {
	type seg struct {
		s, e int
		val  string
		enc  string
	}
	var segs []seg
	n := 0
	scanRuns(text, isB64, 24, func(a, b int) {
		if n >= maxSegments {
			return
		}
		for k := 0; k < 2 && b < len(text) && text[b] == '='; k++ {
			b++ // include base64 padding
		}
		raw := text[a:b]
		if v, ok := decodeB64(raw); ok {
			segs = append(segs, seg{a, b, v, "base64"})
			n++
		}
		if isAllHex(raw) && len(raw) >= 32 && len(raw)%2 == 0 {
			if bs, err := hex.DecodeString(raw); err == nil && printable(string(bs)) {
				segs = append(segs, seg{a, b, string(bs), "hex"})
				n++
			}
		}
	})
	if strings.Count(text, "%") >= 3 {
		scanRuns(text, isPctChar, 9, func(a, b int) {
			raw := text[a:b]
			if countEscapes(raw) < 3 {
				return
			}
			if v, err := url.PathUnescape(raw); err == nil && printable(v) {
				segs = append(segs, seg{a, b, v, "percent"})
			}
		})
	}
	for _, sg := range segs {
		s, e := os, oe
		if depth == 1 {
			s, e = sg.s, sg.e
		}
		enc := sg.enc
		if chain != "" {
			enc = chain + "," + sg.enc
		}
		lower := asciiLower(sg.val)
		line := lineText(f.Raw, s)
		for _, h := range d.hits(sg.val, lower, f.FilePath) {
			if d.inlineIgnored(f.Raw, s, e) || d.allowed(h.rule, f, h.secret, h.match, line) {
				continue
			}
			*out = append(*out, d.newFinding(h.rule, f, h, s, e, enc))
		}
		if depth < d.opts.MaxDecodeDepth {
			d.decodePass(f, sg.val, depth+1, enc, s, e, out)
		}
	}
}

func isB64(c byte) bool {
	return c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '+' || c == '/' || c == '_' || c == '-'
}

func isPctChar(c byte) bool {
	return c == '%' || c == '.' || c == '~' || c == '_' || c == '-' || c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9'
}

func isHexByte(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F'
}

func countEscapes(s string) int {
	n := 0
	for i := 0; i+2 < len(s); i++ {
		if s[i] == '%' && isHexByte(s[i+1]) && isHexByte(s[i+2]) {
			n++
		}
	}
	return n
}

func isAllHex(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F') {
			return false
		}
	}
	return true
}

// scanRuns calls fn for each maximal run of bytes satisfying ok with at
// least minLen bytes. It replaces a regex scan, which is far slower in Go.
func scanRuns(text string, ok func(byte) bool, minLen int, fn func(start, end int)) {
	for i := 0; i < len(text); {
		if !ok(text[i]) {
			i++
			continue
		}
		j := i
		for j < len(text) && ok(text[j]) {
			j++
		}
		if j-i >= minLen {
			fn(i, j)
		}
		i = j
	}
}

func decodeB64(s string) (string, bool) {
	trimmed := strings.TrimRight(s, "=")
	encs := []*base64.Encoding{base64.RawStdEncoding, base64.RawURLEncoding}
	for _, enc := range encs {
		b, err := enc.DecodeString(trimmed)
		if err != nil || len(b) < 12 {
			continue
		}
		if v := string(b); printable(v) {
			return v, true
		}
	}
	return "", false
}

// printable requires valid UTF-8 that is overwhelmingly printable text.
func printable(s string) bool {
	if !utf8.ValidString(s) || s == "" {
		return false
	}
	good, total := 0, 0
	for _, r := range s {
		total++
		if unicode.IsPrint(r) || r == '\n' || r == '\r' || r == '\t' {
			good++
		}
	}
	return float64(good)/float64(total) >= 0.95
}

// ---------------------------------------------------------------------------
// Post-processing

func dedupe(in []Finding) []Finding {
	if len(in) < 2 {
		return in
	}
	type key struct {
		rule   string
		s, e   int
		secret string
	}
	seen := map[key]bool{}
	specificSecrets := map[string]bool{}
	var specific []Finding
	for _, f := range in {
		if !f.generic {
			specific = append(specific, f)
			specificSecrets[f.Secret] = true
		}
	}
	var out []Finding
	for _, f := range in {
		k := key{f.RuleID, f.sStart, f.sEnd, f.Secret}
		if seen[k] {
			continue
		}
		if f.generic {
			if specificSecrets[f.Secret] || overlapsAny(f, specific) {
				continue
			}
			sub := false
			for s := range specificSecrets {
				if s != "" && (strings.Contains(f.Secret, s) || strings.Contains(s, f.Secret)) {
					sub = true
					break
				}
			}
			if sub {
				continue
			}
		}
		seen[k] = true
		out = append(out, f)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].StartLine != out[j].StartLine {
			return out[i].StartLine < out[j].StartLine
		}
		return out[i].StartColumn < out[j].StartColumn
	})
	return out
}

func overlapsAny(f Finding, others []Finding) bool {
	for _, o := range others {
		if o.Decoded == "" && f.Decoded == "" && f.sStart < o.sEnd && o.sStart < f.sEnd {
			return true
		}
	}
	return false
}

// Redact masks the secret in a finding. pct is the percentage hidden
// (100 = fully redacted).
func Redact(f *Finding, pct int) {
	if pct <= 0 || f.Secret == "" {
		return
	}
	if pct > 100 {
		pct = 100
	}
	runes := []rune(f.Secret)
	keep := len(runes) * (100 - pct) / 100
	masked := string(runes[:keep]) + "REDACTED"
	f.Match = strings.ReplaceAll(f.Match, f.Secret, masked)
	f.Line = strings.ReplaceAll(f.Line, f.Secret, masked)
	if strings.Contains(f.Secret, "\n") || f.Line != "" && f.Decoded != "" {
		f.Line = ""
	}
	if f.Decoded != "" {
		f.Match = masked
	}
	f.Secret = masked
}
