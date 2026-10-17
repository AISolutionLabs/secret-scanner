// SPDX-License-Identifier: Apache-2.0

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
	// Confidence (high/medium/low) and the independent evidence behind it.
	Confidence string   `json:"Confidence"`
	Evidence   []string `json:"Evidence,omitempty"`
	// Blocking is set by the policy: strict blocks every finding, balanced
	// blocks high and medium confidence and reports low for review.
	Blocking bool `json:"Blocking"`
	// Context is "local" (a local/development service: localhost, private
	// network, docker-compose, .env.test) or "example" (.env.example and
	// other templates). Such findings are capped at low confidence.
	Context string `json:"Context,omitempty"`
	// Source and Triage are set when re-scoring another scanner's report.
	Source string `json:"Source,omitempty"`
	Triage string `json:"Triage,omitempty"`

	sStart, sEnd int  // secret span in the fragment (for overlap checks)
	generic      bool // produced by a generic rule
}

// Options tune detection.
type Options struct {
	MaxDecodeDepth int      // 0 disables base64/hex/percent decoding
	IgnoreMarkers  []string // inline markers that suppress a finding on that line
	NoNoiseFilters bool     // audit mode: disable heuristic false-positive filters
	// RecordSuppressed keeps every filtered candidate (not just counts).
	RecordSuppressed bool
}

// DefaultIgnoreMarkers are recognized inline suppressions from common tools.
var DefaultIgnoreMarkers = []string{
	"secretscan:allow", "gitleaks:allow", "pragma: allowlist secret", "trufflehog:ignore", "nosecret", "noqa: secret",
}

const nextLineMarker = "secretscan:allow-next-line"

// YieldsTag marks non-generic rules that still give way to provider rules
// on the same span: an HTTP Bearer value that is also a JWT or a GitHub
// token is reported once, by the provider rule.
const YieldsTag = "http-auth"

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
	confidence    string
	evidence      []string
}

// Detect scans one fragment and returns its findings.
func (d *Detector) Detect(f Fragment) []Finding { return d.Scan(f).Findings }

// Scan scans one fragment, returning findings and the suppression ledger.
func (d *Detector) Scan(f Fragment) Result {
	f.FilePath = filepath.ToSlash(f.FilePath)
	if f.StartLine < 1 {
		f.StartLine = 1
	}
	res := Result{Counts: map[string]int{}}
	if d.SkipPath(f.FilePath) {
		return res
	}
	type pending struct {
		rule           *config.CompiledRule
		pos            int
		secret, reason string
	}
	var held []pending
	suppress := func(rule *config.CompiledRule, pos int, secret, reason string) {
		held = append(held, pending{rule, pos, secret, reason})
	}
	var out []Finding

	// File-name rules.
	for _, rule := range d.rs.Rules {
		if rule.Re == nil && rule.PathRe != nil && rule.PathRe.MatchString(f.FilePath) {
			conf, ev := assess(rule, "", false, f.FilePath, 0)
			fd := d.newFinding(rule, f, hit{rule: rule, confidence: conf, evidence: ev}, 0, 0, "")
			if why := d.allowed(rule, f, "", "", ""); why != "" {
				suppress(rule, 0, "", why)
				continue
			}
			out = append(out, fd)
		}
	}

	lower := asciiLower(f.Raw)
	hs, drops := d.hits(f.Raw, lower, f.FilePath)
	for _, dr := range drops {
		suppress(dr.rule, dr.sStart, dr.secret, dr.reason)
	}
	for _, h := range hs {
		line := lineText(f.Raw, h.sStart)
		if d.inlineIgnored(f.Raw, h.sStart, h.sEnd) {
			suppress(h.rule, h.sStart, h.secret, "inline-ignore")
			continue
		}
		if why := d.allowed(h.rule, f, h.secret, h.match, line); why != "" {
			suppress(h.rule, h.sStart, h.secret, why)
			continue
		}
		out = append(out, d.newFinding(h.rule, f, h, h.sStart, h.sEnd, ""))
	}

	if d.opts.MaxDecodeDepth > 0 {
		d.decodePass(f, f.Raw, 1, "", -1, -1, &out, suppress)
	}
	res.Findings = dedupe(out)

	// A candidate filtered by one rule but reported by another (e.g. the
	// generic rule drops a value that password-assignment reports) is not a
	// suppression: leave it out of the ledger.
	reported := map[string]bool{}
	for _, fd := range res.Findings {
		reported[fd.Secret] = true
	}
	for _, p := range held {
		if p.secret != "" && reported[p.secret] {
			continue
		}
		covered := false
		for sec := range reported {
			if p.secret != "" && sec != "" && strings.Contains(sec, p.secret) {
				covered = true
				break
			}
		}
		if covered {
			continue
		}
		res.Counts[reasonKey(p.reason)]++
		if !d.opts.RecordSuppressed {
			continue
		}
		line := f.StartLine
		if p.pos > 0 {
			line, _ = position(f.Raw, p.pos, f.StartLine)
		}
		sum := sha256.Sum256([]byte(p.secret))
		res.Suppressed = append(res.Suppressed, Suppressed{RuleID: p.rule.ID, File: f.FilePath, StartLine: line,
			Commit: f.Commit, Reason: p.reason, Secret: p.secret, SecretHash: hex.EncodeToString(sum[:])})
	}
	return res
}

// hits runs every applicable rule. Rules with keywords only run their regex
// over line windows around keyword occurrences, which keeps throughput high
// with Go's linear-time (but DFA-less) regexp engine.
func (d *Detector) hits(text, lower, path string) ([]hit, []drop) {
	var hs []hit
	var drops []drop
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
				dropIt := func(reason string) {
					drops = append(drops, drop{rule: rule, sStart: w[0] + s, sEnd: w[0] + e, secret: secret, reason: reason})
				}
				ent := Shannon(secret)
				if rule.Entropy > 0 && ent < entropyFloor(rule, secret) {
					continue // never qualified: not a suppression
				}
				var extra []string
				uuidCred := false
				if rule.Validate != "" {
					ok, why := validators[rule.Validate](secret)
					if !ok {
						continue // never qualified: not a suppression
					}
					extra = append(extra, why)
				}
				if filters && (rule.Generic || rule.HasTag("credentials")) {
					if why := credentialValueNoise(rule, sub[m[0]:s], secret); why != "" {
						dropIt(why)
						continue
					}
				}
				if filters && rule.Generic && rule.Entropy > 0 {
					if looksLikeIdentifier(secret, quoted || envishPath.MatchString(path)) {
						dropIt("identifier")
						continue
					}
					if echoesKeyName(sub[m[0]:s], secret) {
						dropIt("echoes-key-name")
						continue
					}
					if why := genericNoise(secret, quoted, path); why != "" {
						// A UUID under a credential-named key (access_token,
						// secretVal, const key) can be the credential; it is
						// kept at low confidence. Request/correlation-style
						// keys keep the filter.
						if why == "uuid" && credentialUUIDKey(text, w[0]+s) {
							uuidCred = true
						} else {
							dropIt(why)
							continue
						}
					}
				}
				if filters && isKnownPublic(secret) {
					dropIt("known-public-example")
					continue
				}
				if filters && rule.Generic && isSequential(secret) {
					dropIt("sequential-or-decoded-prose")
					continue
				}
				if filters && (rule.ID == "password-assignment" || rule.HasTag("password")) && weakPasswordNoise(secret) {
					dropIt("placeholder-password")
					continue
				}
				conf, ev := assess(rule, secret, quoted, path, ent, extra...)
				if uuidCred {
					conf, ev = Low, append(ev, UUIDCredentialEvidence)
				}
				hs = append(hs, hit{rule: rule, mStart: w[0] + m[0], mEnd: w[0] + m[1], sStart: w[0] + s, sEnd: w[0] + e,
					match: strings.TrimSpace(sub[m[0]:m[1]]), secret: secret, entropy: ent, confidence: conf, evidence: ev})
			}
		}
	}
	return hs, drops
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
// and trufflehog) to values caught by entropy-gated generic rules. It returns
// the reason a value is noise, or "".
func genericNoise(secret string, quoted bool, path string) string {
	core := strings.TrimRight(secret, "=")
	if strings.Contains(core, "=") {
		return "key=value-pair" // kwargs / config pairs: func=submit_row, Region=eu-west-1
	}
	if isUUID(secret) {
		return "uuid" // identifiers far more often than credentials
	}
	if numLiteral.MatchString(secret) || dateLike.MatchString(secret) {
		return "number-or-date"
	}
	if strings.Contains(secret, "...") {
		return "truncated-example"
	}
	if segmentsAreWords(secret) {
		return "word-segments" // oauth-2025-04-20, v2-beta
	}
	if testVectorName(secret) {
		return "test-vector-name" // PrivateKey=KAS-ECC-CDH_P-192_C8, PeerKey=ALICE_cf_sect193r1_PUB
	}
	if patternedHex(secret) {
		return "patterned-hex" // 000102030405...1f, 00112233...ff test patterns
	}
	hasDigit := strings.IndexFunc(secret, unicode.IsDigit) >= 0
	w := wordy.Wordiness(secret)
	if !hasDigit && isSingleCaseLetters(secret) && w >= 0.5 {
		return "single-case-letters" // nextkeyfrompreviousresponse, SOMECONSTANT
	}
	// Identifier-shaped values (clean camelCase / snake_case) need less
	// word evidence than arbitrary strings, whose mixed case and inner digits
	// make chance word runs more likely.
	clean := cleanIdentifier(secret)
	// Identifiers are mostly letters; short symbol-heavy passwords can look
	// "wordy" by chance because they contain few letters.
	if letterFraction(secret) >= 0.85 && ((clean && w >= 0.6) || (w >= 0.75 && digitFraction(secret) <= 0.2)) {
		return "word-like" // SecurityProfiles, accessTokenProvider
	}
	if camelWords(secret) {
		return "camel-case-identifier" // V1DownwardAPIProjection, IntegrationSummaries
	}
	if wordTokens(secret) {
		return "word-tokens" // headersToExcludeInCacheKey, keyboard/mouse, 0011_update_proxy_permissions
	}
	if concatExpr.MatchString(secret) {
		return "string-concatenation" // key="'+value1.key+'"
	}
	if emailAddress.MatchString(secret) {
		return "email-address"
	}
	if dottedNamespace(secret) {
		return "dotted-namespace" // es6.symbol, core-js.es7.map
	}
	if namedSegments(secret) {
		return "credential-name" // inf-vsqt-01-secret-id, my-app_api-key: names of secrets, not values
	}
	// Stopwords (gitleaks-style) only when the value is word-like overall:
	// "MySecretToken2024!" or "aSecretTokenValue9x7K" may be real credentials.
	if clean && w >= 0.6 && containsStopword(secret) {
		return "stopword"
	}
	// Digit-free names and paths: separators alone are not evidence (random
	// passwords contain - and _), so the value must also read as words.
	if !hasDigit && (w >= 0.75 || (clean && w >= 0.5) || (lettersAndSeps(secret) && w >= 0.5)) {
		return "digit-free-name-or-path" // esnext.map.group-by
	}
	if strings.ContainsAny(secret, pwSymbols) && !quoted && !envishPath.MatchString(path) {
		return "operator-in-code" // a*b+c; symbols only count in literals/env files
	}
	return ""
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
			// Encoded prose or JSON ("a secret", {"foo": "bar"}) is test data;
			// an encoded password ("ChickenDinner98") is not.
			return check(d) || Shannon(d) < 3.0 || strings.ContainsAny(d, " {}\"\n")
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
	words := 0
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
		case digits+letters == len(p) && len(p) <= 4 && digits > 0: // es6, v2, utf8, KRB5
		case letters == len(p) && len(p) >= 4 && wordy.Score(p) > wordy.Threshold:
			words++
		case letters == len(p) && len(p) <= 3:
		default:
			return false
		}
	}
	// At least one real word: random grouped keys (x7k2-9fj3-qq81, abc-xyz-qwe)
	// are made only of short or numeric groups.
	return words > 0
}

// camelWords reports type and field names: at least two capitalized,
// word-like runs of 4+ letters (plus short acronyms) covering 80% of the
// letters. Each run must also score as a word, so random mixed-case tokens
// (which contain capital+lowercase runs by chance) are not matched.
// camelSlack loosens the per-word threshold for longer capitalized words: the
// capitalization structure is itself evidence of an identifier. Checked in
// tests against 200k random tokens.
const camelSlack = 0.25

func camelWords(s string) bool {
	letters := 0
	for i := 0; i < len(s); i++ {
		if c := s[i]; c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' {
			letters++
		}
	}
	words, covered := 0, 0
	for _, w := range wordy.Tokens(s) {
		upper := w[0] >= 'A' && w[0] <= 'Z'
		rest := strings.ToLower(w[1:]) == w[1:]
		allCaps := strings.ToUpper(w) == w
		switch {
		case upper && rest && len(w) >= 4 && (wordy.Score(w) > wordy.Threshold || len(w) >= 6 && wordy.Score(w) > wordy.Threshold-camelSlack):
			words++
			covered += len(w)
		case allCaps && len(w) >= 2 && len(w) <= 4:
			covered += len(w) // API, HTTP, ID
		}
	}
	return letters > 0 && words >= 2 && float64(covered)/float64(letters) >= 0.85
}

var placeholderPrefix = regexp.MustCompile(`(?i)^(?:my|your|example|sample|some|test|dummy|fake)[_-]?`)

// echoesKeyName reports doc placeholders that repeat the key they are
// assigned to ("webhookKey": "my_webhookKey"). A random value containing its
// own 5+ character key name does not happen by chance.
func echoesKeyName(before, secret string) bool {
	rest := placeholderPrefix.ReplaceAllString(secret, "")
	if rest == secret || len(rest) < 5 {
		return false
	}
	return strings.Contains(strings.ToLower(before), strings.ToLower(rest))
}

// shortWords are common 2-3 letter tokens in identifiers. They count toward
// coverage but never as one of the (at least two) real words required.
var shortWords = map[string]bool{
	"my": true, "is": true, "to": true, "in": true, "of": true, "on": true, "by": true, "at": true, "as": true, "no": true,
	"id": true, "ids": true, "key": true, "api": true, "url": true, "uri": true, "get": true, "set": true, "for": true,
	"the": true, "and": true, "new": true, "old": true, "max": true, "min": true, "use": true, "via": true, "raw": true,
	"sha": true, "md": true, "b": true, "x": true, "app": true, "env": true, "org": true, "com": true, "net": true,
}

// concatExpr is a property access spliced into a string: '+obj.field+'.
var concatExpr = regexp.MustCompile(`^\+[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)+\+?$|^[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)+\+$`)

var emailAddress = regexp.MustCompile(`^[A-Za-z][\w.+-]*@[A-Za-z][\w-]*(?:\.[A-Za-z][\w-]*)+$`)

// wordTokens reports whether a value is made of words: split on case
// changes and non-letters, at least two tokens of 4+ letters score as words,
// and word or common short tokens cover 85% of the letters. Random strings
// split into short, unpronounceable fragments, so they fail coverage; the
// per-alphabet false-negative test pins this.
func wordTokens(s string) bool {
	if digitFraction(s) > 0.25 {
		return false
	}
	letters := 0
	for i := 0; i < len(s); i++ {
		if c := s[i]; c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' {
			letters++
		}
	}
	words, covered := 0, 0
	var toks []string
	// Only separators and case changes split words. A chunk with digits in
	// the middle (kq3update7xz) is not words, whatever its letters spell.
	for _, chunk := range strings.FieldsFunc(s, func(r rune) bool {
		return !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9')
	}) {
		core := strings.Trim(chunk, "0123456789")
		if strings.ContainsAny(core, "0123456789") {
			continue
		}
		toks = append(toks, wordy.Tokens(core)...)
	}
	seps := strings.ContainsAny(s, "_-./:#@ ")
	for _, w := range toks {
		lw := strings.ToLower(w)
		if !seps && len(w) > 4 && strings.ToUpper(w) == w {
			continue // a long all-caps run without separators is base32, not a word
		}
		switch {
		case len(w) >= 4 && len(w) <= 16 && (wordy.Score(lw) > wordy.Threshold || len(w) >= 5 && wordy.Score(lw) > wordy.Threshold-wordSlack):
			words++
			covered += len(w)
		case shortWords[lw]:
			covered += len(w)
		}
	}
	cov := float64(covered) / float64(letters)
	return letters >= 8 && (words >= 2 && cov >= 0.85 || words >= 1 && cov == 1 && len(toks) >= 3)
}

// wordSlack lets longer real words the bigram model scores low (proxy,
// webhook, keyboard) count; coverage still has to hold across the value.
const wordSlack = 0.75

// dottedNamespace matches lowercase module/feature paths (es6.symbol,
// web.dom-collections.iterator) with at most one digit per segment.
func dottedNamespace(s string) bool {
	if !strings.Contains(s, ".") || strings.ToLower(s) != s {
		return false
	}
	for _, seg := range strings.Split(s, ".") {
		if seg == "" || seg[0] < 'a' || seg[0] > 'z' {
			return false
		}
		digits := 0
		for i := 0; i < len(seg); i++ {
			c := seg[i]
			switch {
			case c >= '0' && c <= '9':
				digits++
			case c >= 'a' && c <= 'z', c == '-', c == '_':
			default:
				return false
			}
		}
		if digits > 1 {
			return false
		}
	}
	return true
}

var (
	envVarName = regexp.MustCompile(`^[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+$`)
	semverLike = regexp.MustCompile(`^[v^~>=<]*\d+\.\d+(?:\.\d+)?(?:[-+][\w.-]+)?$`)
	winPath    = regexp.MustCompile(`^[A-Za-z]:[\\/]`)
)

// weakPasswordNoise drops "passwords" that are really labels, error codes
// or timestamps; leet-speak and mixed values (hunter2, s00pers3cret) stay.
func weakPasswordNoise(v string) bool {
	if dateLike.MatchString(v) || numLiteral.MatchString(v) || strings.Contains(v, "...") || envVarName.MatchString(v) {
		return true // timestamps, numbers, truncated examples, ENV_VAR_NAMES
	}
	hasDigit := strings.IndexFunc(v, unicode.IsDigit) >= 0
	// Values with spaces are UI text or messages ("Must be at least 8
	// characters", "Glemt din adgangskode?") unless they carry a digit and
	// do not read as words; passphrases of random chunks stay.
	if sp := strings.Count(v, " "); sp > 2 || sp > 0 && (!hasDigit || wordy.Wordiness(v) >= 0.5 || wordTokens(v)) {
		return true
	}
	if strings.IndexFunc(v, func(r rune) bool { return r < 128 && (unicode.IsLetter(r) || unicode.IsDigit(r)) }) < 0 {
		return true // no ASCII letter or digit: a localized label ("パスワード：")
	}
	if strings.HasSuffix(v, ":") || semverLike.MatchString(v) || winPath.MatchString(v) {
		return true // "Clau:" labels, "1.0.0" versions, C:\ paths
	}
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

// cleanIdentifier reports camelCase / PascalCase / snake_case / kebab-case
// shapes: letters with digits only at the end of a segment, at most one
// all-caps run (acronym) and at most one 1-2 letter word.
func cleanIdentifier(s string) bool {
	for _, seg := range strings.FieldsFunc(s, func(r rune) bool { return r == '_' || r == '-' || r == '.' }) {
		trim := strings.TrimRight(seg, "0123456789")
		if trim == "" || strings.ContainsAny(trim, "0123456789") {
			return false
		}
		for i := 0; i < len(trim); i++ {
			c := trim[i]
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z') {
				return false
			}
		}
	}
	caps, short := 0, 0
	toks := wordy.Tokens(s)
	for i, t := range toks {
		if len(t) >= 2 && strings.ToUpper(t) == t {
			caps++
		}
		if len(t) <= 2 && i > 0 {
			short++
		}
	}
	return len(toks) >= 2 && caps <= 1 && short <= 1
}

var credSegment = map[string]bool{"secret": true, "secrets": true, "token": true, "key": true, "apikey": true,
	"password": true, "passwd": true, "pass": true, "credential": true, "credentials": true, "creds": true, "auth": true}

// namedSegments reports separator-delimited names with a whole segment that
// is a credential word ("-secret-", "_token", ".key"), e.g. a Vault key name.
func namedSegments(s string) bool {
	parts := strings.FieldsFunc(s, func(r rune) bool { return r == '-' || r == '_' || r == '.' || r == '/' })
	if len(parts) < 3 {
		return false
	}
	for _, p := range parts {
		if credSegment[strings.ToLower(p)] {
			return true
		}
	}
	return false
}

// lettersAndSeps reports names/paths: only letters and . / _ -, with at
// least one separator.
func lettersAndSeps(s string) bool {
	if !strings.ContainsAny(s, "./_-") {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c == '.' || c == '/' || c == '_' || c == '-') {
			return false
		}
	}
	return true
}

func containsStopword(s string) bool {
	ls := strings.ToLower(s)
	for _, w := range config.GenericStopwords {
		if strings.Contains(ls, w) {
			return true
		}
	}
	return false
}

func letterFraction(s string) float64 {
	if s == "" {
		return 0
	}
	n := 0
	for i := 0; i < len(s); i++ {
		if c := s[i]; c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' {
			n++
		}
	}
	return float64(n) / float64(len(s))
}

func digitFraction(s string) float64 {
	if s == "" {
		return 0
	}
	n := 0
	for i := 0; i < len(s); i++ {
		if s[i] >= '0' && s[i] <= '9' {
			n++
		}
	}
	return float64(n) / float64(len(s))
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
	// Hex with both letters and digits (acc993b3319ddf05...) is data, not a
	// name; digit-heavy identifiers (Ed25519Key, x509) contain non-hex letters.
	if isHexData(s) {
		return false
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
		// For literals the split alone is not evidence: random mixed-case
		// strings also split into 3+ letter runs, so most letters must form
		// real words. (Unquoted values in code are references, not secrets.)
		if wordy.Wordiness(s) < 0.6 {
			return false
		}
		return short == 0 && len(words) >= 3
	}
	return short*3 <= len(words)
}

func isHexData(s string) bool {
	if len(s) < 12 {
		return false
	}
	letters, digits := 0, 0
	for i := 0; i < len(s); i++ {
		switch c := s[i]; {
		case c >= '0' && c <= '9':
			digits++
		case c >= 'a' && c <= 'f', c >= 'A' && c <= 'F':
			letters++
		default:
			return false
		}
	}
	return letters > 0 && digits > 0
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

// allowed returns "allowlist: <description>" when an allowlist suppresses
// the candidate, else "". Global allowlists only apply to the rules they are
// scoped to (targetRules / targetTags).
func (d *Detector) allowed(rule *config.CompiledRule, f Fragment, secret, match, line string) string {
	for _, a := range rule.Allowlists {
		if a.Allowed(f.FilePath, f.Commit, secret, match, line) {
			return "allowlist: " + nonEmptyDesc(a.Description, rule.ID+" rule allowlist")
		}
	}
	for _, a := range d.rs.Allowlists {
		if !a.AppliesTo(rule) {
			continue
		}
		if secret == "" && len(a.Paths) == 0 && len(a.Commits) == 0 {
			continue // secret-only allowlists don't apply to file-name findings
		}
		if a.Allowed(f.FilePath, f.Commit, secret, match, line) {
			return "allowlist: " + nonEmptyDesc(a.Description, "global allowlist")
		}
	}
	return ""
}

func nonEmptyDesc(s, def string) string {
	if s == "" {
		return def
	}
	return s
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
		sStart: s, sEnd: e, generic: rule.Generic || rule.HasTag(YieldsTag),
		Confidence: h.confidence, Evidence: h.evidence,
	}
	if fd.Confidence == "" {
		fd.Confidence, fd.Evidence = assess(rule, h.secret, false, f.FilePath, h.entropy)
	}
	if decoded != "" {
		fd.Evidence = append(append([]string(nil), fd.Evidence...), "found after decoding ("+decoded+")")
	}
	if rule.Re != nil {
		fd.StartLine, fd.StartColumn = position(f.Raw, s, f.StartLine)
		fd.EndLine, fd.EndColumn = position(f.Raw, e, f.StartLine)
		fd.Line = truncate(lineText(f.Raw, s), 300)
	}
	if rule.Re != nil {
		ctx, why := findingContext(rule, f.FilePath, h.match, lineText(f.Raw, s))
		applyContext(&fd, ctx, why)
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

func (d *Detector) decodePass(f Fragment, text string, depth int, chain string, os, oe int, out *[]Finding,
	suppress func(rule *config.CompiledRule, pos int, secret, reason string)) {
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
		hs, drops := d.hits(sg.val, lower, f.FilePath)
		for _, dr := range drops {
			suppress(dr.rule, s, dr.secret, dr.reason)
		}
		for _, h := range hs {
			if d.inlineIgnored(f.Raw, s, e) {
				suppress(h.rule, s, h.secret, "inline-ignore")
				continue
			}
			if why := d.allowed(h.rule, f, h.secret, h.match, line); why != "" {
				suppress(h.rule, s, h.secret, why)
				continue
			}
			*out = append(*out, d.newFinding(h.rule, f, h, s, e, enc))
		}
		if depth < d.opts.MaxDecodeDepth {
			d.decodePass(f, sg.val, depth+1, enc, s, e, out, suppress)
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
