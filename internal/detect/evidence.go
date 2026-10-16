// SPDX-License-Identifier: Apache-2.0

package detect

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/AISolutionLabs/secret-scanner/internal/config"
)

// Confidence levels. A finding's confidence comes from independent pieces of
// evidence; no single signal (in particular entropy) is enough on its own.
const (
	High   = "high"   // block: provider-specific format, or several independent signals
	Medium = "medium" // probably a secret; blocks under balanced too
	Low    = "low"    // weak evidence, or a generic value in a test/example file: review under balanced
)

// FixtureCap is the evidence line of a generic value capped at low because
// it sits in a test/example file.
const FixtureCap = "capped at low: unstructured value in a test/example file"

// BlocksFinding applies the policy to a finding. testFixtures "block" (the
// CLI default) makes balanced also block generic values capped at low only for
// sitting in a test/example file; "review" lists them instead. Provider
// formats there are high confidence and always block.
func BlocksFinding(policy, testFixtures string, f Finding) bool {
	if Blocks(policy, f.Confidence) {
		return true
	}
	if testFixtures == "block" {
		for _, e := range f.Evidence {
			if e == FixtureCap {
				return true
			}
		}
	}
	return false
}

// Blocks reports whether a finding of this confidence blocks under a policy:
// strict blocks everything; balanced blocks medium and high and lists low
// (weak evidence, generic values in test/example files) for review. See
// bench/results for the measured trade-off.
func Blocks(policy, confidence string) bool {
	return policy != "balanced" || ConfidenceRank(confidence) >= ConfidenceRank(Medium)
}

// ConfidenceRank orders confidence levels; unknown values rank lowest.
func ConfidenceRank(c string) int {
	switch c {
	case High:
		return 2
	case Medium:
		return 1
	}
	return 0
}

// testPath matches test, fixture, example and doc locations. It only ever
// withholds a supporting signal from contextual rules; it never downgrades a
// provider-format (high-confidence) finding.
var testPath = regexp.MustCompile(`(?i)(?:^|/)(?:tests?|spec|specs|__tests__|testdata|test_data|fixtures?|examples?|samples?|mocks?|docs?)/|(?:_test\.go|\.test\.[cm]?[jt]sx?|\.spec\.[cm]?[jt]sx?|_spec\.rb|(?:^|/)test_[^/]*\.py|_test\.py)$|(?:^|[/_.-])(?:tests?|specs?|fixtures?|examples?|samples?|mocks?|fake|dummy)[_.-][^/]*$`)

// weakPassword matches dictionary-style passwords (pass123, admin2024,
// password1) that are equally likely to be real weak credentials or doc
// placeholders: reported, at reduced confidence.
var weakPassword = regexp.MustCompile(`(?i)^(?:pass(?:word|wd)?|admin(?:istrator)?|root|test|user|guest|secret|changeme|qwerty|letmein|welcome|demo|default|login|master|super(?:user)?)[_.!@#-]?\w{0,4}[!@#]?$`)

// IsTestPath reports whether path looks like test, fixture, example or doc content.
func IsTestPath(path string) bool { return testPath.MatchString(path) }

// contextual rules need surrounding evidence: generic and keyword-context
// rules, plus loosely structured credentials (URLs, connection strings,
// JWTs, sensitive file names).
func contextual(r *config.CompiledRule) bool {
	return r.Generic || r.Semi || r.HasTag("credentials") || r.HasTag("token") || r.HasTag("file")
}

// assess scores a candidate from independent signals.
func assess(r *config.CompiledRule, secret string, quoted bool, path string, ent float64) (string, []string) {
	if r.Re == nil { // file-name rule
		return Medium, []string{"file name matches a credential-file pattern"}
	}
	if !contextual(r) {
		return High, []string{"provider-specific format (" + r.ID + ")"}
	}
	var ev []string
	score := 0
	if !r.Generic {
		score++
		ev = append(ev, "structured credential shape ("+r.ID+")")
	}
	if r.Generic || r.Semi {
		score++
		ev = append(ev, "assigned to a credential-named key")
	}
	n := len(secret)
	if ent >= 4.0 || (isAllHex(secret) && n >= 32 && ent >= 3.2) || (n >= 40 && ent >= 3.5) {
		score++
		ev = append(ev, fmt.Sprintf("random-looking value (entropy %.1f)", ent))
	}
	if charClasses(secret) >= 3 || n >= 32 {
		score++
		ev = append(ev, "mixed character classes or long value")
	}
	if quoted || envishPath.MatchString(path) {
		score++
		ev = append(ev, "literal value in code or config")
	}
	if r.HasTag("credentials") && weakPassword.MatchString(secret) {
		score--
		ev = append(ev, "common weak or placeholder-like password (could be an example)")
	}
	if !IsTestPath(path) {
		score++
		ev = append(ev, "outside test/example paths")
	} else {
		ev = append(ev, "in a test/example path (no downgrade for provider formats)")
	}
	switch {
	case score >= 3 && IsTestPath(path):
		// A value without a provider-specific format in a test/example file
		// is most likely a fixture: low, so the balanced policy lists it for
		// review instead of blocking. (Provider formats returned High above
		// and are not affected.)
		return Low, append(ev, FixtureCap)
	case score >= 4:
		return High, ev
	case score == 3:
		return Medium, ev
	}
	return Low, ev
}

// Suppressed is a candidate that matched a rule but was filtered out. The
// ledger exists so nothing is ever dropped invisibly: counts are always
// reported and --show-suppressed lists every entry with its reason.
type Suppressed struct {
	RuleID     string `json:"RuleID"`
	File       string `json:"File"`
	StartLine  int    `json:"StartLine"`
	Commit     string `json:"Commit,omitempty"`
	Reason     string `json:"Reason"`
	Secret     string `json:"Secret"`
	SecretHash string `json:"SecretHash"`
}

// drop is an internal suppressed hit in text coordinates.
type drop struct {
	rule         *config.CompiledRule
	sStart, sEnd int
	secret       string
	reason       string
}

// Result is the outcome of scanning one fragment.
type Result struct {
	Findings   []Finding
	Suppressed []Suppressed   // only when Options.RecordSuppressed
	Counts     map[string]int // suppression reason -> count (always)
}

func reasonKey(reason string) string {
	if i := strings.Index(reason, ":"); i > 0 && strings.HasPrefix(reason, "allowlist") {
		return "allowlist"
	}
	return reason
}

// NoiseReason applies the same value filters used for generic rules to an
// arbitrary candidate (e.g. from another scanner's report) and returns why it
// is noise, or "". Callers must only use it for candidates that are not in a
// provider-specific format.
func NoiseReason(secret string, quoted bool, path string) string {
	if isKnownPublic(secret) {
		return "known-public-example"
	}
	if looksLikeIdentifier(secret, quoted) {
		return "identifier"
	}
	if why := genericNoise(secret, quoted, path); why != "" {
		return why
	}
	if isSequential(secret) {
		return "sequential-or-decoded-prose"
	}
	if Shannon(secret) < 2.5 {
		return "low-entropy"
	}
	return ""
}

var digestCtx = regexp.MustCompile(`(?i)(?:sha(?:1|224|256|384|512)[:=-]|md5[:=-]|/zipball/|/tarball/|/commit/|/blob/|/tree/|@sha256:|integrity["']?\s*[:=])$`)

// EmbeddedReason reports when secret is only a slice of a longer token in
// line (a digest, commit SHA or base64 payload), the class of false positive
// where a provider pattern matches inside unrelated data.
func EmbeddedReason(line, secret string) string {
	if secret == "" || line == "" {
		return ""
	}
	li, ls := strings.ToLower(line), strings.ToLower(secret)
	i := strings.Index(li, ls)
	if i < 0 {
		return ""
	}
	if digestCtx.MatchString(li[:i]) {
		return "digest-or-commit-hash"
	}
	alnum := func(c byte) bool { return c >= '0' && c <= '9' || c >= 'a' && c <= 'z' }
	if (i > 0 && alnum(li[i-1])) || (i+len(ls) < len(li) && alnum(li[i+len(ls)])) {
		return "embedded-in-longer-token"
	}
	return ""
}
