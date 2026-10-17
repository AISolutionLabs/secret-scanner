// SPDX-License-Identifier: Apache-2.0

// Package triage is a precision layer for other scanners: it re-scores
// findings from gitleaks, trufflehog or any SARIF producer using
// secretscan's context analysis and evidence model.
//
// Guarantees:
//   - verified findings are always kept as high confidence;
//   - a finding is only marked "filtered" with an explicit, named reason,
//     and filtered findings are still returned (never silently dropped);
//   - anything that cannot be evaluated (redacted secret, unreadable file,
//     no applicable evidence) is kept as "uncorroborated", not passed.
package triage

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/AISolutionLabs/secret-scanner/internal/detect"
)

// Statuses.
const (
	Confirmed      = "confirmed"      // secretscan independently reports the same secret
	Verified       = "verified"       // the source tool verified it live
	Filtered       = "filtered"       // positively identified as noise (reason given)
	Uncorroborated = "uncorroborated" // no evidence either way: kept for review
)

// Input is one foreign finding.
type Input struct {
	Tool, RuleID, File, Commit, Secret, Match, Line string
	StartLine, EndLine                              int
	Verified                                        bool
	Redacted                                        bool
	// Prefix is the visible part of a partially redacted secret
	// (gitleaks --redact=N gives "abc...", secretscan gives "abcREDACTED").
	Prefix string
}

// minPrefix is the shortest redaction prefix used for matching.
const minPrefix = 4

func redaction(s string) (redacted bool, prefix string) {
	switch {
	case s == "" || strings.Trim(s, "*") == "":
		return true, ""
	case strings.HasSuffix(s, "..."):
		return true, strings.TrimSuffix(s, "...")
	case strings.Contains(s, "REDACTED"):
		return true, s[:strings.Index(s, "REDACTED")]
	}
	return false, ""
}

func finish(in Input) Input {
	in.Redacted, in.Prefix = redaction(in.Secret)
	if len(in.Prefix) < minPrefix {
		in.Prefix = ""
	}
	return in
}

// Parse auto-detects gitleaks JSON, trufflehog JSON lines or SARIF.
func Parse(data []byte) (string, []Input, error) {
	trim := bytes.TrimSpace(data)
	if len(trim) == 0 {
		return "empty", nil, nil
	}
	if trim[0] == '[' {
		var gl []struct {
			RuleID, File, Commit, Secret, Match, Description string
			StartLine, EndLine                               int
		}
		if err := json.Unmarshal(trim, &gl); err != nil {
			return "", nil, fmt.Errorf("gitleaks report: %w", err)
		}
		var out []Input
		for _, f := range gl {
			out = append(out, finish(Input{Tool: "gitleaks", RuleID: f.RuleID, File: f.File, Commit: f.Commit, Secret: f.Secret,
				Match: f.Match, StartLine: f.StartLine, EndLine: f.EndLine}))
		}
		return "gitleaks", out, nil
	}
	if bytes.Contains(trim[:min(len(trim), 4096)], []byte(`"$schema"`)) || bytes.Contains(trim[:min(len(trim), 4096)], []byte(`"runs"`)) {
		return parseSARIF(trim)
	}
	return parseTrufflehog(trim)
}

func parseSARIF(data []byte) (string, []Input, error) {
	var log struct {
		Runs []struct {
			Tool struct {
				Driver struct{ Name string } `json:"driver"`
			} `json:"tool"`
			Results []struct {
				RuleID    string `json:"ruleId"`
				Locations []struct {
					PhysicalLocation struct {
						ArtifactLocation struct {
							URI string `json:"uri"`
						} `json:"artifactLocation"`
						Region struct {
							StartLine int `json:"startLine"`
							Snippet   struct {
								Text string `json:"text"`
							} `json:"snippet"`
						} `json:"region"`
					} `json:"physicalLocation"`
				} `json:"locations"`
				PartialFingerprints map[string]string `json:"partialFingerprints"`
				Properties          struct {
					Commit string `json:"commit"`
					Source string `json:"source"`
				} `json:"properties"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(data, &log); err != nil {
		return "", nil, fmt.Errorf("SARIF report: %w", err)
	}
	var out []Input
	for _, run := range log.Runs {
		tool := strings.ToLower(nonEmpty(run.Tool.Driver.Name, "sarif"))
		for _, r := range run.Results {
			in := Input{Tool: tool, RuleID: r.RuleID}
			if len(r.Locations) > 0 {
				pl := r.Locations[0].PhysicalLocation
				in.File = strings.TrimPrefix(pl.ArtifactLocation.URI, "file://")
				in.StartLine = pl.Region.StartLine
				in.Secret = pl.Region.Snippet.Text
			}
			// gitleaks puts the commit in partialFingerprints; secretscan's own
			// SARIF also has it (and the original tool, after triage) in
			// properties.
			in.Commit = nonEmpty(r.PartialFingerprints["commitSha"], r.Properties.Commit)
			if r.Properties.Source != "" {
				in.Tool = strings.ToLower(r.Properties.Source)
			}
			out = append(out, finish(in))
		}
	}
	return "sarif", out, nil
}

func parseTrufflehog(data []byte) (string, []Input, error) {
	var out []Input
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 1<<20), 64<<20)
	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 || line[0] != '{' {
			continue
		}
		var r struct {
			SourceMetadata struct {
				Data map[string]struct {
					File   string `json:"file"`
					Line   int    `json:"line"`
					Commit string `json:"commit"`
				} `json:"Data"`
			}
			DetectorName string
			Verified     bool
			Raw          string
		}
		if err := json.Unmarshal(line, &r); err != nil {
			return "", nil, fmt.Errorf("trufflehog report line: %w", err)
		}
		if r.DetectorName == "" && r.Raw == "" {
			continue // log line
		}
		in := Input{Tool: "trufflehog", RuleID: r.DetectorName, Secret: r.Raw, Verified: r.Verified}
		for _, d := range r.SourceMetadata.Data {
			in.File, in.StartLine, in.Commit = d.File, d.Line, d.Commit
		}
		out = append(out, finish(in))
	}
	return "trufflehog", out, sc.Err()
}

func nonEmpty(s, def string) string {
	if s == "" {
		return def
	}
	return s
}

// focus drops cached sources other than key. Callers that group findings by
// file (the CLI sorts them) read each file once and hold one at a time,
// however large the report.
func (t *Triager) focus(key string) {
	if t.cur == key {
		return
	}
	t.cur = key
	clear(t.cache)
	clear(t.text)
	clear(t.why)
}

// Triager re-scores findings against source files under Root.
type Triager struct {
	Det   *detect.Detector // must have RecordSuppressed set
	Root  string
	cache map[string]detect.Result
	text  map[string]string
	why   map[string]string
	cur   string
	Mode  string // Conservative (default) or Standard
}

// New returns a triager.
func New(det *detect.Detector, root string) *Triager {
	return &Triager{Det: det, Root: root, Mode: Conservative, cache: map[string]detect.Result{}, text: map[string]string{}, why: map[string]string{}}
}

const maxSource = 8 << 20

var commitRe = regexp.MustCompile(`^[0-9a-fA-F]{7,64}$`)

// resolve maps a report path to a path inside Root, refusing absolute paths
// outside it, ../ traversal and symlinks that escape it.
func (t *Triager) resolve(file string) (string, string, error) {
	root, err := filepath.Abs(t.Root)
	if err != nil {
		return "", "", err
	}
	realRoot := realPath(root)
	p := filepath.FromSlash(file)
	if !filepath.IsAbs(p) {
		p = filepath.Join(root, p)
	}
	p = filepath.Clean(p)
	// Containment is decided on resolved paths, so every spelling of the
	// root works (/var vs /private/var on macOS) and no symlink, on the file
	// or any directory above it, can lead outside --root.
	rel, err := filepath.Rel(realRoot, realPath(p))
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || filepath.IsAbs(rel) {
		return "", "", fmt.Errorf("path outside --root (after resolving symlinks)")
	}
	return p, filepath.ToSlash(rel), nil
}

// realPath resolves symlinks on the deepest existing ancestor of p and
// appends the rest, so a file that does not exist yet still resolves.
func realPath(p string) string {
	for dir, rest := p, ""; ; {
		if real, err := filepath.EvalSymlinks(dir); err == nil {
			return filepath.Join(real, rest)
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return p
		}
		rest = filepath.Join(filepath.Base(dir), rest)
		dir = parent
	}
}

// source loads the file content the finding refers to. A finding from a
// commit is only ever evaluated against that commit's version: if it cannot
// be read, the finding stays uncorroborated (no working-tree substitution).
func (t *Triager) source(in Input) (string, string) {
	key := in.Commit + "\x00" + in.File
	t.focus(key)
	if s, ok := t.text[key]; ok {
		return s, t.why[key]
	}
	set := func(s, why string) (string, string) {
		t.text[key], t.why[key] = s, why
		return s, why
	}
	abs, rel, err := t.resolve(in.File)
	if err != nil {
		return set("", err.Error()+"; not read")
	}
	if in.Commit != "" {
		if !commitRe.MatchString(in.Commit) {
			return set("", "invalid commit id in report")
		}
		// "./" makes the path relative to --root rather than to the top of the
		// repository, so --root on a subdirectory reads the right file.
		out, err := exec.Command("git", "-C", t.Root, "show", "--no-textconv", in.Commit+":./"+rel).Output()
		if err != nil {
			return set("", "source at commit "+in.Commit[:min(10, len(in.Commit))]+" unavailable (no working-tree substitution)")
		}
		if len(out) > maxSource {
			return set("", "source file too large to re-check")
		}
		return set(string(out), "")
	}
	b, err := os.ReadFile(abs)
	if err != nil {
		return set("", "source file unreadable")
	}
	if len(b) > maxSource {
		return set("", "source file too large to re-check")
	}
	return set(string(b), "")
}

// probe is the text expected at the reported location (full value or prefix).
func (in Input) probe() string {
	if !in.Redacted {
		return in.Secret
	}
	return in.Prefix
}

// matches compares a value secretscan saw with the reported one.
func (in Input) matches(ours string) bool {
	if !in.Redacted {
		return overlaps(ours, in.Secret)
	}
	return in.Prefix != "" && strings.HasPrefix(ours, in.Prefix)
}

// coveredBy reports whether a value secretscan filtered contains the whole
// reported value: only then does the filter's reason explain the finding.
// (A placeholder that merely occurs inside a longer reported token does
// not.)
func (in Input) coveredBy(filtered string) bool {
	if in.Redacted {
		return in.Prefix != "" && strings.HasPrefix(filtered, in.Prefix)
	}
	if in.Secret == "" || filtered == "" {
		return false
	}
	if strings.Contains(filtered, in.Secret) {
		return true
	}
	// Tools draw value boundaries differently ("x" vs x, a trailing ;): a
	// reported value that only adds punctuation is still the same value.
	return strings.Contains(in.Secret, filtered) && alnumCount(in.Secret) == alnumCount(filtered)
}

func alnumCount(s string) int {
	n := 0
	for i := 0; i < len(s); i++ {
		if c := s[i]; c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' {
			n++
		}
	}
	return n
}

func valueNear(text, probe string, start, end int) bool {
	lp := strings.ToLower(probe) // case-insensitive rules report the matched text in any case
	for n := max(1, start-1); n <= end+1; n++ {
		if strings.Contains(strings.ToLower(lineAt(text, n)), lp) {
			return true
		}
	}
	// Multi-line values (keys) or very long lines: fall back to the region.
	return strings.Contains(text, probe) && len(probe) > 200
}

func overlaps(a, b string) bool {
	if a == "" || b == "" {
		return false
	}
	return a == b || strings.Contains(a, b) || strings.Contains(b, a)
}

func near(a, b int) bool { return a == b || a == b-1 || a == b+1 || b == 0 }

// Evaluate re-scores one foreign finding.
func (t *Triager) Evaluate(in Input) detect.Finding {
	f := detect.Finding{RuleID: in.RuleID, Description: in.Tool + " " + in.RuleID, Severity: "high", File: in.File,
		StartLine: in.StartLine, EndLine: max(in.StartLine, in.EndLine), Secret: in.Secret, Match: in.Match, Commit: in.Commit,
		Source: in.Tool, Confidence: detect.Low} // uncorroborated: review under balanced, blocks under strict
	f.Fingerprint = detect.Fingerprint(f)
	if in.Verified {
		f.Triage, f.Confidence = Verified, detect.High
		f.Evidence = []string{"verified live by " + in.Tool}
		return f
	}
	text, why := t.source(in)
	if why != "" {
		f.Triage = Uncorroborated
		f.Evidence = []string{why + " (kept for review)"}
		return f
	}
	if in.StartLine > 0 {
		f.Line = lineAt(text, in.StartLine)
	}
	// Stale report: the reported value is no longer on the reported lines.
	if probe := in.probe(); probe != "" && in.StartLine > 0 && !valueNear(text, probe, in.StartLine, max(in.StartLine, in.EndLine)) {
		f.Triage = Uncorroborated
		f.Evidence = []string{"source changed since the report: value not found at the reported line (kept for review)"}
		return f
	}
	key := in.Commit + "\x00" + in.File
	res, done := t.cache[key]
	if !done {
		res = t.Det.Scan(detect.Fragment{Raw: text, FilePath: in.File, StartLine: 1, Commit: in.Commit})
		t.cache[key] = res
	}
	// 1. secretscan independently reports it.
	for _, o := range res.Findings {
		if near(o.StartLine, in.StartLine) && (in.matches(o.Secret) || (in.Redacted && in.Prefix == "" && o.StartLine == in.StartLine)) {
			f.Triage, f.Confidence = Confirmed, o.Confidence
			f.Evidence = append([]string{"also reported by secretscan rule " + o.RuleID}, o.Evidence...)
			return f
		}
	}
	// 2. secretscan saw the candidate and filtered it, with a reason.
	// Works with partially redacted reports (prefix match).
	var spared []string
	for _, s := range res.Suppressed {
		if near(s.StartLine, in.StartLine) && in.coveredBy(s.Secret) {
			if t.spare(s.Reason, f.Line, in) {
				spared = append(spared, s.Reason)
				break
			}
			f.Triage, f.Confidence = Filtered+": "+s.Reason, detect.Low
			f.Evidence = []string{"secretscan " + s.RuleID + " filtered this value: " + s.Reason}
			return f
		}
	}
	if in.Redacted {
		f.Triage = Uncorroborated
		why := "secret fully redacted in the report"
		if in.Prefix != "" {
			why = "partially redacted value not matched by secretscan"
		}
		f.Evidence = []string{why + " (kept for review)"}
		return f
	}
	// 3. Context: the match is a slice of a digest, hash or longer token.
	if why := detect.EmbeddedReason(f.Line, in.Secret); why != "" {
		f.Triage, f.Confidence = Filtered+": "+why, detect.Low
		f.Evidence = []string{"the reported value is part of a longer token: " + why}
		return f
	}
	// 4. Value filters, only for values without a provider-specific shape.
	if !providerShaped(t.Det, in) {
		quoted := strings.Contains(f.Line, `"`+in.Secret) || strings.Contains(f.Line, `'`+in.Secret)
		if why := detect.NoiseReason(in.Secret, quoted, in.File); why != "" {
			if !t.spare(why, f.Line, in) {
				f.Triage, f.Confidence = Filtered+": "+why, detect.Low
				f.Evidence = []string{"value filter: " + why}
				return f
			}
			if len(spared) == 0 || spared[len(spared)-1] != why {
				spared = append(spared, why)
			}
		}
	}
	f.Triage = Uncorroborated
	f.Evidence = []string{"no secretscan rule corroborates it and no filter explains it (kept for review)"}
	if len(spared) > 0 {
		f.Evidence = []string{"conservative mode: assigned to a credential-named key, so the shape-only filter (" +
			strings.Join(spared, ", ") + ") was not applied (kept for review)"}
	}
	return f
}

// Triage modes.
const (
	// Conservative never filters a value only because of its shape when the
	// line assigns it to a credential-named key (token, secret, password, key,
	// auth, ...): a UUID or a word-like string can be a real credential.
	Conservative = "conservative"
	// Standard applies every filter, as a scan does.
	Standard = "standard"
)

// shapeOnly are filters that judge what a value looks like, not where it
// sits; structural ones (digests, truncation, published examples,
// placeholders, sequences, templates) always apply, and so does
// credential-name: a value that names a secret ("prod-db-secret-id") is a
// reference whatever key holds it.
var shapeOnly = map[string]bool{
	"identifier": true, "uuid": true, "word-like": true, "camel-case-identifier": true, "word-tokens": true,
	"word-segments": true, "dotted-namespace": true, "single-case-letters": true, "digit-free-name-or-path": true,
	"stopword": true, "operator-in-code": true, "key=value-pair": true, "email-address": true,
	"allowlist: names that hold identifiers, not secrets": true,
	"allowlist: value read from env/secret store":         true,
}

// spare reports whether conservative mode keeps a value a filter would drop.
func (t *Triager) spare(reason, line string, in Input) bool {
	if t.Mode != Conservative || !shapeOnly[reason] {
		return false
	}
	i := strings.Index(line, in.probe())
	if i < 0 {
		return false
	}
	// Namespaced or snake-case names under a key (crypto.SHA256,
	// ALICE_secp112r2) remain identifiers even here, and a value that names a
	// secret (prod-db-secret-id) is a reference, not the secret.
	if reason == "identifier" && strings.ContainsAny(in.Secret, "._") || secretReference.MatchString(in.Secret) {
		return false
	}
	before := strings.TrimRight(line[max(0, i-80):i], " \t")
	if !detect.CredentialKey.MatchString(before) {
		return false
	}
	// UUIDs under request/correlation-style keys are IDs (request_token,
	// idempotency_key), unlike access_token = <uuid>.
	if reason == "uuid" && detect.RequestIDKey.MatchString(before) {
		return false
	}
	return true
}

var (
	secretReference = regexp.MustCompile(`(?i)(?:^|[_.-])(?:secret|token|password|passwd|key|credentials?)[_.-](?:id|name|ref|path|arn|key)$`)
)

// providerShaped reports whether any secretscan provider rule matches the
// bare value; such values are never filtered by generic value heuristics.
func providerShaped(det *detect.Detector, in Input) bool {
	for _, fd := range det.Detect(detect.Fragment{Raw: in.Secret, FilePath: "value.txt"}) {
		if !strings.Contains(strings.Join(fd.Tags, ","), "generic") {
			return true
		}
	}
	return false
}

func lineAt(text string, n int) string {
	for i := 1; i < n; i++ {
		j := strings.IndexByte(text, '\n')
		if j < 0 {
			return ""
		}
		text = text[j+1:]
	}
	if j := strings.IndexByte(text, '\n'); j >= 0 {
		text = text[:j]
	}
	if len(text) > 400 {
		text = text[:400]
	}
	return strings.TrimRight(text, "\r")
}
