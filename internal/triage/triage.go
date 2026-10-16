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
			in.Commit = r.PartialFingerprints["commitSha"]
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
}

// New returns a triager.
func New(det *detect.Detector, root string) *Triager {
	return &Triager{Det: det, Root: root, cache: map[string]detect.Result{}, text: map[string]string{}, why: map[string]string{}}
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
	realRoot := root
	if r, err := filepath.EvalSymlinks(root); err == nil {
		realRoot = r
	}
	p := filepath.FromSlash(file)
	if !filepath.IsAbs(p) {
		p = filepath.Join(root, p)
	}
	p = filepath.Clean(p)
	inside := func(base, x string) (string, bool) {
		rel, err := filepath.Rel(base, x)
		return rel, err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) && !filepath.IsAbs(rel)
	}
	// Lexically inside --root, as given or as resolved (an absolute report
	// path may be spelled either way, e.g. /var vs /private/var on macOS).
	rel, ok := inside(root, p)
	if !ok {
		if rel, ok = inside(realRoot, p); !ok {
			return "", "", fmt.Errorf("path outside --root")
		}
	}
	// Then resolve symlinks on the deepest existing ancestor: neither the
	// file nor any directory on the way may lead outside --root, even when
	// the file itself does not exist yet.
	for dir, rest := p, ""; ; {
		if real, err := filepath.EvalSymlinks(dir); err == nil {
			if _, ok := inside(realRoot, filepath.Join(real, rest)); !ok {
				return "", "", fmt.Errorf("symlink resolves outside --root")
			}
			break
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		rest = filepath.Join(filepath.Base(dir), rest)
		dir = parent
	}
	return p, filepath.ToSlash(rel), nil
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
	for _, s := range res.Suppressed {
		if near(s.StartLine, in.StartLine) && in.matches(s.Secret) {
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
			f.Triage, f.Confidence = Filtered+": "+why, detect.Low
			f.Evidence = []string{"value filter: " + why}
			return f
		}
	}
	f.Triage = Uncorroborated
	f.Evidence = []string{"no secretscan rule corroborates it and no filter explains it (kept for review)"}
	return f
}

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
