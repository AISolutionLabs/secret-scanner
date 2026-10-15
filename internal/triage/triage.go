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
			out = append(out, Input{Tool: "gitleaks", RuleID: f.RuleID, File: f.File, Commit: f.Commit, Secret: f.Secret,
				Match: f.Match, StartLine: f.StartLine, EndLine: f.EndLine, Redacted: isRedacted(f.Secret)})
		}
		return "gitleaks", out, nil
	}
	if bytes.Contains(trim[:min(len(trim), 4096)], []byte(`"$schema"`)) || bytes.Contains(trim[:min(len(trim), 4096)], []byte(`"runs"`)) {
		return parseSARIF(trim)
	}
	return parseTrufflehog(trim)
}

func isRedacted(s string) bool {
	return s == "" || strings.Contains(s, "REDACTED") || strings.Trim(s, "*") == ""
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
			in.Redacted = isRedacted(in.Secret)
			out = append(out, in)
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
		in := Input{Tool: "trufflehog", RuleID: r.DetectorName, Secret: r.Raw, Verified: r.Verified, Redacted: r.Raw == ""}
		for _, d := range r.SourceMetadata.Data {
			in.File, in.StartLine, in.Commit = d.File, d.Line, d.Commit
		}
		out = append(out, in)
	}
	return "trufflehog", out, sc.Err()
}

func nonEmpty(s, def string) string {
	if s == "" {
		return def
	}
	return s
}

// Triager re-scores findings against source files under Root.
type Triager struct {
	Det   *detect.Detector // must have RecordSuppressed set
	Root  string
	cache map[string]detect.Result
	text  map[string]string
}

// New returns a triager.
func New(det *detect.Detector, root string) *Triager {
	return &Triager{Det: det, Root: root, cache: map[string]detect.Result{}, text: map[string]string{}}
}

func (t *Triager) source(in Input) (string, bool) {
	key := in.Commit + "\x00" + in.File
	if s, ok := t.text[key]; ok {
		return s, s != ""
	}
	var data []byte
	if in.Commit != "" {
		if out, err := exec.Command("git", "-C", t.Root, "show", in.Commit+":"+filepath.ToSlash(in.File)).Output(); err == nil {
			data = out
		}
	}
	if data == nil {
		p := in.File
		if !filepath.IsAbs(p) {
			p = filepath.Join(t.Root, p)
		}
		if b, err := os.ReadFile(p); err == nil && len(b) <= 8<<20 {
			data = b
		}
	}
	t.text[key] = string(data)
	return string(data), data != nil
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
		Source: in.Tool, Confidence: detect.Medium}
	f.Fingerprint = detect.Fingerprint(f)
	if in.Verified {
		f.Triage, f.Confidence = Verified, detect.High
		f.Evidence = []string{"verified live by " + in.Tool}
		return f
	}
	text, ok := t.source(in)
	if !ok {
		f.Triage = Uncorroborated
		f.Evidence = []string{"source not available to re-check (kept for review)"}
		return f
	}
	if in.StartLine > 0 {
		f.Line = lineAt(text, in.StartLine)
	}
	key := in.Commit + "\x00" + in.File
	res, done := t.cache[key]
	if !done {
		res = t.Det.Scan(detect.Fragment{Raw: text, FilePath: in.File, StartLine: 1, Commit: in.Commit})
		t.cache[key] = res
	}
	// 1. secretscan independently reports it.
	for _, o := range res.Findings {
		if near(o.StartLine, in.StartLine) && (overlaps(o.Secret, in.Secret) || (in.Redacted && o.StartLine == in.StartLine)) {
			f.Triage, f.Confidence = Confirmed, o.Confidence
			f.Evidence = append([]string{"also reported by secretscan rule " + o.RuleID}, o.Evidence...)
			return f
		}
	}
	if in.Redacted {
		f.Triage = Uncorroborated
		f.Evidence = []string{"secret redacted in the source report; re-run it unredacted to triage (kept for review)"}
		return f
	}
	// 2. secretscan saw the candidate and filtered it, with a reason.
	for _, s := range res.Suppressed {
		if near(s.StartLine, in.StartLine) && overlaps(s.Secret, in.Secret) {
			f.Triage, f.Confidence = Filtered+": "+s.Reason, detect.Low
			f.Evidence = []string{"secretscan " + s.RuleID + " filtered this value: " + s.Reason}
			return f
		}
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
