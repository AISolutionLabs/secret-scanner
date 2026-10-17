// SPDX-License-Identifier: Apache-2.0

// Package report renders findings as text, JSON, SARIF, CSV or JUnit XML.
package report

import (
	"encoding/csv"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/AISolutionLabs/secret-scanner/internal/config"
	"github.com/AISolutionLabs/secret-scanner/internal/detect"
	"github.com/AISolutionLabs/secret-scanner/internal/remediate"
)

// Options control rendering.
type Options struct {
	Color       bool
	Remediation string // text: short (default) | full | none
	Policy      string // strict | balanced: text output groups non-blocking findings for review
	Explain     bool   // print the evidence for every finding (git hooks: explain every block)
}

// Formats lists supported report formats.
var Formats = []string{"text", "json", "sarif", "csv", "junit", "stats"}

// Write renders findings in the given format.
// ConfidenceScale describes the confidence field for report consumers.
const ConfidenceScale = "high/medium/low are qualitative evidence levels (independent signals that a value is a live credential in production code), not probabilities; policies decide what blocks"

func Write(w io.Writer, format string, fs []detect.Finding, rules []*config.CompiledRule, version string, o Options) error {
	switch strings.ToLower(format) {
	case "", "text":
		return Text(w, fs, o)
	case "json":
		return JSON(w, fs)
	case "sarif":
		return SARIF(w, fs, rules, version)
	case "csv":
		return CSV(w, fs)
	case "junit":
		return JUnit(w, fs)
	case "stats":
		return Stats(w, fs, version, o.Policy)
	}
	return fmt.Errorf("unknown report format %q (want one of %s)", format, strings.Join(Formats, ", "))
}

// StatsReport is an anonymized summary for sharing results publicly (for
// example in a benchmark issue): counts only. It contains no file paths,
// secret values, fingerprints, line numbers or commit data.
type StatsReport struct {
	Schema       int            `json:"schema"`
	Version      string         `json:"version"`
	Policy       string         `json:"policy"`
	Findings     int            `json:"findings"`
	Blocking     int            `json:"blocking"`
	ByRule       map[string]int `json:"byRule"`
	ByConfidence map[string]int `json:"byConfidence"`
	ByFileType   map[string]int `json:"byFileType"` // extension only, e.g. ".py"
}

// Stats writes a StatsReport.
func Stats(w io.Writer, fs []detect.Finding, version, policy string) error {
	if policy == "" {
		policy = "strict"
	}
	r := StatsReport{Schema: 1, Version: version, Policy: policy, Findings: len(fs),
		ByRule: map[string]int{}, ByConfidence: map[string]int{}, ByFileType: map[string]int{}}
	for _, f := range fs {
		if f.Blocking {
			r.Blocking++
		}
		r.ByRule[f.RuleID]++
		r.ByConfidence[f.Confidence]++
		ext := strings.ToLower(filepath.Ext(f.File))
		if ext == "" || len(ext) > 12 {
			ext = "(none)"
		}
		r.ByFileType[ext]++
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(r)
}

// JSON writes a gitleaks-compatible JSON array.
func JSON(w io.Writer, fs []detect.Finding) error {
	if fs == nil {
		fs = []detect.Finding{}
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	return enc.Encode(fs)
}

const (
	cReset = "\x1b[0m"
	cBold  = "\x1b[1m"
	cDim   = "\x1b[2m"
	cRed   = "\x1b[31m"
	cYel   = "\x1b[33m"
	cCyan  = "\x1b[36m"
	cMag   = "\x1b[35m"
)

func sevColor(s string) string {
	switch s {
	case "critical":
		return cMag
	case "high":
		return cRed
	case "medium":
		return cYel
	}
	return cCyan
}

// Text writes a human-readable report.
func Text(w io.Writer, fs []detect.Finding, o Options) error {
	color := o.Color
	c := func(code, s string) string {
		if !color {
			return s
		}
		return code + s + cReset
	}
	reviewHeader := false
	for _, f := range fs {
		if !f.Blocking && o.Policy == "balanced" && !reviewHeader {
			reviewHeader = true
			fmt.Fprintf(w, "%s\n\n", c(cBold+cYel, "── Needs review (not blocking under the balanced policy) ──"))
		}
		loc := f.File
		if f.StartLine > 0 {
			loc = fmt.Sprintf("%s:%d:%d", f.File, f.StartLine, f.StartColumn)
		}
		conf := ""
		if f.Confidence != "" {
			conf = "·" + f.Confidence
		}
		if f.Context != "" {
			conf += "·" + f.Context // local / example credential: review under balanced
		}
		fmt.Fprintf(w, "%s %s %s  %s\n", c(cBold+sevColor(f.Severity), "["+strings.ToUpper(f.Severity)+conf+"]"),
			c(cBold, f.RuleID), c(cDim, f.Description), loc)
		if f.Secret != "" {
			fmt.Fprintf(w, "    secret:  %s\n", c(sevColor(f.Severity), oneLine(f.Secret, 120)))
		}
		if f.Line != "" {
			fmt.Fprintf(w, "    line:    %s\n", oneLine(strings.TrimSpace(f.Line), 160))
		}
		if f.Decoded != "" {
			fmt.Fprintf(w, "    decoded: %s\n", f.Decoded)
		}
		if f.Context != "" {
			fmt.Fprintf(w, "    context: %s\n", contextNote(f))
		}
		if f.Commit != "" {
			fmt.Fprintf(w, "    commit:  %s  %s <%s>  %s\n", short(f.Commit), f.Author, f.Email, f.Date)
		}
		if f.Source != "" {
			fmt.Fprintf(w, "    source:  %s · %s\n", f.Source, f.Triage)
		}
		if f.Verification != "" {
			v := f.Verification
			if v == "verified" {
				v = c(cBold+cRed, "VERIFIED LIVE")
			}
			fmt.Fprintf(w, "    verify:  %s\n", v)
		}
		if len(f.Evidence) > 0 && (o.Explain || o.Remediation == "full" || f.Confidence != detect.High) {
			fmt.Fprintf(w, "    why:     %s\n", c(cDim, strings.Join(f.Evidence, "; ")))
		}
		writeRemediation(w, f, o, c)
		fmt.Fprintf(w, "    ignore:  %s\n\n", c(cDim, f.Fingerprint))
	}
	return nil
}

// contextNote explains a local/example classification.
func contextNote(f detect.Finding) string {
	note := f.Context
	switch f.Context {
	case detect.ContextLocal:
		note = "local (credential for a local/development service; rotate it if it is reused anywhere real)"
	case detect.ContextExample:
		note = "example (in an example/template file; make sure it is not a real value)"
	}
	return note
}

func oneLine(s string, n int) string {
	s = strings.ReplaceAll(s, "\n", `\n`)
	if len(s) > n {
		return s[:n] + "…"
	}
	return s
}

func short(sha string) string {
	if len(sha) > 10 {
		return sha[:10]
	}
	return sha
}

// Summary returns a one-line count by severity.
func Summary(fs []detect.Finding) string {
	if len(fs) == 0 {
		return "no secrets found"
	}
	counts := map[string]int{}
	for _, f := range fs {
		counts[f.Severity]++
	}
	var parts []string
	for _, s := range []string{"critical", "high", "medium", "low", "info"} {
		if counts[s] > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", counts[s], s))
		}
	}
	noun := "secrets"
	if len(fs) == 1 {
		noun = "secret"
	}
	return fmt.Sprintf("%d %s found (%s)", len(fs), noun, strings.Join(parts, ", "))
}

// CSV writes one row per finding.
func CSV(w io.Writer, fs []detect.Finding) error {
	cw := csv.NewWriter(w)
	_ = cw.Write([]string{"RuleID", "Severity", "Confidence", "Blocking", "File", "StartLine", "EndLine", "StartColumn", "EndColumn", "Secret", "Match",
		"Entropy", "Decoded", "Commit", "Author", "Email", "Date", "Fingerprint", "SecretHash", "Verification"})
	for _, f := range fs {
		_ = cw.Write([]string{f.RuleID, f.Severity, f.Confidence, strconv.FormatBool(f.Blocking), f.File, strconv.Itoa(f.StartLine), strconv.Itoa(f.EndLine),
			strconv.Itoa(f.StartColumn), strconv.Itoa(f.EndColumn), f.Secret, f.Match,
			strconv.FormatFloat(f.Entropy, 'f', 2, 64), f.Decoded, f.Commit, f.Author, f.Email, f.Date,
			f.Fingerprint, f.SecretHash, f.Verification})
	}
	cw.Flush()
	return cw.Error()
}

// JUnit writes one failing test case per finding.
func JUnit(w io.Writer, fs []detect.Finding) error {
	type failure struct {
		Message string `xml:"message,attr"`
		Type    string `xml:"type,attr"`
		Body    string `xml:",chardata"`
	}
	type testcase struct {
		Name      string   `xml:"name,attr"`
		Classname string   `xml:"classname,attr"`
		File      string   `xml:"file,attr,omitempty"`
		Failure   *failure `xml:"failure,omitempty"`
	}
	type suite struct {
		XMLName  xml.Name   `xml:"testsuite"`
		Name     string     `xml:"name,attr"`
		Tests    int        `xml:"tests,attr"`
		Failures int        `xml:"failures,attr"`
		Cases    []testcase `xml:"testcase"`
	}
	s := suite{Name: "secretscan", Tests: len(fs), Failures: len(fs)}
	if len(fs) == 0 {
		s.Tests = 1
		s.Cases = []testcase{{Name: "no secrets found", Classname: "secretscan"}}
	}
	for _, f := range fs {
		s.Cases = append(s.Cases, testcase{
			Name:      fmt.Sprintf("%s at %s:%d", f.RuleID, f.File, f.StartLine),
			Classname: f.RuleID, File: f.File,
			Failure: &failure{Message: f.Description, Type: f.Severity,
				Body: fmt.Sprintf("secret=%s\ncommit=%s\nfingerprint=%s", oneLine(f.Secret, 200), f.Commit, f.Fingerprint)},
		})
	}
	fmt.Fprint(w, xml.Header)
	enc := xml.NewEncoder(w)
	enc.Indent("", "  ")
	if err := enc.Encode(s); err != nil {
		return err
	}
	_, err := fmt.Fprintln(w)
	return err
}

// SARIF writes a SARIF 2.1.0 log (GitHub code scanning, ADO, Defender).
func SARIF(w io.Writer, fs []detect.Finding, rules []*config.CompiledRule, version string) error {
	type msg struct {
		Text string `json:"text"`
	}
	type rule struct {
		ID                   string            `json:"id"`
		Name                 string            `json:"name"`
		ShortDescription     msg               `json:"shortDescription"`
		DefaultConfiguration map[string]any    `json:"defaultConfiguration"`
		Properties           map[string]any    `json:"properties,omitempty"`
		Help                 map[string]string `json:"help,omitempty"`
	}
	used := map[string]bool{}
	for _, f := range fs {
		used[f.RuleID] = true
	}
	var srules []rule
	for _, r := range rules {
		if !used[r.ID] {
			continue
		}
		srules = append(srules, rule{ID: r.ID, Name: r.ID, ShortDescription: msg{r.Description}, Help: ruleHelp(r),
			DefaultConfiguration: map[string]any{"level": sarifLevel(r.Severity)},
			Properties:           map[string]any{"tags": append([]string{"security", "secret"}, r.Tags...), "security-severity": securitySeverity(r.Severity)}})
	}
	sort.Slice(srules, func(i, j int) bool { return srules[i].ID < srules[j].ID })

	results := make([]map[string]any, 0, len(fs))
	for _, f := range fs {
		region := map[string]any{}
		if f.StartLine > 0 {
			region = map[string]any{"startLine": f.StartLine, "startColumn": f.StartColumn, "endLine": f.EndLine, "endColumn": max(f.EndColumn, 1),
				"snippet": map[string]any{"text": f.Secret}}
		}
		phys := map[string]any{"artifactLocation": map[string]any{"uri": f.File}}
		if len(region) > 0 {
			phys["region"] = region
		}
		props := map[string]any{"context": f.Context, "confidence": f.Confidence, "evidence": f.Evidence, "blocking": f.Blocking, "commit": f.Commit, "author": f.Author, "email": f.Email, "date": f.Date, "entropy": f.Entropy}
		if f.Decoded != "" {
			props["decoded"] = f.Decoded
		}
		if f.Verification != "" {
			props["verification"] = f.Verification
		}
		if f.Remediation != nil {
			props["remediation"] = f.Remediation
		}
		// Triage provenance: the tool that reported the finding and the
		// status secretscan gave it (confirmed, uncorroborated, filtered:
		// <reason>). Without these a filtered finding reads as a plain note.
		if f.Source != "" {
			props["source"] = f.Source
		}
		if f.Triage != "" {
			props["triage"] = f.Triage
		}
		fps := map[string]string{"secretscan/v1": f.SecretHash, "fingerprint": f.Fingerprint}
		if f.Commit != "" {
			fps["commitSha"] = f.Commit // as gitleaks writes it, so the report can be re-triaged
		}
		results = append(results, map[string]any{
			"ruleId":              f.RuleID,
			"level":               resultLevel(f),
			"message":             msg{fmt.Sprintf("%s detected", f.Description)},
			"locations":           []any{map[string]any{"physicalLocation": phys}},
			"partialFingerprints": fps,
			"properties":          props,
		})
	}
	log := map[string]any{
		"$schema": "https://json.schemastore.org/sarif-2.1.0.json",
		"version": "2.1.0",
		"runs": []any{map[string]any{
			"tool": map[string]any{"driver": map[string]any{
				"name": "secretscan", "version": version, "semanticVersion": version,
				"informationUri": "https://github.com/AISolutionLabs/secret-scanner", "rules": srules,
				// Result properties.confidence is an evidence level; say so
				// where SARIF consumers look, so it is not read as a score.
				"properties": map[string]any{"confidenceScale": ConfidenceScale}}},
			"results": results,
		}},
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	return enc.Encode(log)
}

func sarifLevel(sev string) string {
	switch sev {
	case "critical", "high":
		return "error"
	case "medium":
		return "warning"
	}
	return "note"
}

func securitySeverity(sev string) string {
	switch sev {
	case "critical":
		return "9.5"
	case "high":
		return "8.0"
	case "medium":
		return "5.5"
	case "low":
		return "3.0"
	}
	return "1.0"
}

func writeRemediation(w io.Writer, f detect.Finding, o Options, c func(string, string) string) {
	g := f.Remediation
	if g == nil || o.Remediation == "none" {
		return
	}
	explain := fmt.Sprintf("secretscan explain %s", f.RuleID)
	if g.Language != "" {
		explain += " --lang " + g.Language
	}
	if g.Store != "" && g.Store != "env" {
		explain += " --store " + g.Store
	}
	if o.Remediation == "full" {
		fmt.Fprintf(w, "    fix (%s):\n", g.Family)
		for i, s := range g.Steps {
			fmt.Fprintf(w, "      %d. %s\n", i+1, s)
		}
		if snip, ok := remediate.Snippet(g.Language, g.Store, g.EnvVar); ok {
			fmt.Fprintf(w, "      code (%s, %s):\n", g.Language, g.Store)
			for _, l := range strings.Split(strings.TrimRight(snip, "\n"), "\n") {
				fmt.Fprintf(w, "        %s\n", l)
			}
		}
		return
	}
	urg := "rotate"
	if g.Urgency == "revoke-now" {
		urg = c(cBold+cRed, "REVOKE NOW")
	} else if g.Urgency == "review" {
		urg = "remove (already invalid)"
	}
	fmt.Fprintf(w, "    fix:     %s · %s\n", urg, firstSentence(g.Rotate))
	if g.Eliminate != "" {
		fmt.Fprintf(w, "    better:  %s\n", firstSentence(g.Eliminate))
	}
	if g.Replace != "" {
		fmt.Fprintf(w, "    code:    %s  %s\n", g.Replace, c(cDim, "("+explain+")"))
	} else {
		fmt.Fprintf(w, "    code:    %s\n", c(cDim, explain))
	}
}

// firstSentence cuts at the first ". X" that isn't an abbreviation like e.g.
func firstSentence(s string) string {
	for i := 0; i+2 < len(s); i++ {
		if s[i] != '.' || s[i+1] != ' ' || !(s[i+2] >= 'A' && s[i+2] <= 'Z') {
			continue
		}
		if prev := s[max(0, i-3):i]; strings.HasSuffix(prev, "e.g") || strings.HasSuffix(prev, "i.e") || strings.HasSuffix(prev, "etc") {
			continue
		}
		return s[:i+1]
	}
	return s
}

// ruleHelp renders SARIF help for a rule from its remediation family.
func ruleHelp(r *config.CompiledRule) map[string]string {
	fam := remediate.FamilyFor(r.ID)
	g := remediate.For(remediate.Input{RuleID: r.ID})
	md := fmt.Sprintf("**%s** (%s)\n\n1. **Rotate:** %s\n2. **Avoid static secrets:** %s\n3. **Load at runtime:** inject `%s` from your secret store and read it once at startup (or cache with a TTL). Run `secretscan explain %s --lang <language>` for code.\n\nRemoving the line does not remove it from git history; rotation is the fix.",
		r.Description, fam.Name, fam.Rotate, nonEmpty(fam.Eliminate, "keep it in a secret store"), g.EnvVar, r.ID)
	text := fmt.Sprintf("%s. Rotate: %s %s", r.Description, fam.Rotate, fam.Eliminate)
	return map[string]string{"text": text, "markdown": md}
}

func nonEmpty(s, def string) string {
	if s == "" {
		return def
	}
	return s
}

// PolicyLine summarizes what blocks, what needs review and what filters
// removed, so nothing is silently dropped.
func PolicyLine(fs []detect.Finding, policy string, hidden int, suppressed map[string]int) string {
	block, review := 0, 0
	for _, f := range fs {
		if f.Blocking {
			block++
		} else {
			review++
		}
	}
	var parts []string
	if len(fs) > 0 || hidden > 0 {
		parts = append(parts, fmt.Sprintf("policy %s: %d blocking, %d to review", policy, block, review))
	}
	if hidden > 0 {
		parts = append(parts, fmt.Sprintf("%d below --min-confidence hidden", hidden))
	}
	total := 0
	for _, n := range suppressed {
		total += n
	}
	if total > 0 {
		keys := make([]string, 0, len(suppressed))
		for k := range suppressed {
			keys = append(keys, k)
		}
		sort.Slice(keys, func(i, j int) bool { return suppressed[keys[i]] > suppressed[keys[j]] })
		var why []string
		for i, k := range keys {
			if i == 4 {
				why = append(why, "…")
				break
			}
			why = append(why, fmt.Sprintf("%d %s", suppressed[k], k))
		}
		parts = append(parts, fmt.Sprintf("%d candidates filtered as noise (%s; --show-suppressed to list)", total, strings.Join(why, ", ")))
	}
	if len(parts) == 0 {
		return ""
	}
	return "  " + strings.Join(parts, " · ")
}

// resultLevel follows the policy: blocking findings are errors; findings
// left for review are warnings (medium) or notes (low), so CI gates that
// fail on SARIF errors match the scanner's own exit code.
func resultLevel(f detect.Finding) string {
	if f.Blocking {
		return "error"
	}
	if f.Confidence == detect.Medium {
		return "warning"
	}
	return "note"
}
