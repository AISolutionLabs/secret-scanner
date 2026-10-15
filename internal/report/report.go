// Package report renders findings as text, JSON, SARIF, CSV or JUnit XML.
package report

import (
	"encoding/csv"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"

	"github.com/anirudh/secretscan/internal/config"
	"github.com/anirudh/secretscan/internal/detect"
)

// Formats lists supported report formats.
var Formats = []string{"text", "json", "sarif", "csv", "junit"}

// Write renders findings in the given format.
func Write(w io.Writer, format string, fs []detect.Finding, rules []*config.CompiledRule, version string, color bool) error {
	switch strings.ToLower(format) {
	case "", "text":
		return Text(w, fs, color)
	case "json":
		return JSON(w, fs)
	case "sarif":
		return SARIF(w, fs, rules, version)
	case "csv":
		return CSV(w, fs)
	case "junit":
		return JUnit(w, fs)
	}
	return fmt.Errorf("unknown report format %q (want one of %s)", format, strings.Join(Formats, ", "))
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
func Text(w io.Writer, fs []detect.Finding, color bool) error {
	c := func(code, s string) string {
		if !color {
			return s
		}
		return code + s + cReset
	}
	for _, f := range fs {
		loc := f.File
		if f.StartLine > 0 {
			loc = fmt.Sprintf("%s:%d:%d", f.File, f.StartLine, f.StartColumn)
		}
		fmt.Fprintf(w, "%s %s %s  %s\n", c(cBold+sevColor(f.Severity), "["+strings.ToUpper(f.Severity)+"]"),
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
		if f.Commit != "" {
			fmt.Fprintf(w, "    commit:  %s  %s <%s>  %s\n", short(f.Commit), f.Author, f.Email, f.Date)
		}
		if f.Verification != "" {
			fmt.Fprintf(w, "    verify:  %s\n", f.Verification)
		}
		fmt.Fprintf(w, "    ignore:  %s\n\n", c(cDim, f.Fingerprint))
	}
	return nil
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
	_ = cw.Write([]string{"RuleID", "Severity", "File", "StartLine", "EndLine", "StartColumn", "EndColumn", "Secret", "Match",
		"Entropy", "Decoded", "Commit", "Author", "Email", "Date", "Fingerprint", "SecretHash", "Verification"})
	for _, f := range fs {
		_ = cw.Write([]string{f.RuleID, f.Severity, f.File, strconv.Itoa(f.StartLine), strconv.Itoa(f.EndLine),
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
		ID                   string         `json:"id"`
		Name                 string         `json:"name"`
		ShortDescription     msg            `json:"shortDescription"`
		DefaultConfiguration map[string]any `json:"defaultConfiguration"`
		Properties           map[string]any `json:"properties,omitempty"`
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
		srules = append(srules, rule{ID: r.ID, Name: r.ID, ShortDescription: msg{r.Description},
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
		props := map[string]any{"commit": f.Commit, "author": f.Author, "email": f.Email, "date": f.Date, "entropy": f.Entropy}
		if f.Decoded != "" {
			props["decoded"] = f.Decoded
		}
		if f.Verification != "" {
			props["verification"] = f.Verification
		}
		results = append(results, map[string]any{
			"ruleId":              f.RuleID,
			"level":               sarifLevel(f.Severity),
			"message":             msg{fmt.Sprintf("%s detected", f.Description)},
			"locations":           []any{map[string]any{"physicalLocation": phys}},
			"partialFingerprints": map[string]string{"secretscan/v1": f.SecretHash, "fingerprint": f.Fingerprint},
			"properties":          props,
		})
	}
	log := map[string]any{
		"$schema": "https://json.schemastore.org/sarif-2.1.0.json",
		"version": "2.1.0",
		"runs": []any{map[string]any{
			"tool": map[string]any{"driver": map[string]any{
				"name": "secretscan", "version": version, "semanticVersion": version,
				"informationUri": "https://github.com/anirudh/secretscan", "rules": srules}},
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
