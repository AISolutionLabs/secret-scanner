// SPDX-License-Identifier: Apache-2.0

// Package config defines the scanner configuration schema (a superset of the
// gitleaks v8 TOML format), loads and merges configs, and compiles rules.
package config

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/AISolutionLabs/secret-scanner/internal/toml"
)

// Config is the on-disk configuration. Field names match gitleaks so existing
// .gitleaks.toml files load unchanged.
type Config struct {
	Title       string      `json:"title"`
	Description string      `json:"description"`
	Extend      Extend      `json:"extend"`
	Rules       []Rule      `json:"rules"`
	Allowlist   *Allowlist  `json:"allowlist"`  // legacy single global allowlist
	Allowlists  []Allowlist `json:"allowlists"` // global allowlists
	Remediation Remediation `json:"remediation"`
	// Policy decides what blocks: "strict" (every finding) or "balanced"
	// (only high-confidence findings; the rest are reported for review).
	Policy string `json:"policy"`
}

// Remediation sets organization defaults for fix guidance.
type Remediation struct {
	Store   string `json:"store"`   // env | vault | aws | azure | gcp: the secret store snippets target
	Runbook string `json:"runbook"` // link to your internal secret-handling / rotation runbook
}

// Extend controls how this config relates to others.
type Extend struct {
	// UseDefault keeps the built-in rule pack. Unlike gitleaks, it defaults
	// to true: custom rules are additive unless you set useDefault = false.
	UseDefault    *bool    `json:"useDefault"`
	Path          string   `json:"path"`          // another config to extend
	DisabledRules []string `json:"disabledRules"` // rule IDs to drop
}

// Rule is one detector.
type Rule struct {
	ID          string      `json:"id"`
	Description string      `json:"description"`
	Regex       string      `json:"regex"`       // RE2 syntax; optional if Path is set
	SecretGroup int         `json:"secretGroup"` // capture group holding the secret
	Entropy     float64     `json:"entropy"`     // minimum Shannon entropy of the secret
	Keywords    []string    `json:"keywords"`    // fast prefilter (case-insensitive)
	Path        string      `json:"path"`        // only scan matching paths; alone = file-name rule
	Tags        []string    `json:"tags"`
	Severity    string      `json:"severity"` // critical|high|medium|low|info (default high)
	Allowlist   *Allowlist  `json:"allowlist"`
	Allowlists  []Allowlist `json:"allowlists"`
	// Self-tests, checked by `secretscan config validate`.
	Examples  []string `json:"examples"`  // must produce a finding
	Negatives []string `json:"negatives"` // must not produce a finding
}

// Allowlist suppresses findings. Within one allowlist, criteria combine with
// Condition (OR by default, or AND).
type Allowlist struct {
	Description string   `json:"description"`
	Condition   string   `json:"condition"`
	Commits     []string `json:"commits"`
	Paths       []string `json:"paths"`
	RegexTarget string   `json:"regexTarget"` // secret (default) | match | line | prefix (match text before the secret)
	Regexes     []string `json:"regexes"`
	Stopwords   []string `json:"stopwords"`
	TargetRules []string `json:"targetRules"` // global allowlists only
	// TargetTags limits a global allowlist to rules carrying one of these
	// tags (e.g. ["generic"]), so value-based suppressions written for noisy
	// generic rules can never hide a structured provider token.
	TargetTags []string `json:"targetTags"`
}

// Severity levels, ordered.
var severityRank = map[string]int{"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

// SeverityRank returns the ordinal of a severity, or -1 if unknown.
func SeverityRank(s string) int {
	if r, ok := severityRank[strings.ToLower(s)]; ok {
		return r
	}
	return -1
}

// LoadFile reads a TOML (or JSON, by extension) config file.
func LoadFile(path string) (*Config, []string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, err
	}
	return Load(data, strings.EqualFold(filepath.Ext(path), ".json"))
}

// Load decodes config bytes. Unknown keys are reported as warnings, not
// errors, so newer gitleaks configs still load.
func Load(data []byte, isJSON bool) (*Config, []string, error) {
	var raw []byte
	if isJSON {
		raw = data
	} else {
		tree, err := toml.Parse(data)
		if err != nil {
			return nil, nil, err
		}
		raw, err = json.Marshal(tree)
		if err != nil {
			return nil, nil, err
		}
	}
	var c Config
	if err := json.Unmarshal(raw, &c); err != nil {
		return nil, nil, fmt.Errorf("config: %w", err)
	}
	var warnings []string
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var strict Config
	if err := dec.Decode(&strict); err != nil {
		warnings = append(warnings, fmt.Sprintf("config: ignoring unsupported setting (%v)", err))
	}
	return &c, warnings, nil
}

// Options are CLI-level adjustments applied on top of file configs.
type Options struct {
	ConfigPath      string
	NoDefaults      bool
	Patterns        []string // "id=regex" or bare regex
	PatternsFiles   []string
	EnableRules     []string // if set, only these rule IDs
	DisableRules    []string
	Tags            []string // if set, only rules carrying one of these tags
	ExcludePaths    []string // extra global path allowlist regexes
	SearchDirs      []string // where to auto-discover a config
	DefaultSeverity string
}

// AutoConfigNames are discovered (in order) in the scan root when no config
// is given explicitly.
var AutoConfigNames = []string{".secretscan.toml", "secretscan.toml", ".gitleaks.toml"}

// Resolve builds the effective config: discovered/explicit file (with
// extends), the default pack, ad-hoc patterns, then filters.
func Resolve(o Options) (*Config, []string, error) {
	var warnings []string
	path := o.ConfigPath
	if path == "" {
		path = os.Getenv("SECRETSCAN_CONFIG")
	}
	if path == "" {
		for _, dir := range o.SearchDirs {
			for _, name := range AutoConfigNames {
				candidate := filepath.Join(dir, name)
				if fi, err := os.Stat(candidate); err == nil && !fi.IsDir() {
					path = candidate
					break
				}
			}
			if path != "" {
				break
			}
		}
	}

	eff := &Config{}
	useDefault := !o.NoDefaults
	var disabled []string
	if path != "" {
		c, w, err := loadWithExtends(path, 0)
		warnings = append(warnings, w...)
		if err != nil {
			return nil, warnings, err
		}
		eff = c
		if c.Extend.UseDefault != nil && !*c.Extend.UseDefault {
			useDefault = false
		}
		disabled = c.Extend.DisabledRules
	}
	if useDefault {
		def := Default()
		eff = merge(def, eff)
	}

	// Ad-hoc patterns from flags and files.
	pats := append([]string{}, o.Patterns...)
	for _, f := range o.PatternsFiles {
		lines, err := readPatternsFile(f)
		if err != nil {
			return nil, warnings, err
		}
		pats = append(pats, lines...)
	}
	for i, p := range pats {
		r, err := ParsePattern(p, i+1)
		if err != nil {
			return nil, warnings, err
		}
		if o.DefaultSeverity != "" && r.Severity == "" {
			r.Severity = o.DefaultSeverity
		}
		eff = merge(eff, &Config{Rules: []Rule{r}})
	}

	if len(o.ExcludePaths) > 0 {
		eff.Allowlists = append(eff.Allowlists, Allowlist{Description: "--exclude-path", Paths: o.ExcludePaths})
	}

	disabled = append(disabled, o.DisableRules...)
	eff.Rules = filterRules(eff.Rules, o.EnableRules, disabled, o.Tags)
	if len(eff.Rules) == 0 {
		return nil, warnings, fmt.Errorf("config: no rules enabled")
	}
	return eff, warnings, nil
}

func loadWithExtends(path string, depth int) (*Config, []string, error) {
	if depth > 5 {
		return nil, nil, fmt.Errorf("config: extend chain too deep at %s", path)
	}
	c, warnings, err := LoadFile(path)
	if err != nil {
		return nil, warnings, fmt.Errorf("config %s: %w", path, err)
	}
	if c.Extend.Path != "" {
		base := c.Extend.Path
		if !filepath.IsAbs(base) {
			base = filepath.Join(filepath.Dir(path), base)
		}
		parent, w, err := loadWithExtends(base, depth+1)
		warnings = append(warnings, w...)
		if err != nil {
			return nil, warnings, err
		}
		ext := c.Extend
		c = merge(parent, c)
		c.Extend = ext
		c.Extend.DisabledRules = append(parent.Extend.DisabledRules, ext.DisabledRules...)
		if ext.UseDefault == nil {
			c.Extend.UseDefault = parent.Extend.UseDefault
		}
	}
	return c, warnings, nil
}

// merge returns base overlaid with top: rules with the same ID are replaced
// by top's version; allowlists accumulate.
func merge(base, top *Config) *Config {
	out := &Config{Title: top.Title, Description: top.Description, Extend: top.Extend, Remediation: base.Remediation}
	out.Policy = base.Policy
	if top.Policy != "" {
		out.Policy = top.Policy
	}
	if top.Remediation.Store != "" {
		out.Remediation.Store = top.Remediation.Store
	}
	if top.Remediation.Runbook != "" {
		out.Remediation.Runbook = top.Remediation.Runbook
	}
	if out.Title == "" {
		out.Title = base.Title
	}
	idx := map[string]int{}
	for _, r := range base.Rules {
		idx[r.ID] = len(out.Rules)
		out.Rules = append(out.Rules, r)
	}
	for _, r := range top.Rules {
		if i, ok := idx[r.ID]; ok {
			out.Rules[i] = r
			continue
		}
		idx[r.ID] = len(out.Rules)
		out.Rules = append(out.Rules, r)
	}
	for _, c := range []*Config{base, top} {
		if c.Allowlist != nil {
			out.Allowlists = append(out.Allowlists, *c.Allowlist)
		}
		out.Allowlists = append(out.Allowlists, c.Allowlists...)
	}
	return out
}

func filterRules(rules []Rule, enable, disable, tags []string) []Rule {
	en := toSet(enable)
	dis := toSet(disable)
	tg := toSet(tags)
	var out []Rule
	for _, r := range rules {
		if dis[r.ID] || (len(en) > 0 && !en[r.ID]) {
			continue
		}
		if len(tg) > 0 {
			hit := false
			for _, t := range r.Tags {
				if tg[t] {
					hit = true
				}
			}
			if !hit && !en[r.ID] {
				continue
			}
		}
		out = append(out, r)
	}
	return out
}

func toSet(xs []string) map[string]bool {
	m := map[string]bool{}
	for _, x := range xs {
		for _, p := range strings.Split(x, ",") {
			if p = strings.TrimSpace(p); p != "" {
				m[p] = true
			}
		}
	}
	return m
}

var patternIDRe = regexp.MustCompile(`^([A-Za-z0-9][A-Za-z0-9_.-]*)=(.+)$`)

// ParsePattern turns "id=regex" (or a bare regex) into a rule. An optional
// trailing ";entropy=3.5", ";severity=high", ";group=1" or ";keywords=a|b"
// suffix list may follow, separated by " ;; ".
func ParsePattern(spec string, n int) (Rule, error) {
	spec = strings.TrimSpace(spec)
	parts := strings.Split(spec, " ;; ")
	body := parts[0]
	r := Rule{Tags: []string{"custom"}}
	if m := patternIDRe.FindStringSubmatch(body); m != nil {
		r.ID, r.Regex = m[1], m[2]
	} else {
		r.ID, r.Regex = fmt.Sprintf("custom-pattern-%d", n), body
	}
	r.Description = "Custom pattern " + r.ID
	for _, opt := range parts[1:] {
		k, v, ok := strings.Cut(strings.TrimSpace(opt), "=")
		if !ok {
			return r, fmt.Errorf("pattern %s: bad option %q", r.ID, opt)
		}
		switch strings.ToLower(k) {
		case "entropy":
			if _, err := fmt.Sscanf(v, "%g", &r.Entropy); err != nil {
				return r, fmt.Errorf("pattern %s: bad entropy %q", r.ID, v)
			}
		case "group", "secretgroup":
			if _, err := fmt.Sscanf(v, "%d", &r.SecretGroup); err != nil {
				return r, fmt.Errorf("pattern %s: bad group %q", r.ID, v)
			}
		case "severity":
			r.Severity = v
		case "keywords":
			r.Keywords = strings.Split(v, "|")
		case "description":
			r.Description = v
		case "path":
			r.Path = v
		default:
			return r, fmt.Errorf("pattern %s: unknown option %q", r.ID, k)
		}
	}
	return r, nil
}

func readPatternsFile(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("patterns file: %w", err)
	}
	defer f.Close()
	var out []string
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		out = append(out, line)
	}
	return out, sc.Err()
}

// ---------------------------------------------------------------------------
// Compilation

// CompiledRule is a rule ready for matching.
type CompiledRule struct {
	Rule
	Re         *regexp.Regexp
	PathRe     *regexp.Regexp
	LowerKeys  []string
	Allowlists []*CompiledAllowlist
	Generic    bool // tagged "generic": yields to specific rules on overlap
	Multiline  bool // regex can span lines; widens keyword windows
	Bounded    bool // token rule: boundary chars are checked in code, not regex
	Semi       bool // keyword-context rule ("name = value" with a provider charset)
	Before     int  // keyword window radius before / after an occurrence
	After      int
	numGroups  int
}

// NumGroups is the number of capture groups in the rule's regex.
func (r *CompiledRule) NumGroups() int { return r.numGroups }

// CompiledAllowlist is an allowlist ready for evaluation.
type CompiledAllowlist struct {
	Description string
	And         bool
	Commits     map[string]bool
	Paths       []*regexp.Regexp
	Target      string
	Regexes     []*regexp.Regexp
	Stopwords   []string
	TargetRules map[string]bool
	TargetTags  map[string]bool
}

// Ruleset is a compiled config.
type Ruleset struct {
	Rules       []*CompiledRule
	Allowlists  []*CompiledAllowlist // global
	Remediation Remediation
	Policy      string
}

// Compile validates and compiles a resolved config.
func Compile(c *Config) (*Ruleset, error) {
	rs := &Ruleset{Remediation: c.Remediation, Policy: c.Policy}
	seen := map[string]bool{}
	var errs []string
	switch c.Policy {
	case "", "strict", "balanced":
	default:
		errs = append(errs, fmt.Sprintf("policy %q: want strict or balanced", c.Policy))
	}
	for _, r := range c.Rules {
		cr, err := compileRule(r)
		if err != nil {
			errs = append(errs, err.Error())
			continue
		}
		if seen[r.ID] {
			errs = append(errs, fmt.Sprintf("rule %q: duplicate id", r.ID))
			continue
		}
		seen[r.ID] = true
		rs.Rules = append(rs.Rules, cr)
	}
	for i, a := range c.Allowlists {
		ca, err := compileAllowlist(a, true)
		if err != nil {
			errs = append(errs, fmt.Sprintf("global allowlist #%d: %v", i+1, err))
			continue
		}
		rs.Allowlists = append(rs.Allowlists, ca)
	}
	if len(errs) > 0 {
		return nil, fmt.Errorf("config errors:\n  %s", strings.Join(errs, "\n  "))
	}
	// Specific rules first so generic rules can yield on overlap.
	sort.SliceStable(rs.Rules, func(i, j int) bool { return !rs.Rules[i].Generic && rs.Rules[j].Generic })
	return rs, nil
}

func compileRule(r Rule) (*CompiledRule, error) {
	if r.ID == "" {
		return nil, fmt.Errorf("rule with regex %q: missing id", r.Regex)
	}
	if r.Regex == "" && r.Path == "" {
		return nil, fmt.Errorf("rule %q: needs regex and/or path", r.ID)
	}
	if r.Severity == "" {
		r.Severity = "high"
	}
	r.Severity = strings.ToLower(r.Severity)
	if SeverityRank(r.Severity) < 0 {
		return nil, fmt.Errorf("rule %q: unknown severity %q", r.ID, r.Severity)
	}
	if r.Entropy < 0 || r.Entropy > 8 {
		return nil, fmt.Errorf("rule %q: entropy must be between 0 and 8", r.ID)
	}
	cr := &CompiledRule{Rule: r}
	var err error
	if r.Regex != "" {
		src := r.Regex
		// Token rules wrap the token in boundary groups; matching the bare
		// token keeps RE2's literal-prefix acceleration, and the detector
		// checks the boundaries itself.
		if strings.HasPrefix(src, TokPrefix) && strings.HasSuffix(src, TokSuffix) {
			src = src[len(TokPrefix)-1 : len(src)-len(TokSuffix)+1]
			cr.Bounded = true
		}
		cr.Before, cr.After = 256, 2048
		if strings.Contains(src, SemiMarker) {
			cr.Semi = true
			cr.Before, cr.After = 80, 1100
		}
		for _, t := range r.Tags {
			if t == "generic" {
				cr.Before, cr.After = 80, 300
			}
		}
		if cr.Re, err = regexp.Compile(src); err != nil {
			return nil, fmt.Errorf("rule %q: bad regex: %v", r.ID, err)
		}
		cr.numGroups = cr.Re.NumSubexp()
		cr.Multiline = strings.Contains(r.Regex, `[\s\S`) || strings.Contains(r.Regex, `(?s`)
		if len(r.Keywords) == 0 {
			// Derive a prefilter keyword from a literal prefix (e.g. "mytok_"),
			// so custom patterns stay fast without extra configuration.
			if p, _ := cr.Re.LiteralPrefix(); len(p) >= 3 {
				r.Keywords = []string{p}
				cr.Rule.Keywords = r.Keywords
			}
		}
		if r.SecretGroup > cr.numGroups {
			return nil, fmt.Errorf("rule %q: secretGroup %d but regex has %d groups", r.ID, r.SecretGroup, cr.numGroups)
		}
	}
	if r.Path != "" {
		if cr.PathRe, err = regexp.Compile(r.Path); err != nil {
			return nil, fmt.Errorf("rule %q: bad path regex: %v", r.ID, err)
		}
	}
	for _, k := range r.Keywords {
		if k = strings.ToLower(strings.TrimSpace(k)); k != "" {
			cr.LowerKeys = append(cr.LowerKeys, k)
		}
	}
	for _, t := range r.Tags {
		if t == "generic" {
			cr.Generic = true
		}
	}
	all := r.Allowlists
	if r.Allowlist != nil {
		all = append([]Allowlist{*r.Allowlist}, all...)
	}
	for i, a := range all {
		ca, err := compileAllowlist(a, false)
		if err != nil {
			return nil, fmt.Errorf("rule %q allowlist #%d: %v", r.ID, i+1, err)
		}
		cr.Allowlists = append(cr.Allowlists, ca)
	}
	return cr, nil
}

func compileAllowlist(a Allowlist, global bool) (*CompiledAllowlist, error) {
	ca := &CompiledAllowlist{Description: a.Description, Commits: map[string]bool{}, TargetRules: map[string]bool{}, TargetTags: map[string]bool{}}
	switch strings.ToUpper(strings.TrimSpace(a.Condition)) {
	case "", "OR":
	case "AND", "&&":
		ca.And = true
	default:
		return nil, fmt.Errorf("unknown condition %q", a.Condition)
	}
	switch t := strings.ToLower(a.RegexTarget); t {
	case "", "secret":
		ca.Target = "secret"
	case "match", "line", "prefix":
		ca.Target = t
	default:
		return nil, fmt.Errorf("unknown regexTarget %q", a.RegexTarget)
	}
	for _, c := range a.Commits {
		ca.Commits[strings.ToLower(c)] = true
	}
	for _, p := range a.Paths {
		re, err := regexp.Compile(p)
		if err != nil {
			return nil, fmt.Errorf("bad path regex %q: %v", p, err)
		}
		ca.Paths = append(ca.Paths, re)
	}
	for _, p := range a.Regexes {
		re, err := regexp.Compile(p)
		if err != nil {
			return nil, fmt.Errorf("bad regex %q: %v", p, err)
		}
		ca.Regexes = append(ca.Regexes, re)
	}
	for _, s := range a.Stopwords {
		ca.Stopwords = append(ca.Stopwords, strings.ToLower(s))
	}
	if len(a.TargetRules) > 0 && !global {
		return nil, fmt.Errorf("targetRules is only valid in global allowlists")
	}
	if len(a.TargetTags) > 0 && !global {
		return nil, fmt.Errorf("targetTags is only valid in global allowlists")
	}
	for _, t := range a.TargetTags {
		ca.TargetTags[t] = true
	}
	for _, t := range a.TargetRules {
		ca.TargetRules[t] = true
	}
	if len(ca.Commits)+len(ca.Paths)+len(ca.Regexes)+len(ca.Stopwords) == 0 {
		return nil, fmt.Errorf("allowlist has no criteria")
	}
	return ca, nil
}

// PathAllowed reports whether a path alone (no other criteria needed) is
// allowlisted, letting sources skip files cheaply.
func (a *CompiledAllowlist) PathAllowed(path string) bool {
	if len(a.TargetRules) > 0 || len(a.TargetTags) > 0 || len(a.Paths) == 0 {
		return false
	}
	if a.And && (len(a.Commits)+len(a.Regexes)+len(a.Stopwords) > 0) {
		return false
	}
	for _, re := range a.Paths {
		if re.MatchString(path) {
			return true
		}
	}
	return false
}

// Allowed evaluates the allowlist against a candidate finding.
func (a *CompiledAllowlist) Allowed(path, commit, secret, match, line string) bool {
	type check struct{ present, ok bool }
	checks := make([]check, 0, 4)
	if len(a.Commits) > 0 {
		ok := commit != "" && (a.Commits[strings.ToLower(commit)] || a.prefixCommit(commit))
		checks = append(checks, check{true, ok})
	}
	if len(a.Paths) > 0 {
		ok := false
		for _, re := range a.Paths {
			if re.MatchString(path) {
				ok = true
				break
			}
		}
		checks = append(checks, check{true, ok})
	}
	if len(a.Regexes) > 0 {
		target := secret
		switch a.Target {
		case "match":
			target = match
		case "line":
			target = line
		case "prefix": // the identifier/operator part of the match, before the secret
			target = match
			if i := strings.Index(match, secret); i >= 0 && secret != "" {
				target = match[:i]
			}
		}
		ok := false
		for _, re := range a.Regexes {
			if re.MatchString(target) {
				ok = true
				break
			}
		}
		checks = append(checks, check{true, ok})
	}
	if len(a.Stopwords) > 0 {
		ls := strings.ToLower(secret)
		ok := false
		for _, w := range a.Stopwords {
			if strings.Contains(ls, w) {
				ok = true
				break
			}
		}
		checks = append(checks, check{true, ok})
	}
	if a.And {
		for _, c := range checks {
			if !c.ok {
				return false
			}
		}
		return len(checks) > 0
	}
	for _, c := range checks {
		if c.ok {
			return true
		}
	}
	return false
}

func (a *CompiledAllowlist) prefixCommit(commit string) bool {
	lc := strings.ToLower(commit)
	for c := range a.Commits {
		if len(c) >= 7 && strings.HasPrefix(lc, c) {
			return true
		}
	}
	return false
}

// HasTag reports whether the rule carries tag t.
func (r *CompiledRule) HasTag(t string) bool {
	for _, x := range r.Tags {
		if x == t {
			return true
		}
	}
	return false
}

// AppliesTo reports whether a global allowlist is scoped to this rule.
func (a *CompiledAllowlist) AppliesTo(r *CompiledRule) bool {
	if len(a.TargetRules) > 0 && !a.TargetRules[r.ID] {
		return false
	}
	if len(a.TargetTags) > 0 {
		for _, t := range r.Tags {
			if a.TargetTags[t] {
				return true
			}
		}
		return false
	}
	return true
}
