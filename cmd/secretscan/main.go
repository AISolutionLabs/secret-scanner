// SPDX-License-Identifier: Apache-2.0

// Command secretscan finds hard-coded secrets in files, git history, staged
// changes, outgoing pushes and diffs.
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"sort"
	"strconv"
	"strings"
	"sync"
	"text/tabwriter"
	"time"

	"github.com/AISolutionLabs/secret-scanner/internal/config"
	"github.com/AISolutionLabs/secret-scanner/internal/detect"
	"github.com/AISolutionLabs/secret-scanner/internal/remediate"
	"github.com/AISolutionLabs/secret-scanner/internal/report"
	"github.com/AISolutionLabs/secret-scanner/internal/sources"
	"github.com/AISolutionLabs/secret-scanner/internal/triage"
	"github.com/AISolutionLabs/secret-scanner/internal/verify"
)

// version is set by -ldflags in release builds; otherwise it comes from the
// module version embedded by `go install ...@vX.Y.Z`.
var version = ""

func init() {
	if version != "" {
		return
	}
	version = "devel"
	if bi, ok := debug.ReadBuildInfo(); ok && bi.Main.Version != "" && bi.Main.Version != "(devel)" {
		version = bi.Main.Version
	}
}

const (
	exitOK    = 0
	exitError = 2
)

const usage = `secretscan - fast, configurable secret scanner

Usage:
  secretscan dir   [paths...]   scan files and directories (default: .)
  secretscan git   [repo]       scan git history (default: all refs)
        --staged                 only staged changes (pre-commit hook)
        --pre-push               only commits being pushed (reads hook stdin)
        --log-opts "<args>"      extra git log args, e.g. "--since=1.week main"
  secretscan stdin              scan stdin (--diff to parse a unified diff)
  secretscan explain <rule-id>  how to rotate, avoid and load a secret (--lang, --store)
  secretscan triage <report>    re-score a gitleaks / trufflehog / SARIF report (precision layer)
  secretscan rules              list active rules
  secretscan validate           check config, regexes and rule self-tests
  secretscan install-hook       install git hooks (--type pre-commit|pre-push|both)
  secretscan version

Run "secretscan <command> -h" for all options.
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(exitError)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	cmd, args := os.Args[1], os.Args[2:]
	var code int
	switch cmd {
	case "dir", "files", "fs":
		code = runScan(ctx, "dir", args)
	case "git", "detect":
		code = runScan(ctx, "git", args)
	case "stdin", "diff":
		if cmd == "diff" {
			args = append([]string{"--diff"}, args...)
		}
		code = runScan(ctx, "stdin", args)
	case "rules":
		code = runRules(args)
	case "explain":
		code = runExplain(args)
	case "triage":
		code = runTriage(args)
	case "validate":
		code = runValidate(args)
	case "install-hook", "install-hooks":
		code = runInstallHook(args)
	case "version", "--version", "-version":
		fmt.Println("secretscan", version)
	case "help", "-h", "--help":
		fmt.Print(usage)
	default:
		// Bare path: `secretscan .`
		if _, err := os.Stat(cmd); err == nil {
			code = runScan(ctx, "dir", os.Args[1:])
		} else {
			fmt.Fprintf(os.Stderr, "unknown command %q\n\n%s", cmd, usage)
			code = exitError
		}
	}
	os.Exit(code)
}

// ---------------------------------------------------------------------------
// Flags

type multi []string

func (m *multi) String() string     { return strings.Join(*m, ",") }
func (m *multi) Set(v string) error { *m = append(*m, v); return nil }

type redactFlag struct{ v *int }

func (r redactFlag) String() string {
	if r.v == nil {
		return "80"
	}
	return strconv.Itoa(*r.v)
}
func (r redactFlag) IsBoolFlag() bool { return true }
func (r redactFlag) Set(s string) error {
	switch s {
	case "true", "":
		*r.v = 100
	case "false":
		*r.v = 0
	default:
		n, err := strconv.Atoi(strings.TrimSuffix(s, "%"))
		if err != nil || n < 0 || n > 100 {
			return fmt.Errorf("redact must be 0-100")
		}
		*r.v = n
	}
	return nil
}

type common struct {
	cfg           config.Options
	configPath    string
	patterns      multi
	patternsFiles multi
	enable        multi
	disable       multi
	tags          multi
	exclude       multi
	ignoreFiles   multi
	baseline      string
	format        string
	reportPath    string
	redact        int
	exitCode      int
	minSeverity   string
	policy        string
	defaultPolicy string
	minConfidence string
	showSupp      bool
	maxMB         float64
	decodeDepth   int
	threads       int
	verify        bool
	onlyVerified  bool
	noColor       bool
	quiet         bool
	noDefaults    bool
	noInline      bool
	noFilters     bool
	secretStore   string
	remediation   string
	fixPatch      string
	fixInPlace    bool
	yes           bool
	followLinks   bool
	timeout       time.Duration

	// git
	staged  bool
	prePush bool
	remote  string
	logOpts string

	// stdin
	asDiff bool
	label  string
}

func bindCommon(fs *flag.FlagSet, c *common, mode string) {
	str := func(p *string, names []string, def, help string) {
		for _, n := range names {
			fs.StringVar(p, n, def, help)
		}
	}
	str(&c.configPath, []string{"c", "config"}, "", "config file (default: .secretscan.toml, .gitleaks.toml in scan root, or $SECRETSCAN_CONFIG)")
	fs.Var(&c.patterns, "pattern", `extra rule as "id=regex" (repeatable); options: "id=regex ;; entropy=3.5 ;; severity=high ;; group=1 ;; keywords=a|b"`)
	fs.Var(&c.patternsFiles, "patterns-file", "file with one pattern per line (same syntax as --pattern)")
	fs.BoolVar(&c.noDefaults, "no-default-rules", false, "do not load the built-in rule pack")
	fs.Var(&c.enable, "enable-rule", "only run these rule IDs (repeatable or comma-separated)")
	fs.Var(&c.disable, "disable-rule", "skip these rule IDs (repeatable or comma-separated)")
	fs.Var(&c.tags, "tag", "only run rules with these tags, e.g. aws,azure (repeatable)")
	fs.Var(&c.exclude, "exclude-path", "regex of paths to skip (repeatable)")
	fs.Var(&c.ignoreFiles, "ignore-file", "ignore file of fingerprints / sha256:<hash> / rule:<id>[:file] (default: .secretscanignore, .gitleaksignore)")
	str(&c.baseline, []string{"b", "baseline-path"}, "", "JSON report of accepted findings to ignore")
	str(&c.format, []string{"f", "report-format"}, "", "text|json|sarif|csv|junit|stats (default: text, or from --report-path extension)")
	str(&c.reportPath, []string{"r", "report-path"}, "", "write report to this file instead of stdout")
	c.redact = 80
	fs.Var(redactFlag{&c.redact}, "redact", "mask secrets in output: --redact (100%), --redact=N (percent hidden), --redact=0 to show (default 80)")
	fs.IntVar(&c.exitCode, "exit-code", 1, "exit code when secrets are found")
	fs.StringVar(&c.minSeverity, "min-severity", "low", "report and fail only at/above: info|low|medium|high|critical")
	fs.StringVar(&c.policy, "policy", "", "strict (every finding blocks; default) | balanced (high and medium confidence block; low-confidence findings are listed for review)")
	fs.StringVar(&c.defaultPolicy, "default-policy", "", "policy to use when neither --policy nor the config sets one (git hooks use balanced)")
	fs.StringVar(&c.minConfidence, "min-confidence", "low", "hide findings below this confidence: low|medium|high (hidden findings are still counted)")
	fs.BoolVar(&c.showSupp, "show-suppressed", false, "list every candidate removed by a filter or allowlist, with the reason")
	fs.Float64Var(&c.maxMB, "max-target-megabytes", 10, "skip files (or diff additions per file) larger than this; 0 = no limit")
	fs.IntVar(&c.decodeDepth, "max-decode-depth", 2, "recursively decode base64/hex/percent-encoded data this many levels; 0 = off")
	fs.IntVar(&c.threads, "threads", runtime.NumCPU(), "worker goroutines")
	fs.BoolVar(&c.verify, "verify", false, "check secrets against provider APIs (sends secrets over the network)")
	fs.BoolVar(&c.onlyVerified, "only-verified", false, "with --verify, report only verified-live secrets")
	fs.BoolVar(&c.noColor, "no-color", false, "disable ANSI colors (also NO_COLOR env)")
	for _, n := range []string{"q", "quiet"} {
		fs.BoolVar(&c.quiet, n, false, "print only the summary")
	}
	fs.BoolVar(&c.noInline, "no-inline-ignore", false, "ignore inline allow comments (audit mode)")
	fs.BoolVar(&c.noFilters, "no-noise-filters", false, "disable heuristic false-positive filters for generic rules (audit mode)")
	fs.StringVar(&c.secretStore, "secret-store", "", "store the fix guidance targets: env|vault|aws|azure|gcp (default from config [remediation] store, else env)")
	fs.StringVar(&c.remediation, "remediation", "short", "fix guidance in text output: short|full|none")
	fs.StringVar(&c.fixPatch, "fix-patch", "", "write a git-apply-able patch replacing hard-coded literals with env lookups (contains the old secrets: keep it outside the repo)")
	fs.BoolVar(&c.fixInPlace, "fix", false, "rewrite hard-coded literals into env lookups in place after showing the diff and asking (prefer --fix-patch to review first)")
	fs.BoolVar(&c.yes, "yes", false, "with --fix: apply without the interactive confirmation")
	fs.DurationVar(&c.timeout, "timeout", 0, "abort the scan after this long, e.g. 30s (0 = none)")
	switch mode {
	case "dir":
		fs.BoolVar(&c.followLinks, "follow-symlinks", false, "follow symbolic links")
	case "git":
		fs.BoolVar(&c.staged, "staged", false, "scan staged changes only (pre-commit)")
		fs.BoolVar(&c.prePush, "pre-push", false, "scan commits being pushed; reads pre-push hook stdin")
		fs.StringVar(&c.remote, "remote", "", "remote name for --pre-push (hook passes $1)")
		fs.StringVar(&c.logOpts, "log-opts", "", `extra "git log" arguments (default "--all")`)
	case "stdin":
		fs.BoolVar(&c.asDiff, "diff", false, "treat stdin as a unified diff and scan only added lines")
		fs.StringVar(&c.label, "label", "stdin", "file name to report for stdin content")
	}
}

// parseInterleaved lets flags appear before or after positional arguments.
func parseInterleaved(fs *flag.FlagSet, args []string) ([]string, error) {
	var pos []string
	for {
		if err := fs.Parse(args); err != nil {
			return nil, err
		}
		rest := fs.Args()
		if len(rest) == 0 {
			return pos, nil
		}
		pos = append(pos, rest[0])
		args = rest[1:]
	}
}

// ---------------------------------------------------------------------------
// Scan

func runScan(ctx context.Context, mode string, args []string) int {
	fs := flag.NewFlagSet("secretscan "+mode, flag.ContinueOnError)
	var c common
	bindCommon(fs, &c, mode)
	pos, err := parseInterleaved(fs, args)
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return exitOK
		}
		return exitError
	}
	if c.timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, c.timeout)
		defer cancel()
	}

	// Determine roots and config search dirs.
	var roots []string
	var searchDirs []string
	repo := "."
	switch mode {
	case "dir":
		roots = pos
		if len(roots) == 0 {
			roots = []string{"."}
		}
		for _, r := range roots {
			if fi, err := os.Stat(r); err == nil && fi.IsDir() {
				searchDirs = append(searchDirs, r)
			} else {
				searchDirs = append(searchDirs, filepath.Dir(r))
			}
		}
	case "git":
		if len(pos) > 0 {
			repo = pos[0]
		}
		top := gitTopLevel(repo)
		if top == "" {
			fmt.Fprintf(os.Stderr, "secretscan: %s is not a git repository\n", repo)
			return exitError
		}
		repo = top
		searchDirs = []string{top}
	case "stdin":
		searchDirs = []string{"."}
	}

	det, rs, code := buildDetector(c, searchDirs)
	if det == nil {
		return code
	}
	ignores := detect.NewIgnoreSet()
	ignorePaths := append([]string{}, c.ignoreFiles...)
	if len(ignorePaths) == 0 {
		for _, d := range searchDirs {
			ignorePaths = append(ignorePaths, filepath.Join(d, ".secretscanignore"), filepath.Join(d, ".gitleaksignore"))
		}
	}
	for _, p := range ignorePaths {
		if err := ignores.LoadIgnoreFile(p); err != nil {
			fmt.Fprintf(os.Stderr, "secretscan: ignore file %s: %v\n", p, err)
			return exitError
		}
	}
	if c.baseline != "" {
		if err := ignores.LoadBaseline(c.baseline); err != nil {
			fmt.Fprintf(os.Stderr, "secretscan: %v\n", err)
			return exitError
		}
	}

	// Worker pool.
	start := time.Now()
	frags := make(chan detect.Fragment, 256)
	var (
		mu       sync.Mutex
		findings []detect.Finding
		supCount = map[string]int{}
		supItems []detect.Suppressed
		nFrags   int
		nBytes   int64
		commits  = map[string]bool{}
		wg       sync.WaitGroup
	)
	threads := max(c.threads, 1)
	for i := 0; i < threads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for f := range frags {
				res := det.Scan(f)
				out := res.Findings
				mu.Lock()
				for k, v := range res.Counts {
					supCount[k] += v
				}
				supItems = append(supItems, res.Suppressed...)
				nFrags++
				nBytes += int64(len(f.Raw))
				if f.Commit != "" {
					commits[f.Commit] = true
				}
				findings = append(findings, out...)
				mu.Unlock()
			}
		}()
	}
	emit := func(f detect.Fragment) {
		select {
		case frags <- f:
		case <-ctx.Done():
		}
	}
	maxBytes := int64(c.maxMB * 1024 * 1024)

	var srcErr error
	var fileStats sources.Stats
	switch mode {
	case "dir":
		fileStats, srcErr = sources.Files(ctx, roots, sources.FileOptions{
			MaxBytes: maxBytes, FollowSymlinks: c.followLinks, Skip: det.SkipPath,
		}, emit)
	case "git":
		srcErr = sources.Git(ctx, sources.GitOptions{
			Repo: repo, LogOpts: strings.Fields(c.logOpts), Staged: c.staged, PrePush: c.prePush,
			Remote: c.remote, Stdin: os.Stdin, MaxBytes: maxBytes,
		}, emit)
	case "stdin":
		srcErr = sources.Reader(os.Stdin, c.label, c.asDiff, maxBytes, emit)
	}
	close(frags)
	wg.Wait()
	if srcErr == nil && ctx.Err() != nil {
		srcErr = ctx.Err()
	}
	if srcErr != nil {
		fmt.Fprintf(os.Stderr, "secretscan: %v\n", srcErr)
		return exitError
	}

	// Filter, dedupe, verify, redact.
	seen := map[string]bool{}
	var kept []detect.Finding
	for _, f := range findings {
		if ignores.Ignored(f) || !detect.MeetsSeverity(f, c.minSeverity) {
			continue
		}
		k := f.Fingerprint + "\x00" + f.SecretHash + "\x00" + strconv.Itoa(f.StartColumn)
		if seen[k] {
			continue
		}
		seen[k] = true
		kept = append(kept, f)
	}
	if c.verify && len(kept) > 0 {
		verify.New().Run(ctx, kept, 8)
		for i := range kept {
			switch kept[i].Verification {
			case verify.Verified: // proof beats every heuristic
				kept[i].Confidence = detect.High
				kept[i].Evidence = append(kept[i].Evidence, "verified live by the provider")
			case verify.Invalid:
				kept[i].Confidence = detect.Low
				kept[i].Evidence = append(kept[i].Evidence, "rejected by the provider (revoked or invalid)")
			}
		}
		if c.onlyVerified {
			var v []detect.Finding
			for _, f := range kept {
				if f.Verification == verify.Verified {
					v = append(v, f)
				}
			}
			kept = v
		}
	}
	// Confidence filter (hidden findings are counted, never silently dropped)
	// and policy: which findings block the commit / build.
	policy := resolvePolicy(c, rs)
	hidden := 0
	minConf := detect.ConfidenceRank(c.minConfidence)
	shown := kept[:0]
	for _, f := range kept {
		if detect.ConfidenceRank(f.Confidence) < minConf {
			hidden++
			continue
		}
		f.Blocking = detect.Blocks(policy, f.Confidence)
		shown = append(shown, f)
	}
	kept = shown
	// Fix guidance needs the raw secret and line, so it runs before redaction.
	store := c.secretStore
	if store == "" {
		store = rs.Remediation.Store
	}
	for i := range kept {
		f := &kept[i]
		g := remediate.For(remediate.Input{RuleID: f.RuleID, File: f.File, Line: f.Line, Secret: f.Secret,
			Verification: f.Verification, Store: store, Runbook: rs.Remediation.Runbook})
		f.Remediation = &g
	}
	var fixSummary string
	if c.fixPatch != "" || c.fixInPlace {
		root := ""
		switch {
		case mode == "dir" && len(roots) == 1:
			if fi, err := os.Stat(roots[0]); err == nil && fi.IsDir() {
				root = roots[0]
			}
		case mode == "git" && c.staged:
			root = repo
		}
		if root == "" {
			fmt.Fprintln(os.Stderr, "secretscan: --fix/--fix-patch need `dir <one directory>` or `git --staged`")
			return exitError
		}
		sum, err := applyFixes(c.fixPatch, c.fixInPlace, c.yes, root, kept)
		if err != nil {
			fmt.Fprintf(os.Stderr, "secretscan: %v\n", err)
			return exitError
		}
		fixSummary = sum
	}
	sort.SliceStable(kept, func(i, j int) bool {
		a, b := kept[i], kept[j]
		if (a.Verification == verify.Verified) != (b.Verification == verify.Verified) {
			return a.Verification == verify.Verified // live secrets first
		}
		if a.Blocking != b.Blocking {
			return a.Blocking // blocking before review
		}
		if a.File != b.File {
			return a.File < b.File
		}
		if a.StartLine != b.StartLine {
			return a.StartLine < b.StartLine
		}
		if a.Commit != b.Commit {
			return a.Commit < b.Commit
		}
		return a.RuleID < b.RuleID
	})
	for i := range kept {
		detect.Redact(&kept[i], c.redact)
	}

	// Output.
	format := c.format
	if format == "" && c.reportPath != "" {
		switch strings.ToLower(filepath.Ext(c.reportPath)) {
		case ".json":
			format = "json"
		case ".sarif":
			format = "sarif"
		case ".csv":
			format = "csv"
		case ".xml":
			format = "junit"
		}
	}
	if format == "" {
		format = "text"
	}
	color := !c.noColor && os.Getenv("NO_COLOR") == "" && isTerminal(os.Stdout)
	if c.reportPath != "" {
		out, err := createPrivate(c.reportPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "secretscan: %v\n", err)
			return exitError
		}
		werr := report.Write(out, format, kept, rs.Rules, version, report.Options{Remediation: c.remediation, Policy: policy, Explain: c.staged || c.prePush})
		if cerr := out.Close(); werr == nil {
			werr = cerr
		}
		if werr != nil {
			fmt.Fprintf(os.Stderr, "secretscan: %v\n", werr)
			return exitError
		}
		if !c.quiet && format != "text" {
			_ = report.Text(os.Stdout, kept, report.Options{Color: color, Remediation: c.remediation, Policy: policy, Explain: c.staged || c.prePush})
		}
	} else if !c.quiet || format != "text" {
		if err := report.Write(os.Stdout, format, kept, rs.Rules, version, report.Options{Color: color, Remediation: c.remediation, Policy: policy, Explain: c.staged || c.prePush}); err != nil {
			fmt.Fprintf(os.Stderr, "secretscan: %v\n", err)
			return exitError
		}
	}

	scope := fmt.Sprintf("%d fragments", nFrags)
	switch {
	case mode == "dir":
		scope = fmt.Sprintf("%d files", fileStats.Files)
	case mode == "git" && c.staged:
		scope = fmt.Sprintf("%d staged hunks", nFrags)
	case mode == "git":
		scope = fmt.Sprintf("%d commits", len(commits))
	}
	blocking := 0
	for _, f := range kept {
		if f.Blocking {
			blocking++
		}
	}
	fmt.Fprintf(os.Stderr, "secretscan: %s · scanned %s (%s) in %s\n",
		report.Summary(kept), scope, humanBytes(nBytes), time.Since(start).Round(time.Millisecond))
	if line := report.PolicyLine(kept, policy, hidden, supCount); line != "" {
		fmt.Fprintln(os.Stderr, line)
	}
	if c.showSupp {
		writeSuppressed(os.Stderr, supItems, c.redact)
	}

	fmt.Fprint(os.Stderr, fixSummary)
	if blocking > 0 {
		if c.staged || c.prePush {
			fmt.Fprint(os.Stderr, `
  Blocked. To fix:
    • move the value to your secret store and read it at runtime (see "code:" above;
      --fix-patch fix.diff writes the change for you)
    • rotate it if it was ever pushed or shared
    • false positive? add "secretscan:allow" in a comment on that line,
      or put the "ignore:" fingerprint in .secretscanignore
`)
		}
		return c.exitCode
	}
	return exitOK
}

// resolvePolicy: --policy, then the repo config, then --default-policy
// (set by git hooks), then strict.
func resolvePolicy(c common, rs *config.Ruleset) string {
	for _, p := range []string{c.policy, rs.Policy, c.defaultPolicy} {
		if p != "" {
			return p
		}
	}
	return "strict"
}

// writeSuppressed lists the ledger: every candidate a filter or allowlist
// removed, so a missing finding can always be explained.
func writeSuppressed(w io.Writer, items []detect.Suppressed, redactPct int) {
	if len(items) == 0 {
		fmt.Fprintln(w, "secretscan: no candidates were suppressed")
		return
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].File != items[j].File {
			return items[i].File < items[j].File
		}
		return items[i].StartLine < items[j].StartLine
	})
	fmt.Fprintf(w, "secretscan: %d suppressed candidate(s):\n", len(items))
	for _, it := range items {
		f := detect.Finding{Secret: it.Secret}
		detect.Redact(&f, redactPct)
		loc := fmt.Sprintf("%s:%d", it.File, it.StartLine)
		if it.Commit != "" {
			loc = it.Commit[:min(10, len(it.Commit))] + ":" + loc
		}
		fmt.Fprintf(w, "  %-40s %-24s %-28s %s\n", loc, it.RuleID, it.Reason, oneLineSecret(f.Secret))
	}
}

func oneLineSecret(s string) string {
	s = strings.ReplaceAll(s, "\n", `\n`)
	if len(s) > 60 {
		s = s[:60] + "…"
	}
	return s
}

func buildDetector(c common, searchDirs []string) (*detect.Detector, *config.Ruleset, int) {
	opts := config.Options{
		ConfigPath: c.configPath, NoDefaults: c.noDefaults, Patterns: c.patterns, PatternsFiles: c.patternsFiles,
		EnableRules: c.enable, DisableRules: c.disable, Tags: c.tags, ExcludePaths: c.exclude, SearchDirs: searchDirs,
	}
	cfg, warnings, err := config.Resolve(opts)
	for _, w := range warnings {
		fmt.Fprintf(os.Stderr, "secretscan: warning: %s\n", w)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "secretscan: %v\n", err)
		return nil, nil, exitError
	}
	rs, err := config.Compile(cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "secretscan: %v\n", err)
		return nil, nil, exitError
	}
	if config.SeverityRank(c.minSeverity) < 0 {
		fmt.Fprintf(os.Stderr, "secretscan: unknown --min-severity %q\n", c.minSeverity)
		return nil, nil, exitError
	}
	dopts := detect.Options{MaxDecodeDepth: c.decodeDepth, NoNoiseFilters: c.noFilters, RecordSuppressed: c.showSupp}
	for _, p := range []string{c.policy, c.defaultPolicy} {
		switch p {
		case "", "strict", "balanced":
		default:
			fmt.Fprintf(os.Stderr, "secretscan: unknown policy %q (want strict or balanced)\n", p)
			return nil, nil, exitError
		}
	}
	switch c.minConfidence {
	case "", "low", "medium", "high":
	default:
		fmt.Fprintf(os.Stderr, "secretscan: unknown --min-confidence %q (want low, medium or high)\n", c.minConfidence)
		return nil, nil, exitError
	}
	if c.noInline {
		dopts.IgnoreMarkers = []string{}
	}
	return detect.New(rs, dopts), rs, exitOK
}

func gitTopLevel(dir string) string {
	out, err := exec.Command("git", "-C", dir, "rev-parse", "--show-toplevel").Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

// interactive reports whether stdin is a real terminal (/dev/null is also a
// character device, so it is excluded explicitly).
func interactive() bool {
	if !isTerminal(os.Stdin) {
		return false
	}
	in, err1 := os.Stdin.Stat()
	null, err2 := os.Stat(os.DevNull)
	return err1 == nil && (err2 != nil || !os.SameFile(in, null))
}

func isTerminal(f *os.File) bool {
	fi, err := f.Stat()
	return err == nil && fi.Mode()&os.ModeCharDevice != 0
}

func humanBytes(n int64) string {
	switch {
	case n >= 1<<30:
		return fmt.Sprintf("%.1f GB", float64(n)/(1<<30))
	case n >= 1<<20:
		return fmt.Sprintf("%.1f MB", float64(n)/(1<<20))
	case n >= 1<<10:
		return fmt.Sprintf("%.1f KB", float64(n)/(1<<10))
	}
	return fmt.Sprintf("%d B", n)
}

// ---------------------------------------------------------------------------
// rules / validate

func configOnlyFlags(name string) (*flag.FlagSet, *common) {
	fs := flag.NewFlagSet("secretscan "+name, flag.ContinueOnError)
	c := &common{}
	bindCommon(fs, c, name)
	return fs, c
}

func runRules(args []string) int {
	fs, c := configOnlyFlags("rules")
	pos, err := parseInterleaved(fs, args)
	if err != nil {
		return exitError
	}
	dirs := pos
	if len(dirs) == 0 {
		dirs = []string{"."}
	}
	_, rs, code := buildDetector(*c, dirs)
	if rs == nil {
		return code
	}
	if c.format == "json" {
		var out []config.Rule
		for _, r := range rs.Rules {
			out = append(out, r.Rule)
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(out)
		return exitOK
	}
	tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "ID\tSEVERITY\tTAGS\tDESCRIPTION")
	for _, r := range rs.Rules {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", r.ID, r.Severity, strings.Join(r.Tags, ","), r.Description)
	}
	_ = tw.Flush()
	fmt.Fprintf(os.Stderr, "%d rules, %d global allowlists\n", len(rs.Rules), len(rs.Allowlists))
	return exitOK
}

func runValidate(args []string) int {
	fs, c := configOnlyFlags("validate")
	pos, err := parseInterleaved(fs, args)
	if err != nil {
		return exitError
	}
	dirs := pos
	if len(dirs) == 0 {
		dirs = []string{"."}
	}
	det, rs, code := buildDetector(*c, dirs)
	if det == nil {
		return code
	}
	// Self-tests check the regex, entropy and allowlists, not the rule's
	// path filter, so examples don't need a matching file name.
	test := &config.Ruleset{Allowlists: rs.Allowlists}
	for _, r := range rs.Rules {
		cp := *r
		if cp.Re != nil {
			cp.PathRe = nil
		}
		test.Rules = append(test.Rules, &cp)
	}
	det = detect.New(test, detect.Options{MaxDecodeDepth: c.decodeDepth})
	failures, tests := 0, 0
	for _, r := range rs.Rules {
		path := "example.txt"
		for _, ex := range r.Examples {
			tests++
			if !ruleFires(det, r.ID, ex, path) {
				failures++
				fmt.Printf("FAIL %s: example did not match: %q\n", r.ID, ex)
			}
		}
		for _, neg := range r.Negatives {
			tests++
			if ruleFires(det, r.ID, neg, path) {
				failures++
				fmt.Printf("FAIL %s: negative matched: %q\n", r.ID, neg)
			}
		}
	}
	fmt.Printf("config OK: %d rules compiled, %d global allowlists, %d self-tests, %d failures\n",
		len(rs.Rules), len(rs.Allowlists), tests, failures)
	if failures > 0 {
		return 1
	}
	return exitOK
}

func ruleFires(det *detect.Detector, id, text, path string) bool {
	for _, f := range det.Detect(detect.Fragment{Raw: text, FilePath: path, StartLine: 1}) {
		if f.RuleID == id {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// install-hook

const hookMarker = "# managed-by: secretscan"

func hookScript(kind, bin, policy string) string {
	// An explicit --policy at install time wins over the repo config;
	// otherwise the repo config decides, falling back to balanced.
	pflag := " --default-policy balanced"
	if policy != "" {
		pflag = " --policy " + policy
	}
	locate := fmt.Sprintf(`DEFAULT_BIN=%s
SECRETSCAN_BIN="${SECRETSCAN_BIN:-$DEFAULT_BIN}"
[ -x "$SECRETSCAN_BIN" ] || SECRETSCAN_BIN="$(command -v secretscan 2>/dev/null)"
SKIP_SCAN=
if [ -n "$SECRETSCAN_SKIP" ]; then
  echo "secretscan: SECRETSCAN_SKIP is set; secret scan bypassed" >&2
  SKIP_SCAN=1
elif [ -z "$SECRETSCAN_BIN" ]; then
  echo "secretscan: binary not found (install it or set SECRETSCAN_BIN)" >&2
  [ -n "$SECRETSCAN_OPTIONAL" ] || exit 1
  SKIP_SCAN=1
fi
`, shellQuote(bin))
	switch kind {
	case "pre-push":
		return "#!/bin/sh\n" + hookMarker + "\n" + locate + `refs="$(cat)"
if [ -z "$SKIP_SCAN" ]; then
  printf '%s\n' "$refs" | "$SECRETSCAN_BIN" git --pre-push --remote "$1"` + pflag + ` || exit $?
fi
if [ -x "$0.local" ]; then printf '%s\n' "$refs" | "$0.local" "$@"; exit $?; fi
exit 0
`
	default:
		return "#!/bin/sh\n" + hookMarker + "\n" + locate + `if [ -z "$SKIP_SCAN" ]; then
  "$SECRETSCAN_BIN" git --staged` + pflag + ` || exit $?
fi
if [ -x "$0.local" ]; then exec "$0.local" "$@"; fi
exit 0
`
	}
}

func shellQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }

func runInstallHook(args []string) int {
	fs := flag.NewFlagSet("secretscan install-hook", flag.ContinueOnError)
	kind := fs.String("type", "pre-commit", "pre-commit | pre-push | both")
	hookPolicy := fs.String("policy", "", "strict | balanced (default: the repo config's policy, else balanced)")
	repo := fs.String("repo", ".", "repository")
	pos, err := parseInterleaved(fs, args)
	if err != nil {
		return exitError
	}
	if len(pos) > 0 {
		*repo = pos[0]
	}
	if *hookPolicy != "" && *hookPolicy != "strict" && *hookPolicy != "balanced" {
		fmt.Fprintf(os.Stderr, "secretscan: unknown --policy %q (want strict or balanced)\n", *hookPolicy)
		return exitError
	}
	out, err := exec.Command("git", "-C", *repo, "rev-parse", "--git-path", "hooks").Output()
	if err != nil {
		fmt.Fprintf(os.Stderr, "secretscan: %s is not a git repository\n", *repo)
		return exitError
	}
	hooksDir := strings.TrimSpace(string(out))
	if !filepath.IsAbs(hooksDir) {
		hooksDir = filepath.Join(*repo, hooksDir)
	}
	if err := os.MkdirAll(hooksDir, 0o755); err != nil {
		fmt.Fprintf(os.Stderr, "secretscan: %v\n", err)
		return exitError
	}
	bin, _ := os.Executable()
	kinds := []string{*kind}
	if *kind == "both" {
		kinds = []string{"pre-commit", "pre-push"}
	}
	for _, k := range kinds {
		if k != "pre-commit" && k != "pre-push" {
			fmt.Fprintf(os.Stderr, "secretscan: unknown hook type %q\n", k)
			return exitError
		}
		path := filepath.Join(hooksDir, k)
		if existing, err := os.ReadFile(path); err == nil && !strings.Contains(string(existing), hookMarker) {
			if err := os.Rename(path, path+".local"); err != nil {
				fmt.Fprintf(os.Stderr, "secretscan: %v\n", err)
				return exitError
			}
			fmt.Printf("existing %s hook kept as %s.local and chained after the scan\n", k, k)
		}
		if err := os.WriteFile(path, []byte(hookScript(k, bin, *hookPolicy)), 0o755); err != nil {
			fmt.Fprintf(os.Stderr, "secretscan: %v\n", err)
			return exitError
		}
		fmt.Printf("installed %s hook at %s\n", k, path)
	}
	switch *hookPolicy {
	case "strict":
		fmt.Print(`
policy: strict. Every finding blocks the commit/push, including medium- and
low-confidence generic matches. Expect more interruptions; use for
security-sensitive repositories.
`)
	default:
		fmt.Print(`
policy: balanced (unless .secretscan.toml sets one). High- and medium-confidence
findings block. Low-confidence findings (weak evidence, and generic values in
test/example files, which are usually fixtures) are printed under
"Needs review" and do NOT block. On CredData (337 real repositories, labeled
independently) balanced blocks 17.5% of labeled secrets at 88% precision and
lists most of the rest, which are test fixtures, for review; strict blocks 68%
at 85% precision. Run CI with the default strict policy, or reinstall with
--policy strict to block everything locally.
`)
	}
	return exitOK
}

// applyFixes builds the literal replacements and writes them as a patch
// file, in place, or both. It returns a summary for stderr.
func applyFixes(patchPath string, inPlace, yes bool, root string, fs []detect.Finding) (string, error) {
	seen := map[string]bool{}
	var items []remediate.PatchItem
	for _, f := range fs {
		if f.Commit != "" || f.Decoded != "" || f.StartLine == 0 || strings.Contains(f.Secret, "\n") || f.Remediation == nil {
			continue
		}
		k := fmt.Sprintf("%s:%d:%s", f.File, f.StartLine, f.SecretHash)
		if seen[k] {
			continue
		}
		seen[k] = true
		items = append(items, remediate.PatchItem{File: f.File, Line: f.StartLine, Secret: f.Secret, EnvVar: f.Remediation.EnvVar})
	}
	res := remediate.BuildPatch(root, items)
	var b strings.Builder
	if patchPath != "" {
		// The diff's "-" lines contain the original secrets.
		if err := writePrivate(patchPath, []byte(res.Diff)); err != nil {
			return "", err
		}
		fmt.Fprintf(&b, "secretscan: fix patch: %d literal(s) -> %s (apply from %s: git apply %s)\n", len(res.Patched), patchPath, root, patchPath)
		if abs, err := filepath.Abs(patchPath); err == nil {
			if r, err := filepath.Abs(root); err == nil && strings.HasPrefix(abs, r+string(filepath.Separator)) {
				fmt.Fprintf(&b, "  warning: %s is inside the scanned tree and contains the old secrets; delete it after applying (or use --fix)\n", patchPath)
			}
		}
	}
	if inPlace && len(res.Files) > 0 && !yes {
		if !interactive() {
			return "", fmt.Errorf("refusing to rewrite %d file(s) without review: use --fix-patch FILE to review the change, or --fix --yes", len(res.Files))
		}
		fmt.Fprintf(os.Stderr, "%s\nApply these changes to %d file(s)? [y/N] ", res.Diff, len(res.Files))
		ans, _ := bufio.NewReader(os.Stdin).ReadString('\n')
		if a := strings.ToLower(strings.TrimSpace(ans)); a != "y" && a != "yes" {
			b.WriteString("secretscan: --fix cancelled; no files changed\n")
			inPlace = false
		}
	}
	if inPlace {
		for file, content := range res.Files {
			p := filepath.Join(root, file)
			info, err := os.Stat(p)
			if err != nil {
				return "", err
			}
			if err := os.WriteFile(p, []byte(content), info.Mode().Perm()); err != nil {
				return "", err
			}
		}
		fmt.Fprintf(&b, "secretscan: fixed %d literal(s) in %d file(s) in place\n", len(res.Patched), len(res.Files))
	}
	if len(res.EnvVars) > 0 {
		fmt.Fprintf(&b, "  provide at runtime from your secret store: %s\n", strings.Join(res.EnvVars, ", "))
	}
	for _, s := range res.Skipped {
		fmt.Fprintf(&b, "  manual: %s\n", s)
	}
	for _, l := range res.Langs {
		if cv := remediate.Caveats[l]; cv != "" {
			fmt.Fprintf(&b, "  note (%s): %s\n", l, cv)
		}
	}
	if len(res.Unchecked) > 0 {
		fmt.Fprintf(&b, "  review by hand (no syntax check available): %s\n", strings.Join(res.Unchecked, ", "))
	}
	b.WriteString("  this only changes the code: rotate the credentials too (they remain in git history and anywhere they were copied)\n")
	return b.String(), nil
}

// runExplain prints rotation, keyless alternatives and loading code for a rule.
func runExplain(args []string) int {
	fs := flag.NewFlagSet("secretscan explain", flag.ContinueOnError)
	lang := fs.String("lang", "", "language: "+strings.Join(remediate.Languages(), ", ")+" (or all)")
	store := fs.String("store", "", "secret store: "+strings.Join(remediate.Stores, ", ")+" (or all)")
	env := fs.String("env", "", "variable / secret name to use in snippets")
	cfgPath := fs.String("config", "", "config file (for [remediation] defaults and custom rules)")
	pos, err := parseInterleaved(fs, args)
	if err != nil {
		return exitError
	}
	if len(pos) != 1 {
		fmt.Fprintln(os.Stderr, "usage: secretscan explain <rule-id> [--lang python] [--store azure] [--env NAME]")
		return exitError
	}
	ruleID := pos[0]
	cfg, _, err := config.Resolve(config.Options{ConfigPath: *cfgPath, SearchDirs: []string{"."}})
	if err != nil {
		fmt.Fprintf(os.Stderr, "secretscan: %v\n", err)
		return exitError
	}
	var desc string
	for _, r := range cfg.Rules {
		if r.ID == ruleID {
			desc = r.Description
		}
	}
	if desc == "" {
		fmt.Fprintf(os.Stderr, "secretscan: unknown rule %q (see: secretscan rules)\n", ruleID)
		return exitError
	}
	st := *store
	if st == "" {
		st = cfg.Remediation.Store
	}
	fam := remediate.FamilyFor(ruleID)
	g := remediate.For(remediate.Input{RuleID: ruleID, Store: st, Runbook: cfg.Remediation.Runbook})
	name := g.EnvVar
	if *env != "" {
		name = *env
	}
	fmt.Printf("%s  (%s)\n\n", desc, fam.Name)
	fmt.Printf("1. Rotate\n   %s\n\n", fam.Rotate)
	if fam.Eliminate != "" {
		fmt.Printf("2. Remove the need for a static secret\n   %s\n\n", fam.Eliminate)
	}
	fmt.Printf("3. Load it at runtime as %s\n", name)
	fmt.Println("   Read once at startup (or cache with a TTL shorter than rotation), share one client,")
	fmt.Println("   refetch once on 401, never log it. Files from Vault Agent/CSI reload without restarts.")
	if g.Runbook != "" {
		fmt.Printf("\n   Runbook: %s\n", g.Runbook)
	}
	langs := []string{*lang}
	if *lang == "" || *lang == "all" {
		langs = remediate.Languages()
		if *lang == "" {
			langs = []string{"python", "go", "javascript", "java", "csharp", "kubernetes"}
		}
	}
	stores := []string{st}
	if st == "all" {
		stores = remediate.Stores
	}
	for _, l := range langs {
		for _, s := range stores {
			snip, ok := remediate.Snippet(l, s, name)
			if !ok {
				fmt.Fprintf(os.Stderr, "secretscan: no snippets for language %q\n", l)
				return exitError
			}
			label := s
			if label == "" {
				label = "env"
			}
			fmt.Printf("\n--- %s (%s) ---\n%s", l, label, snip)
		}
	}
	return exitOK
}

// runTriage re-scores another scanner's findings with secretscan's context
// analysis. Filtered findings are listed with their reason, never dropped.
// createPrivate opens a file for secrets-bearing output with mode 0600. An
// existing file keeps its mode under O_CREATE, so it is tightened explicitly
// before anything is written.
func createPrivate(path string) (*os.File, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, err
	}
	if err := f.Chmod(0o600); err != nil && runtime.GOOS != "windows" {
		f.Close()
		return nil, fmt.Errorf("cannot restrict permissions of %s: %w", path, err)
	}
	if err := f.Truncate(0); err != nil {
		f.Close()
		return nil, err
	}
	return f, nil
}

func writePrivate(path string, b []byte) error {
	f, err := createPrivate(path)
	if err != nil {
		return err
	}
	if _, err := f.Write(b); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

func runTriage(args []string) int {
	fs := flag.NewFlagSet("secretscan triage", flag.ContinueOnError)
	var c common
	bindCommon(fs, &c, "triage")
	root := fs.String("root", ".", "directory (or git repository) the report's paths are relative to; files outside it are never read")
	deleteInput := fs.Bool("delete-input", false, "delete the report file after reading it (even if triage fails)")
	pos, err := parseInterleaved(fs, args)
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return exitOK
		}
		return exitError
	}
	if len(pos) != 1 {
		fmt.Fprintln(os.Stderr, "usage: secretscan triage <gitleaks.json | trufflehog.jsonl | report.sarif | -> [--root DIR] [--policy balanced]")
		return exitError
	}
	var data []byte
	if pos[0] == "-" {
		data, err = io.ReadAll(os.Stdin)
	} else {
		if *deleteInput {
			defer func() {
				if rerr := os.Remove(pos[0]); rerr == nil {
					fmt.Fprintf(os.Stderr, "secretscan: deleted %s\n", pos[0])
				}
			}()
		}
		if fi, serr := os.Stat(pos[0]); serr == nil && fi.Mode().Perm()&0o077 != 0 {
			fmt.Fprintf(os.Stderr, "secretscan: warning: %s is readable by other users (mode %v)\n", pos[0], fi.Mode().Perm())
		}
		data, err = os.ReadFile(pos[0])
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "secretscan: %v\n", err)
		return exitError
	}
	kind, inputs, err := triage.Parse(data)
	if err != nil {
		fmt.Fprintf(os.Stderr, "secretscan: %v\n", err)
		return exitError
	}
	if pos[0] != "-" && !*deleteInput {
		unredacted := 0
		for _, in := range inputs {
			if !in.Redacted && in.Secret != "" {
				unredacted++
			}
		}
		if unredacted > 0 {
			fmt.Fprintf(os.Stderr, "secretscan: warning: %s contains %d unredacted secret(s) on disk. Prefer piping "+
				"(gitleaks ... -f json -r - | secretscan triage -), a partially redacted report (gitleaks --redact=50), or --delete-input\n",
				pos[0], unredacted)
		}
	}
	c.showSupp = true // the triager needs the suppression ledger
	det, rs, code := buildDetector(c, []string{*root})
	if det == nil {
		return code
	}
	policy := resolvePolicy(c, rs)
	tr := triage.New(det, *root)
	var kept, filtered []detect.Finding
	counts := map[string]int{}
	// Group by source so the triager keeps only one file in memory at a time.
	sort.SliceStable(inputs, func(i, j int) bool {
		if inputs[i].Commit != inputs[j].Commit {
			return inputs[i].Commit < inputs[j].Commit
		}
		return inputs[i].File < inputs[j].File
	})
	for _, in := range inputs {
		f := tr.Evaluate(in)
		status := f.Triage
		if i := strings.Index(status, ":"); i > 0 {
			status = status[:i]
		}
		counts[status]++
		if status == triage.Filtered {
			filtered = append(filtered, f)
			continue
		}
		f.Blocking = detect.Blocks(policy, f.Confidence)
		kept = append(kept, f)
	}
	sort.SliceStable(kept, func(i, j int) bool { return kept[i].Blocking && !kept[j].Blocking })
	all := append(append([]detect.Finding{}, kept...), filtered...)
	for i := range all {
		detect.Redact(&all[i], c.redact)
	}
	kept, filtered = all[:len(kept)], all[len(kept):]

	format := strings.ToLower(c.format)
	color := !c.noColor && os.Getenv("NO_COLOR") == "" && isTerminal(os.Stdout)
	out := io.Writer(os.Stdout)
	if c.reportPath != "" {
		fh, err := createPrivate(c.reportPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "secretscan: %v\n", err)
			return exitError
		}
		defer fh.Close()
		out, color = fh, false
		if format == "" {
			format = strings.TrimPrefix(strings.ToLower(filepath.Ext(c.reportPath)), ".")
		}
	}
	switch format {
	case "", "text":
		if !c.quiet {
			_ = report.Text(out, kept, report.Options{Color: color, Remediation: "none", Policy: policy})
			if len(filtered) > 0 {
				fmt.Fprintf(out, "── Filtered as noise (%d; not blocking) ──\n", len(filtered))
				for _, f := range filtered {
					fmt.Fprintf(out, "  %s:%d  %s  %s  %s\n", f.File, f.StartLine, f.RuleID, strings.TrimPrefix(f.Triage, "filtered: "), oneLineSecret(f.Secret))
				}
			}
		}
	case "json", "sarif":
		if err := report.Write(out, format, all, rs.Rules, version, report.Options{Policy: policy}); err != nil {
			fmt.Fprintf(os.Stderr, "secretscan: %v\n", err)
			return exitError
		}
	default:
		fmt.Fprintf(os.Stderr, "secretscan: triage supports text, json and sarif output\n")
		return exitError
	}
	blocking := 0
	for _, f := range kept {
		if f.Blocking {
			blocking++
		}
	}
	fmt.Fprintf(os.Stderr, "secretscan triage (%s, %d findings): %d confirmed, %d verified, %d uncorroborated, %d filtered as noise · policy %s: %d blocking\n",
		kind, len(inputs), counts[triage.Confirmed], counts[triage.Verified], counts[triage.Uncorroborated], counts[triage.Filtered], policy, blocking)
	if blocking > 0 {
		return c.exitCode
	}
	return exitOK
}
