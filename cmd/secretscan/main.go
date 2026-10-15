// Command secretscan finds hard-coded secrets in files, git history, staged
// changes, outgoing pushes and diffs.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"text/tabwriter"
	"time"

	"github.com/anirudh/secretscan/internal/config"
	"github.com/anirudh/secretscan/internal/detect"
	"github.com/anirudh/secretscan/internal/report"
	"github.com/anirudh/secretscan/internal/sources"
	"github.com/anirudh/secretscan/internal/verify"
)

var version = "1.0.0"

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
	str(&c.format, []string{"f", "report-format"}, "", "text|json|sarif|csv|junit (default: text, or from --report-path extension)")
	str(&c.reportPath, []string{"r", "report-path"}, "", "write report to this file instead of stdout")
	c.redact = 80
	fs.Var(redactFlag{&c.redact}, "redact", "mask secrets in output: --redact (100%), --redact=N (percent hidden), --redact=0 to show (default 80)")
	fs.IntVar(&c.exitCode, "exit-code", 1, "exit code when secrets are found")
	fs.StringVar(&c.minSeverity, "min-severity", "low", "report and fail only at/above: info|low|medium|high|critical")
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
				out := det.Detect(f)
				mu.Lock()
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
	sort.SliceStable(kept, func(i, j int) bool {
		a, b := kept[i], kept[j]
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
		out, err := os.OpenFile(c.reportPath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
		if err != nil {
			fmt.Fprintf(os.Stderr, "secretscan: %v\n", err)
			return exitError
		}
		werr := report.Write(out, format, kept, rs.Rules, version, false)
		if cerr := out.Close(); werr == nil {
			werr = cerr
		}
		if werr != nil {
			fmt.Fprintf(os.Stderr, "secretscan: %v\n", werr)
			return exitError
		}
		if !c.quiet && format != "text" {
			_ = report.Text(os.Stdout, kept, color)
		}
	} else if !c.quiet || format != "text" {
		if err := report.Write(os.Stdout, format, kept, rs.Rules, version, color); err != nil {
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
	fmt.Fprintf(os.Stderr, "secretscan: %s · scanned %s (%s) in %s\n",
		report.Summary(kept), scope, humanBytes(nBytes), time.Since(start).Round(time.Millisecond))

	if len(kept) > 0 {
		if c.staged || c.prePush {
			fmt.Fprint(os.Stderr, `
  Blocked. To fix:
    • remove the secret and rotate it if it was ever pushed or shared
    • false positive? add "secretscan:allow" in a comment on that line,
      or put the "ignore:" fingerprint in .secretscanignore
`)
		}
		return c.exitCode
	}
	return exitOK
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
	dopts := detect.Options{MaxDecodeDepth: c.decodeDepth, NoNoiseFilters: c.noFilters}
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

func hookScript(kind, bin string) string {
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
  printf '%s\n' "$refs" | "$SECRETSCAN_BIN" git --pre-push --remote "$1" || exit $?
fi
if [ -x "$0.local" ]; then printf '%s\n' "$refs" | "$0.local" "$@"; exit $?; fi
exit 0
`
	default:
		return "#!/bin/sh\n" + hookMarker + "\n" + locate + `if [ -z "$SKIP_SCAN" ]; then
  "$SECRETSCAN_BIN" git --staged || exit $?
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
	repo := fs.String("repo", ".", "repository")
	pos, err := parseInterleaved(fs, args)
	if err != nil {
		return exitError
	}
	if len(pos) > 0 {
		*repo = pos[0]
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
		if err := os.WriteFile(path, []byte(hookScript(k, bin)), 0o755); err != nil {
			fmt.Fprintf(os.Stderr, "secretscan: %v\n", err)
			return exitError
		}
		fmt.Printf("installed %s hook at %s\n", k, path)
	}
	return exitOK
}
