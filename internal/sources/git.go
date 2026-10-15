package sources

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"os/exec"
	"strings"
	"sync"

	"github.com/AISolutionLabs/secret-scanner/internal/detect"
)

const zeroSHA = "0000000000000000000000000000000000000000"

// GitOptions selects what part of a repository to scan.
type GitOptions struct {
	Repo     string
	LogOpts  []string  // extra `git log` args, e.g. "--since=2024-01-01" or "main~10..main"
	Staged   bool      // scan only the staged diff (pre-commit)
	PrePush  bool      // read pre-push refs from Stdin and scan only outgoing commits
	Remote   string    // remote name passed to the pre-push hook ($1)
	Stdin    io.Reader // pre-push ref lines
	MaxBytes int64     // skip files whose added content in a diff exceeds this
}

// Git streams fragments from a repository.
func Git(ctx context.Context, o GitOptions, emit func(detect.Fragment)) error {
	if o.Repo == "" {
		o.Repo = "."
	}
	switch {
	case o.Staged:
		return runDiff(ctx, o, emit, "diff", "--cached", "-U0", "--no-color", "--no-ext-diff", "--no-renames", "--diff-filter=d")
	case o.PrePush:
		return prePush(ctx, o, emit)
	default:
		opts := o.LogOpts
		if len(opts) == 0 {
			opts = []string{"--all"}
		}
		args := append([]string{"log", "-p", "-U0", "--no-color", "--no-ext-diff", "--full-history", GitLogFormat}, opts...)
		return runDiff(ctx, o, emit, args...)
	}
}

func runDiff(ctx context.Context, o GitOptions, emit func(detect.Fragment), args ...string) error {
	full := append([]string{"-C", o.Repo, "-c", "core.quotepath=off", "-c", "diff.noprefix=false"}, args...)
	cmd := exec.CommandContext(ctx, "git", full...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("git: %w", err)
	}
	perr := ParseDiff(out, o.MaxBytes, emit)
	_, _ = io.Copy(io.Discard, out)
	werr := cmd.Wait()
	if perr != nil {
		return perr
	}
	if werr != nil {
		msg := strings.TrimSpace(stderr.String())
		if strings.Contains(msg, "does not have any commits yet") || strings.Contains(msg, "bad default revision 'HEAD'") {
			return nil
		}
		return fmt.Errorf("git %s: %v: %s", args[0], werr, msg)
	}
	return nil
}

// prePush handles the hook's stdin: "<local ref> <local sha> <remote ref> <remote sha>".
func prePush(ctx context.Context, o GitOptions, emit func(detect.Fragment)) error {
	if o.Stdin == nil {
		return fmt.Errorf("pre-push: no ref list on stdin")
	}
	var mu sync.Mutex
	seen := map[string]bool{}
	dedup := func(f detect.Fragment) {
		mu.Lock()
		defer mu.Unlock()
		key := f.Commit + "\x00" + f.FilePath + "\x00" + fmt.Sprint(f.StartLine)
		if seen[key] {
			return
		}
		seen[key] = true
		emit(f)
	}
	sc := bufio.NewScanner(o.Stdin)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) != 4 {
			continue
		}
		localSHA, remoteSHA := fields[1], fields[3]
		if strings.Trim(localSHA, "0") == "" {
			continue // branch deletion
		}
		var rng []string
		if strings.Trim(remoteSHA, "0") == "" {
			// New branch: everything not already on the remote.
			rng = []string{localSHA, "--not"}
			if o.Remote != "" {
				rng = append(rng, "--remotes="+o.Remote)
			} else {
				rng = append(rng, "--remotes")
			}
		} else {
			rng = []string{remoteSHA + ".." + localSHA}
		}
		args := append([]string{"log", "-p", "-U0", "--no-color", "--no-ext-diff", "--full-history", GitLogFormat}, rng...)
		args = append(args, o.LogOpts...)
		if err := runDiff(ctx, o, dedup, args...); err != nil {
			return err
		}
	}
	return sc.Err()
}
