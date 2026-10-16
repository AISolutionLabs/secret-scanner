# Audit: triage, automatic fixes and verification (2026-10-15)

A code-level re-audit of the parts of secretscan that read untrusted input
(other tools' reports), write secrets to disk, edit source code, or send
secrets over the network. Every finding below has a regression test that fails
without the fix.

## Findings fixed

| # | Area | Problem | Fix | Test |
|---|---|---|---|---|
| 1 | triage | With `--root` on a subdirectory, a history finding was read with `git show <commit>:<path>`, which resolves from the top of the repository: `sub/config.py` was checked against the top-level `config.py`. | `git show <commit>:./<path>`, relative to `--root`. | `TestHistoryReadsTheReportedFileUnderRoot` |
| 2 | triage | The symlink check ran only when the reported file existed; `linkdir/x.py` under a directory symlink leaving `--root` passed the check (the read then failed). | Symlinks are resolved on the deepest existing ancestor. | `TestResolveContainment`, `FuzzResolveStaysInRoot` |
| 3 | triage | The 8 MB source limit applied to working-tree reads only, not history reads. | Same limit for both. | — |
| 4 | reports | `-r report.json` and `--fix-patch` over an existing file kept its old mode (e.g. 0644); `O_CREATE`'s 0600 applies only to new files. | Files are chmod-ed to 0600 before anything is written. | `TestReportPermissionsAreTightened` |
| 5 | `--verify` | The HTTP client followed redirects. On a cross-host redirect Go drops `Authorization` but forwards custom headers, so keys sent as `x-api-key`/`DD-API-KEY` could reach the redirect target. | Redirects are never followed; a redirect answer is `unknown`. | `TestVerifierNeverFollowsRedirects` |
| 6 | `--fix` | JavaScript, TypeScript, Java and C# replacements yielded `undefined`/`null` when the variable was missing, failing later and far from the cause. | Those replacements now throw `"<VAR> is not set"`; Python and Ruby already raised, shell aborts. Go's `os.Getenv` cannot fail inline and is flagged in the output. | `TestPatchedCodeBehaves` (runs the patched Python, JavaScript and Go programs with and without the variable) |
| 7 | `--fix` | Literals in Go/C#/PHP `const` declarations, Java annotations, C# attributes and `case` labels were rewritten into runtime calls, which parse but do not compile. | Skipped with a reason. | `TestPatchSkipsConstantContexts` |

## Re-verified, no change needed

- **Path containment**: absolute paths outside `--root`, `../` traversal and
  symlinks leaving `--root` are refused (fuzzed: 500,000+ inputs, no escape).
  Absolute paths inside `--root` are accepted.
- **History integrity**: a finding with a commit is only ever evaluated
  against that commit; a missing or unreadable commit leaves it
  *uncorroborated*. Commit IDs must be 7-64 hex characters, so a report cannot
  inject git options. `git show` runs with `--no-textconv`.
- **Stale reports**: a value no longer near its reported line is
  *uncorroborated* ("source changed since the report").
- **Report confidentiality**: reports can be streamed (`triage -`); partially
  redacted reports are matched by prefix; unredacted report files and
  group/world-readable files trigger warnings; `--delete-input` removes the
  report even when triage fails; triage output is redacted by default.
- **`--fix` safety**: in-place edits need confirmation or `--yes`; Go, Python
  and JavaScript results are syntax-checked and skipped if they would not
  parse; literals nested in other strings are never rewritten; output always
  says to rotate the secret.
- **`--verify`**: requests go only to hard-coded provider endpoints with a 10 s
  per-request and 15 s client timeout, at most 4 at a time, each secret checked
  once per run; responses are read up to 64 KB. Hooks never pass `--verify`.

## Known limits

- `--verify` sends secrets to their issuers by design; don't use it where
  that is not acceptable, and expect `error` behind egress proxies.
  Rate-limited (`429`) answers are reported as `unknown`, not retried.
- `--fix` validates syntax, not types: a replacement can still change a
  value's type in dynamically typed code paths. Review the patch and run tests.
- Go replacements return `""` for a missing variable; validate at startup.
