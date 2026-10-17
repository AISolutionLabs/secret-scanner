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
| 2b | triage | With `--root` reached through a symlink (on macOS every temp dir: `/var` → `/private/var`), absolute report paths inside the root were rejected. | Containment is decided on fully resolved paths only, so every spelling of the root works. | `TestResolveThroughSymlinkedRoot` |
| 3 | triage | The 8 MB source limit applied to working-tree reads only, not history reads. | Same limit for both. | — |
| 4 | reports | `-r report.json` and `--fix-patch` over an existing file kept its old mode (e.g. 0644); `O_CREATE`'s 0600 applies only to new files. | Files are chmod-ed to 0600 before anything is written. | `TestReportPermissionsAreTightened` |
| 5 | `--verify` | The HTTP client followed redirects. On a cross-host redirect Go drops `Authorization` but forwards custom headers, so keys sent as `x-api-key`/`DD-API-KEY` could reach the redirect target. | Redirects are never followed; a redirect answer is `unknown`. | `TestVerifierNeverFollowsRedirects` |
| 6 | `--fix` | JavaScript, TypeScript, Java and C# replacements yielded `undefined`/`null` when the variable was missing, failing later and far from the cause. | Those replacements now throw `"<VAR> is not set"`; Python and Ruby already raised, shell aborts. Go's `os.Getenv` cannot fail inline and is flagged in the output. | `TestPatchedCodeBehaves` (runs the patched Python, JavaScript and Go programs with and without the variable) |
| 7 | `--fix` | Literals in Go/C#/PHP `const` declarations, Java annotations, C# attributes and `case` labels were rewritten into runtime calls, which parse but do not compile. | Skipped with a reason. | `TestPatchSkipsConstantContexts` |
| 8 | `--verify` | Any 2xx or 403 answer meant "verified": a TLS-inspecting proxy's HTML caution page (200) or block page (403), or a captive portal, made every secret for that provider "verified live". | Only a JSON answer can verify; others are `unverified`. | `TestVerifierOnlyTrustsProviderAnswers` |
| 9 | `--verify` | A 401 from api.github.com / gitlab.com marked GitHub Enterprise Server and self-managed GitLab tokens (same formats) `invalid`, which lowered them to low confidence, so balanced stopped blocking a live enterprise token. | 401 is `unverified` for these rules. | `TestVerifierOnlyTrustsProviderAnswers` |
| 10 | triage | SARIF output dropped the source tool and the triage status (a filtered finding read as a plain note) and wrote the commit only where the SARIF parser did not read it. | `properties.source`, `properties.triage`, `partialFingerprints.commitSha`; the parser reads them back. | `TestSARIFKeepsTriageProvenance` |
| 11 | triage | A filtered candidate that merely overlapped a reported value (a placeholder inside a longer reported token) marked the finding filtered. | The filtered value must cover the reported one. | `TestFilteredCandidateMustCoverReportedValue` |
| 12 | `--fix` | Literals inside comments, Go raw strings, Python triple-quoted strings, JS templates and heredocs were rewritten: the result parsed but the program's data changed (and Go gained an unused import). `rb"…"` became `rbos.environ[…]`. PHP property/parameter defaults, C# mid-line `case` and optional parameters, Java constants used in `case`, TypeScript enum members were rewritten into non-constant expressions. | A lexer requires the literal to be in code; bytes literals and those constant positions are skipped; Ruby/PHP/shell results are syntax-checked (`ruby -c`, `php -l`, `bash -n`) when available. | `TestPatchPreservesBehaviour`, `TestCodeAt` |
| 13 | scans | Files over `--max-target-megabytes`, the tail of stdin past it, and diff additions past it were skipped with no message and exit 0. | The summary lists what was not scanned. | `TestOversizedInputIsReported` |
| 14 | triage | The 8 MiB source limit was checked after `os.ReadFile` / `git show` had already loaded the whole file or blob, so a report naming a huge file could exhaust memory (relevant when triage runs in CI or a push proxy). Found by an external reviewer. | Size checked before reading (`stat`, `git cat-file -s`) and content read through a capped reader; git is stopped if a blob exceeds the cap. | `TestOversizedWorkingTreeFileIsNotLoaded`, `TestOversizedHistoricalBlobIsNotLoaded` (assert allocations stay under 4 MiB) |
| 15 | `--verify` | The cache was checked and filled around the network call, so concurrent findings with the same secret each sent a request (33 requests for 200 identical findings in the test). Found by an external reviewer. | Per-secret in-flight coordination: one request, shared result. | `TestVerifierChecksEachSecretOnce` (counts server requests) |
| 16 | `--verify` | Any 2xx JSON response counted as verified, so a gateway's JSON error document or an empty object marked a secret live; JSON 403 also counted as verified, although GitHub uses 403 for rate limits. Found by an external reviewer. | Each provider declares the fields of its documented success response; anything else is unverified, and 403 is unverified. | `TestVerifierRequiresSuccessShape` |
| 17 | output files | Report and patch output opened the path with `O_CREATE`, then changed its mode and truncated it, following an existing symlink: a link planted at `-r`/`--fix-patch` (for example in a CI checkout of an untrusted branch) could truncate an unrelated file and make it 0600. `install-hook` and `--fix` also wrote through symlinks. Found by an external reviewer. | Output goes to a new file created exclusively in the destination directory and renamed over the path; symlinks at report and patch paths are refused, symlinked hooks are replaced, `--fix` skips symlinked sources; a failed report write leaves no partial file. | `TestOutputPathsDoNotFollowSymlinks` (links to files inside and outside the repository and to an existing report), `TestReportReplacesHardLink`, `TestInstallHookDoesNotWriteThroughSymlink`, `TestBuildPatchSkipsSymlinks`, `TestReportToDevStdout` |
| 18 | triage | The report itself was read whole (`os.ReadFile` / `io.ReadAll` of stdin) before parsing, so the 8 MiB source limit did not bound memory for a huge report. Found by an external reviewer. | `--max-report-megabytes` (default 256): files over it are rejected from their size before reading, stdin is read through a capped reader; an oversized report exits 2, never as a clean result. | `TestTriageRejectsOversizedReport` |

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
- **Resource bounds**: a triage report over `--max-report-megabytes`
  (default 256) is rejected before parsing, from a file or stdin; source files
  and history blobs it names are read only up to 8 MiB.
- **Output files**: reports, fix patches, hooks and `--fix` rewrites are
  written to a new file in the destination directory and renamed into place,
  so an existing symlink or hard link at the path is never written through.
  A symlink at a report or patch path is refused (links to a terminal or pipe,
  such as `/dev/stdout`, are allowed); a symlinked hook is replaced by a
  regular file; `--fix` skips symlinked sources.
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
  Java and C# results are never compiled: a `static final` constant used as a
  `case` label or annotation argument in *another* file stops compiling.
- `--verify` reports `unverified` for GitHub and GitLab tokens the public
  endpoint rejects; check self-managed instances yourself.
- Go replacements return `""` for a missing variable; validate at startup.
