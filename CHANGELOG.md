# Changelog

All notable changes are listed here. The project follows
[Semantic Versioning](https://semver.org); see [docs/compatibility.md](docs/compatibility.md)
for what counts as a breaking change.

## 1.0.0 - 2026-10-17

First public release: 136 rules, gitleaks-compatible config and reports,
staged/push/history/diff scanning, git hooks, placeholder and local-credential
recognition, noise filters with a suppression ledger, confidence levels and
strict/balanced policies, `triage` for other scanners' reports, live
verification, remediation guidance and `explain`. Benchmark results:
[bench/results/2026-10-17.md](https://github.com/AISolutionLabs/secret-scanner/blob/v1.0.0/bench/results/2026-10-17.md)
(earlier rounds: 2026-10-15, 2026-10-16).

### Placeholders, local credentials and new detectors
<!-- bench:changelog-headline -->
Designed on CredData's dev half, measured once on its test half: precision
83.7% -> 91.5%, recall 48.0% -> 59.2% on repositories never used for design.
Under balanced (`testFixtures = "block"`), 39.9% of labeled secrets block at
90.2%; gitleaks + triage loses 54 of gitleaks' 1,110 true findings (41
`ChangeToken`) and removes 27 of its 99 false positives.
<!-- /bench:changelog-headline -->

- Placeholder credentials (`some_password`, `s3krit-password`, `admin123`,
  `postgres:postgres@`) are dropped with a ledger reason
  (`placeholder-vocabulary`, `echoes-key-name`, `user-equals-password`);
  so are digests under hash keys, .NET `PublicKeyToken`s, translated UI
  strings, algorithm names, crypto test-vector key names and patterned hex.
  Word+number passwords other than one-word defaults are still reported.
- New `Context` field (`local` / `example`): credentials for localhost,
  private networks, `*.local` and compose service hosts, and values in
  docker-compose files, `.env.example` and `.env.test`, are reported at low
  confidence and listed for review under `balanced` (strict still blocks).
  URL credentials to local hosts were previously allowlisted silently.
- New detectors: HTTP `Authorization: Basic` (only when it decodes to
  `user:password`) and `Bearer` headers, SQL `CREATE/ALTER USER ... PASSWORD`
  and `IDENTIFIED BY`, `NAME_PASSWORD=` in compose files, `docker -e`, ENV and
  inline env, command-line passwords (`curl -u`, `sshpass -p`, `mysql -p`,
  openssl `pass:`), password calls (`setPassword`, `SetBasicAuth`,
  `NetworkCredential`) and token setters (`SetAuthToken`).
- UUIDs under credential-named keys are reported at low confidence; UUIDs
  under request, correlation, paging and concurrency keys (including AWS WAF
  `ChangeToken`, which grants no access) are not.
- `password-assignment` matches indexers (`["password"] =`), comparisons,
  wrapper calls and 4-5 character values; UI labels under password keys are
  filtered.
- Rules can declare content validators (`basic-auth`, `opaque-token`); a
  value that fails validation never becomes a finding.

### Benchmark integrity and confidence semantics
- Every published benchmark figure (README, docs, CHANGELOG, release notes,
  `install-hook`) is generated from `bench/results/latest.json`, and CI
  checks each one against the row it comes from in the dated results file.
  It also rejects any percentage published outside a generated passage, and
  any balanced figure that does not name its `testFixtures` setting. This
  fixed stale figures: trufflehog in the README (an earlier full-dataset
  run), detect-secrets' leaky-repo extra lines, two CHANGELOG lines, and a
  triage figure that had no source row.
- `bench/breakdown.py`: precision by confidence, path, context, detector
  family and policy, from the holdout report, with detection and blocking
  recall separately. Confidence is documented in the CLI help, the SARIF
  output (`tool.driver.properties.confidenceScale`) and docs/precision.md as
  a qualitative evidence level, not a probability.
- Every provider-format rule (86) is tested at test, fixture, example and
  doc paths, `.env.example` and compose files: none is downgraded or stops
  blocking under balanced (`TestNoProviderFormatDowngradedByLocation`).
- [docs/benchmark-policy.md](https://github.com/AISolutionLabs/secret-scanner/blob/v1.0.0/docs/benchmark-policy.md):
  labels used as given, a register of label disagreements (AWS WAF
  `ChangeToken`) reported only as a secondary figure, and a protocol for a
  second independent benchmark. The detection-code fingerprint is recorded
  with the figures, and a release fails if they were measured on different
  detection code. `bench/score_labeled.py` scores any line-labeled corpus.

### Fixes from an external code review
- Output files are never written through a link: reports, fix patches,
  hooks and `--fix` rewrites go to a new file in the destination directory
  that is renamed into place. A symlink at a report or patch path is refused
  (terminal and pipe links such as `/dev/stdout` still work), a symlinked
  hook is replaced by a regular file, `--fix` skips symlinked sources, and a
  failed report write leaves no partial file.
- `triage --max-report-megabytes N` (default 256): a larger report, from a
  file or stdin, is rejected before parsing with exit 2.
- `triage` enforces its 8 MiB source limit while reading: working-tree
  files are size-checked before reading and read through a capped reader;
  history blobs are size-checked with `git cat-file -s` and streamed with a
  cap, so a huge file named in a report can no longer exhaust memory.
- `--verify` checks each secret once per run even under concurrency
  (in-flight requests are shared), and only a provider's documented success
  shape verifies (`login` for GitHub, `object: balance` for Stripe,
  `data.viewer.id` for Linear, ...): JSON error objects, empty documents and
  malformed bodies are unverified. 403 is no longer treated as verified.
  GitHub App installation tokens are checked against
  `/installation/repositories`.
- README, docs and the install-hook message take their benchmark figures
  from `bench/results/latest.json` (`bench/render_docs.py`); CI fails if a
  published figure is stale.

### Fixes from an adversarial recall and security review
- One-word default passwords plus digits (`admin@123`, `Welcome@2024`,
  `P@ssw0rd2023`, `Password1`) under password keys are reported at low
  confidence outside test, example and doc files instead of being dropped
  as placeholders (still dropped there, ledger reason
  `default-password-in-test-or-doc`).
- Local context no longer applies to Kubernetes service DNS
  (`*.svc.cluster.local`), other multi-label `.local` names
  (`sql01.corp.local`), `.env.local` / `.env.*.local`, or any path with a
  `prod`/`production`/`prd`/`live` segment.
- `redis://:password@host` (empty user) is reported by `url-credentials`.
- Placeholder phrases must be the whole value: `mysecretkey_8f2kq` and
  `yourkey_<random>` are reported.
- Unquoted values in `.env.*.*`, `.envrc`, Makefiles, systemd units and
  `.txt` files are literals: random base64 there was dropped as
  `operator-in-code` about 40% of the time. Base64 starting with `/` or `+`
  is matched by `generic-api-key`.
- Digit-free Bearer tokens (long, mixed case, high entropy) are reported;
  `Authorization: <uuid>` counts as a credential-named key.
- `--verify`: only a JSON answer verifies (a proxy's HTML block or caution
  page no longer marks every secret live), and a 401 for GitHub/GitLab
  tokens is `unverified`, not `invalid`, because self-managed instances
  issue the same formats.
- `triage -f sarif` keeps the source tool, triage status and commit, and a
  filtered value explains a reported finding only when it covers it.
- `--fix` never rewrites a literal inside a comment, multi-line string or
  heredoc, Python bytes literals, or constant positions (PHP property and
  parameter defaults, C# case labels and optional parameters, Java
  constants used in `case`/annotations, TypeScript enums); Ruby, PHP and
  shell results are syntax-checked when the interpreter is installed.
- Inputs skipped for `--max-target-megabytes` (files, stdin tail, diff
  additions) are reported in the summary instead of passing silently.

Changes since the first public commit, made in response to an external
review (benchmark rigor, default policy, filter safety, triage and `--fix`
safety, release hygiene):

### Detection
- Fixed: unquoted hex values (`Key = acc993b3…`) were classed as code
  identifiers and dropped, in scans and triage.
- New rules for formats an independent benchmark (leaky-repo) showed were
  missed: unquoted passwords in env/INI/properties/YAML (`password-in-config`),
  WordPress/PHP `define()` secrets, Django `SECRET_KEY`, Laravel `APP_KEY`,
  XML password attributes and `<Pass>` elements, `.netrc` passwords, AWS key
  IDs in SigV4 credential scopes (`Credential=AKIA…/20260101/…`), and
  `shadow`, `proftpdpasswd`, Rails `config/master.key` and Firefox
  `logins.json` as sensitive files. `pass` is now a password key name.
- Weak dictionary passwords (`admin123`) are reported at reduced confidence
  instead of being dropped; exact placeholder words are still filtered.
- Fixed: `SECRET_KEY=…` was suppressed by the secret-reference name allowlist.
- New noise filters, each with keep/reject/borderline tests: word tokens,
  values that repeat their own key name, string concatenation, e-mail
  addresses, and signature/auth scheme names (`AWS4-HMAC-SHA256`).

### Policy and hooks
- Git hooks (installed and pre-commit framework) default to the **balanced**
  policy; scans and CI still default to strict. `install-hook` prints the
  trade-off, and hooks explain every blocked finding.
- Balanced now blocks **high and medium** confidence (before: high only) and
  lists weak evidence for review.
- Generic values in test/example files block under balanced by default
  (`testFixtures = "block"`); `testFixtures = "review"` in `.secretscan.toml`
  or `--test-fixtures review` lists them for review instead. Provider formats
  in test files always block. The measured blocking recall and precision of
  each setting are in the README and docs/precision.md.
- Triage's *uncorroborated* findings are low confidence (review under
  balanced, blocking under strict), as documented.

### Triage
- **Conservative mode (default)**: shape-only filters are not applied to a
  value under a credential-named key; `--mode standard` applies every filter.
  Regression tests cover each missed class (UUID tokens, hex values,
  pagination tokens, base64 under `key =`, getenv defaults) and the false
  positives that must stay filtered.
- Memory is bounded: findings are processed grouped by file with one file
  held at a time (8,350 gitleaks findings over 1 GB: 13 s, 203 MB).
- Source is read only inside `--root`; absolute paths, `../` and escaping
  symlinks are rejected. History findings are read at their commit with no
  working-tree fallback; unavailable or changed source stays uncorroborated.
- Reads reports from stdin (`-`), matches partially redacted values
  (gitleaks `--redact=N`), warns about unredacted or group/world-readable
  reports, and `--delete-input` removes the report after reading.

### Remediation
- `--fix` applies edits only after confirmation or `--yes`; `--fix-patch` is
  the documented default. Go/Python/JavaScript edits are syntax-checked and
  skipped if they would not parse; literals nested in other strings are never
  rewritten; output always reminds you to rotate.

### Security audit fixes ([docs/security-audit.md](https://github.com/AISolutionLabs/secret-scanner/blob/v1.0.0/docs/security-audit.md))
- Triage read the wrong file at a commit when `--root` was a subdirectory.
- Triage symlink containment now also covers files that don't exist yet.
- Reports and `--fix-patch` files are forced to 0600 even when overwriting.
- `--verify` no longer follows redirects (custom auth headers could be
  forwarded to the redirect target).
- `--fix` replacements fail fast naming the variable (JS/TS, Java, C#) and
  skip literals that must stay compile-time constants.

### Distribution
- `install.ps1` for Windows (checksum and optional signature verification);
  installers are tested on Linux, macOS and Windows on every push, and the
  post-release install test covers Windows.
- Releases sign `SHA256SUMS` with Sigstore (keyless, bound to the release
  workflow) and attach GitHub build-provenance attestations; `install.sh`
  verifies the signature when cosign is installed
  (`SECRETSCAN_REQUIRE_SIGNATURE=1` makes it mandatory), and the post-release
  install test requires it.
- `install.sh`: one-command install of the release binary with SHA-256
  verification; refuses to install on a mismatch.
- The release workflow installs every published release from scratch on
  Linux and macOS (install script, `go install @tag`, pre-commit hook) and
  checks it blocks a generated token.
- `secretscan version` reports the module version for `go install` builds.

### Reporting and benchmarks
- `bench/reproduce.sh` and the `benchmark` workflow reproduce every published
  number with pinned tools and datasets, locally or in a fork's Actions.
- CredData is split into dev/test halves by repository (pre-registered);
  CredData-informed changes are designed on dev and reported on test.
- CI reports failing tests as annotations.
- `-f stats`: anonymized counts (rule, confidence, file type) for sharing.
- `bench/creddata.py`: independent precision challenge on Samsung CredData
  (337 real repositories), including gitleaks + triage; first-run results
  published with every false-positive and miss class.
- detect-secrets runs in all benchmarks with `--no-verify` (by default it
  sends matched values to provider APIs).
- `bench/leaky_repo.py` (independent ground truth), `bench/adjudicate.py` with
  hand labels for every corpus finding, pinned corpus versions, per-alphabet
  false-negative measurement, and dated results in `bench/results/`.
- README claims now lead with independent data and list misses and limits.
