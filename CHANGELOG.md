# Changelog

All notable changes are listed here. The project follows
[Semantic Versioning](https://semver.org); see [docs/compatibility.md](docs/compatibility.md)
for what counts as a breaking change.

## 1.0.0 - 2026-10-15

First public release: 129 rules, gitleaks-compatible config and reports,
staged/push/history/diff scanning, git hooks, noise filters with a
suppression ledger, confidence levels and strict/balanced policies, `triage`
for other scanners' reports, live verification, remediation guidance and
`explain`. Benchmark results: [bench/results/2026-10-15.md](https://github.com/AISolutionLabs/secret-scanner/blob/v1.0.0/bench/results/2026-10-15.md).

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
  in test files always block. On CredData, balanced's blocking recall goes
  from 14.4% (high only) to 59.9%, at 91.6% precision.
- Triage's *uncorroborated* findings are low confidence (review under
  balanced, blocking under strict), as documented.

### Triage
- **Conservative mode (default)**: shape-only filters are not applied to a
  value under a credential-named key; `--mode standard` applies every filter.
  On CredData repositories never used to design it, triage loses 15 of
  gitleaks' 1,110 true findings instead of 130, and still removes 20% of its
  false positives. Regression tests cover each missed class (UUID tokens,
  hex values, pagination tokens, base64 under `key =`, getenv defaults) and
  the false positives that must stay filtered.
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
