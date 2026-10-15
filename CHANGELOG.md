# Changelog

All notable changes are listed here. The project follows
[Semantic Versioning](https://semver.org); see [docs/compatibility.md](docs/compatibility.md)
for what counts as a breaking change.

## Unreleased

Changes made in response to an external review (benchmark rigor, default
policy, filter safety, triage and `--fix` safety, release hygiene).

### Detection
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

### Triage
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

### Reporting and benchmarks
- `-f stats`: anonymized counts (rule, confidence, file type) for sharing.
- `bench/leaky_repo.py` (independent ground truth), `bench/adjudicate.py` with
  hand labels for every corpus finding, pinned corpus versions, per-alphabet
  false-negative measurement, and dated results in `bench/results/`.
- README claims now lead with independent data and list misses and limits.

## 1.0.0 (not yet tagged)

First public version: 120+ rules, gitleaks-compatible config and reports,
staged/push/history/diff scanning, git hooks, noise filters with a
suppression ledger, confidence and policies, `triage` for other scanners'
reports, verification, remediation guidance and `explain`.
