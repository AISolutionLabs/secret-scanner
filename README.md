# secretscan

[![ci](https://github.com/AISolutionLabs/secret-scanner/actions/workflows/ci.yml/badge.svg)](https://github.com/AISolutionLabs/secret-scanner/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Go Reference](https://pkg.go.dev/badge/github.com/AISolutionLabs/secret-scanner.svg)](https://pkg.go.dev/github.com/AISolutionLabs/secret-scanner)

**Catch real secrets. Ignore the noise. Keep every commit moving.**

secretscan is a precision-first secret scanner. Alert fatigue is the real
failure mode of secret scanning: when developers keep seeing harmless
matches, they add broad exclusions or bypass the hook. secretscan keeps broad
coverage, cuts unnecessary alerts, and refuses to buy that by quietly missing
real secrets. Both directions are [measured](#benchmark) against gitleaks and
detect-secrets on the same corpus.

It scans files, git history, staged changes, outgoing pushes and raw diffs as
a single dependency-free Go binary, and its [`triage`](#triage-a-precision-layer-for-other-scanners)
command adds the same precision layer on top of gitleaks, trufflehog or any
SARIF report.

- **Evidence, not entropy**: provider formats are high confidence on their
  own. Generic matches need several independent signals (credential-named
  key, randomness, composition, literal, location) and get a confidence
  level with the reasons. See [docs/precision.md](docs/precision.md).
- **Strict or balanced**: strict blocks every finding; balanced blocks high
  and medium confidence and generic values in test files, and lists only weak
  evidence for review. Git hooks default to balanced, scans and CI to strict.
  The trade-off is measured, and a provider token is never downgraded because
  it sits in `tests/`.
- **No silent passes**: every filtered candidate is counted and listable
  with its reason (`--show-suppressed`). Suppressions are narrow, and
  regression tests prove none of them hides a valid secret next to it.

- **130+ built-in rules**: AWS (incl. Bedrock API keys), Azure (Entra ID secrets,
  storage keys, SAS, new and legacy Azure DevOps PATs), GCP, GitHub, GitLab,
  JFrog, Vault, Terraform Cloud, Slack, Stripe, OpenAI, Anthropic, LiteLLM,
  Grafana, Datadog, private keys, credentialed URLs, JWTs, generic secrets.
- **Custom patterns**: via TOML config, `--pattern` flags or a patterns file.
- **Drop-in gitleaks compatibility**: config schema, fingerprints, `.gitleaksignore`,
  `gitleaks:allow` and JSON report shape all carry over.
- **Noise filters with named reasons**: a character-level language model and
  structural checks reject identifiers, words, paths, digests, UUIDs and
  published sample credentials. See [How noise is filtered](#how-noise-is-filtered).
- **Finds hidden secrets**: recursively decodes base64, hex and percent-encoding.
- **Safe output**: secrets are redacted by default (80% masked); reports
  carry a SHA-256 of each secret so baselines work without storing secrets.
- **Optional live verification** (`--verify`) for GitHub, GitLab, Slack,
  Stripe, OpenAI, Anthropic, Hugging Face, npm, SendGrid, DigitalOcean, Groq and Linear.
- **Fix guidance**: every finding says how urgent it is (verified-live means
  revoke now), how to rotate it at the issuer, how to avoid static secrets
  (workload identity, OIDC, managed identity), and the replacement code in the
  file's language. `secretscan explain` gives efficient loading patterns for
  env, Vault, AWS, Azure and GCP, and `--fix-patch` writes a reviewable
  patch that turns literals into env lookups. See [docs/using-secrets.md](docs/using-secrets.md).
- **Reports** in text, JSON, SARIF 2.1.0, CSV and JUnit XML, plus an
  anonymized `stats` summary for sharing results.

## Install

One command on Linux or macOS (amd64/arm64). It downloads the release binary,
verifies it against the release's `SHA256SUMS` and installs nothing if the
check fails:

```sh
curl -fsSL https://raw.githubusercontent.com/AISolutionLabs/secret-scanner/main/install.sh | sh
# a specific version, or another directory
curl -fsSL https://raw.githubusercontent.com/AISolutionLabs/secret-scanner/main/install.sh | BINDIR=/usr/local/bin sh -s -- v1.0.0
```

On Windows (PowerShell), with the same checks:

```powershell
irm https://raw.githubusercontent.com/AISolutionLabs/secret-scanner/main/install.ps1 | iex
```

Or with Go 1.24+, or a binary from
[Releases](https://github.com/AISolutionLabs/secret-scanner/releases):

```sh
go install github.com/AISolutionLabs/secret-scanner/cmd/secretscan@v1.0.0
make build            # from a checkout -> bin/secretscan
```

Every release is installed from scratch on Linux, macOS and Windows by CI
after it is published (install script, `go install` at the tag and, on Linux
and macOS, the pre-commit hook), with the signature required, and must block
a freshly generated token. The installers are also tested on all three
systems on every push, including refusing a tampered binary.

**Verifying a release.** `SHA256SUMS` is signed by the release workflow with
Sigstore (keyless: the signing certificate names this repository's
`release.yml` and the tag), and every binary has a GitHub build-provenance
attestation. With [cosign](https://docs.sigstore.dev/cosign/system_config/installation/)
installed, `install.sh` checks the signature automatically
(`SECRETSCAN_REQUIRE_SIGNATURE=1` makes it mandatory). By hand:

```sh
cosign verify-blob SHA256SUMS --bundle SHA256SUMS.sigstore.json \
  --certificate-identity-regexp '^https://github.com/AISolutionLabs/secret-scanner/\.github/workflows/release\.yml@refs/tags/v' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
sha256sum --ignore-missing -c SHA256SUMS
gh attestation verify secretscan-linux-amd64 --repo AISolutionLabs/secret-scanner
```

## Quick start

```sh
secretscan dir .                       # scan the working tree
secretscan git                         # scan all git history (all refs)
secretscan git --staged                # what you're about to commit
secretscan git --log-opts "origin/main..HEAD"   # a commit range
git diff | secretscan stdin --diff     # scan only added lines of a diff
cat file | secretscan stdin --label file.env

secretscan install-hook --type both    # pre-commit + pre-push hooks
secretscan triage gitleaks.json        # re-score another scanner's report
```

Exit codes: `0` clean · `1` secrets found (`--exit-code N` to change) · `2` usage or config error.

## Policies, confidence and the suppression ledger

```
[CRITICAL·high] github-pat GitHub personal access token  tests/test_gh.py:1:7     <- blocks under both policies
── Needs review (not blocking under the balanced policy) ──
[MEDIUM·low] generic-api-key Generic API key, token or secret  tests/test_cfg.py:2:18
    why:     assigned to a credential-named key; mixed character classes or long value; literal value
             in code or config; in a test/example path (no downgrade for provider formats);
             capped at low: unstructured value in a test/example file
secretscan: 2 secrets found (1 critical, 1 medium) · scanned 3 files (490 B) in 1ms
  policy balanced: 1 blocking, 1 to review · 3 candidates filtered as noise (2 word-like, 1 uuid; --show-suppressed to list)
```

- `--policy strict|balanced`, or `policy = "balanced"` in `.secretscan.toml`.
  Without either, `dir`/`git`/`stdin` scans use **strict** and installed git
  hooks use **balanced** (`install-hook --policy strict` to change it).
<!-- bench:policy -->
- Balanced blocks high and medium confidence, and generic values in
  test/example files. Only weak evidence (low confidence: dictionary-style
  passwords, values with few supporting signals) is printed under
  "Needs review" without blocking. On CredData repositories never used for
  design ([2026-10-17](bench/results/2026-10-17.md)), balanced blocks 39.9% of
  labeled secrets at 90.2% precision, strict 59.2% at 91.5%.
- A real credential committed as a test fixture is still a credential, so
  fixtures block by default. A repository whose tests are full of fake
  credentials can set `testFixtures = "review"` in `.secretscan.toml` (or
  `--test-fixtures review`) to list them for review instead; balanced then
  blocks 22.2% of those labeled secrets. Provider-format tokens
  (`ghp_`, `AKIA`, private keys, ...) block in test files under every setting.
<!-- /bench:policy -->
- Keep CI on strict so nothing merges without a decision.
- Every finding has `Confidence` (high/medium/low), `Evidence` and `Blocking`
  in JSON. SARIF levels follow the policy (blocking = `error`).
- `--min-confidence medium` hides weaker findings (still counted in the summary).
- `--show-suppressed` lists every candidate a filter or allowlist removed:
  file, line, rule, reason and redacted value.

## Triage: a precision layer for other scanners

Keep your existing scanner's rules and cut its noise:

```sh
# Preferred: stream the report, so no unredacted copy is written to disk
gitleaks dir . -f json -r - --no-banner | secretscan triage - --policy balanced
# Partially redacted reports work too (prefix matching), with fewer secrets exposed
gitleaks dir . -f json -r - --redact=50 | secretscan triage -
# If you must use a file: keep it outside the repo and delete it afterwards
secretscan triage /tmp/gl.json --delete-input          # also trufflehog JSON lines or any SARIF
```

Triage needs the reported values to re-check them, so a report file is a
copy of your secrets. secretscan warns when it reads an unredacted report or
one that other users can read. It reads source only inside `--root` (default:
the current directory), rejects absolute paths, `../` and symlinks that lead
outside it, and for history findings reads the file at the reported commit: if that
commit is unavailable, the finding stays *uncorroborated* instead of being
checked against today's file.

Each finding comes back as `verified`, `confirmed` (secretscan independently
finds it), `uncorroborated` (kept for review) or `filtered: <reason>` (for
example `digest-or-commit-hash`, `word-like`, `identifier`). Filtered findings
are listed, never dropped. Values with a provider-specific shape are never
filtered by word heuristics, and redacted or unreadable findings are kept.
Exit codes follow the policy.

Triage runs in **conservative** mode by default: a value assigned to a
credential-named key (`access_token`, `secretVal`, `"nextToken":`) is never
filtered for its shape alone (UUID, identifier-like, word-like), because real
credentials take those shapes. Structural filters (digests, truncated or
published examples, placeholders, sequences) and values that name a secret
(`prod-db-secret-id`) still apply, and UUIDs under request-style keys
(`request_token`, `idempotency_key`) are still IDs. `--mode standard` applies
<!-- bench:triage-modes -->
every filter: fewer findings to review, more real secrets lost. On CredData
repositories never used to design it, conservative lost 54 of gitleaks'
1,110 true findings (41 of them AWS WAF `ChangeToken` values, deliberately
not treated as credentials) and standard lost 105.
<!-- /bench:triage-modes -->

## Git hooks

`secretscan install-hook --type pre-commit|pre-push|both` writes hooks into
`git rev-parse --git-path hooks`, so `core.hooksPath` is respected.

- Hooks use the **balanced** policy unless you pass `--policy` or set it in
  config (generic values in test files block too, unless
  `testFixtures = "review"`), and the installer prints what that means. Every blocked
  finding is explained (`why:`).
- **pre-commit** scans only the staged diff. Typical commits take milliseconds.
- **pre-push** reads the refs git passes on stdin and scans only commits that
  aren't on the remote yet. This catches secrets committed with `--no-verify`.
- An existing hook is preserved as `<hook>.local` and chained after the scan.
- Hooks **fail closed** if the binary is missing. Set `SECRETSCAN_OPTIONAL=1` to
  fail open, or `SECRETSCAN_SKIP=1` for an explicit, logged one-off bypass.
  Set `SECRETSCAN_BIN` to point at a specific binary.

Hooks are a developer convenience and can be bypassed. Enforce with CI or a
push proxy (below).

With the [pre-commit](https://pre-commit.com) framework, the repo ships a
`.pre-commit-hooks.yaml`:

```yaml
repos:
  - repo: https://github.com/AISolutionLabs/secret-scanner
    rev: v1.0.0
    hooks:
      - id: secretscan          # staged changes
      - id: secretscan-push     # outgoing commits (stages: [pre-push])
```

## Custom patterns

There are three ways to add patterns. All are **additive** to the built-in pack,
and a custom rule with the same `id` as a built-in replaces it.

**1. Config file**: `.secretscan.toml` in the scan root is auto-discovered,
then `.gitleaks.toml`. You can also use `-c path` or `$SECRETSCAN_CONFIG`.
See [`examples/secretscan.toml`](examples/secretscan.toml).

```toml
[[rules]]
id = "acme-service-token"
description = "ACME internal service token"
regex = '''\b(acme_(?:live|test)_[A-Za-z0-9]{32})\b'''
secretGroup = 1                  # capture group holding the secret (default: first group)
keywords = ["acme_live_", "acme_test_"]   # fast prefilter
entropy = 3.5                    # minimum Shannon entropy of the secret
path = '''\.(?:env|ya?ml)$'''    # only these files; path alone = file-name rule
severity = "critical"            # critical | high (default) | medium | low | info
tags = ["internal"]
examples  = ["ACME_TOKEN=acme_live_abcdefghijklmnopqrstuvwxyz012345"]   # self-tests
negatives = ["acme_live_short"]

  [rules.allowlist]
  regexes = ['''acme_test_0{32}''']
```

Config-level controls:

```toml
[extend]
useDefault = false                # use ONLY your rules (default: true)
path = "../org/secretscan.toml"   # inherit an org-wide baseline (chains allowed)
disabledRules = ["jwt"]
```

**2. Flags.** These are repeatable. Options follow ` ;; `:

```sh
secretscan dir . --pattern 'corp-key=CORP-[A-Z0-9]{16}'
secretscan dir . --pattern 'tenant=(?i)tenant_secret\s*=\s*(\w{16}) ;; group=1 ;; entropy=3 ;; severity=high ;; keywords=tenant'
```

**3. Patterns file.** Use `--patterns-file patterns.txt`, with one pattern per line in the
same syntax. `#` starts a comment.

If a custom rule has no `keywords`, a literal regex prefix (e.g. `CORP-`) is
used as the prefilter automatically. `secretscan validate` compiles everything
and runs each rule's `examples` and `negatives`, which makes it a good CI check for
config changes. `secretscan rules [--tag aws] [-f json]` lists the active rules.

## Fixing findings

Each finding carries remediation in every output format (`Remediation` in
JSON, `help` and `properties.remediation` in SARIF):

```
[CRITICAL] github-pat GitHub personal access token  app/settings.py:5:17
    secret:  ghp_C3J2REDACTED
    fix:     rotate · Revoke the token (Settings > Developer settings > Tokens; ...) and review the org audit log.
    better:  In Actions use the built-in GITHUB_TOKEN with least-privilege `permissions:`, and OIDC for cloud access.
    code:    os.environ["GITHUB_TOKEN"]  (secretscan explain github-pat --lang python)
```

- `--remediation full` prints the step list and a complete code pattern for
  the target store. `--remediation none` hides guidance.
- `--secret-store env|vault|aws|azure|gcp` chooses the store (default from
  `[remediation] store` in config).
- `secretscan explain <rule-id> [--lang L|all] [--store S|all] [--env NAME]`
  covers Python, Go, JS/TS, Java, C#, Ruby, PHP, shell, PowerShell,
  Kubernetes, Terraform, Dockerfile, GitHub Actions, Azure Pipelines,
  Spring, .NET config and .env.
- **Prefer `--fix-patch FILE`**: it writes a `git apply` patch that replaces
  quoted literals in code with env lookups (adding `import os` / `"os"` where
  needed) for you to review. The patch contains the old secrets, so it's
  created with 0600 permissions and you're warned if it sits inside the repo.
- `--fix` applies the same edits in place, only after an interactive
  confirmation or `--yes`. Edited Go, Python and JavaScript files are
  syntax-checked and an edit that would not parse is skipped; other languages
  are listed as unchecked. Literals nested inside other strings (struct tags,
  SQL) are never rewritten. Unquoted values (YAML, `.env`) are listed for
  manual moves to a secret store.
- Replacements fail fast with the variable's name when it is missing
  (Python, JavaScript/TypeScript, Java, C#, Ruby, shell; Go and PHP are
  flagged). Literals that must stay constants (`const`, annotations,
  attributes, `case` labels) are skipped. Run your tests. **Moving a secret out of the code does not un-leak it: rotate every
  real secret that was committed**, since it stays in git history and clones.
- Verified-live findings sort first and say **REVOKE NOW**.

Patterns follow the efficiency rules in
[docs/using-secrets.md](docs/using-secrets.md): read once or cache with a TTL,
share one client, refresh once on 401, keep the last good value if the store
is unavailable, prefer mounted files over env vars for rotation, and never
fetch per request. Snippets are syntax-checked in the test suite.

```toml
# .secretscan.toml: org defaults for guidance
[remediation]
store   = "azure"
runbook = "https://wiki.example.com/platform/secrets-rotation"
```

## Suppressing findings

| Mechanism | Use for |
|---|---|
| Inline comment on the line: `secretscan:allow` (also `gitleaks:allow`, `pragma: allowlist secret`, `trufflehog:ignore`) | one-off false positives |
| `# secretscan:allow-next-line` on the line above | lines you can't append to |
| `.secretscanignore` / `.gitleaksignore` with `file:rule:line` or `commit:file:rule:line` fingerprints (printed as `ignore:`) | accepted findings |
| `.secretscanignore` with `sha256:<hash>` | a known secret anywhere, robust to line moves |
| `.secretscanignore` with `rule:<id>` or `rule:<id>:<file>` | silencing a rule globally or per file |
| `--baseline-path old.json` | adopting the scanner on a repo with existing debt (only new leaks fail) |
| `[[allowlists]]` / `[rules.allowlist]` in config | structured, reviewable policy |
| `--exclude-path REGEX` | ad-hoc path skips |

`--no-inline-ignore` disables inline markers, and `--no-noise-filters`
disables the heuristic filters below. Both are useful for audits.

## Options

```
-c, --config FILE            config file
    --pattern SPEC           extra rule (repeatable)
    --patterns-file FILE     file of patterns
    --no-default-rules       skip the built-in pack
    --enable-rule IDS        only these rules
    --disable-rule IDS       skip these rules
    --tag TAGS               only rules with these tags (aws, azure, ai, vcs, ...)
    --exclude-path REGEX     skip paths
    --ignore-file FILE       fingerprints/hashes to ignore
-b, --baseline-path FILE     JSON report of accepted findings
-f, --report-format FMT      text | json | sarif | csv | junit | stats (anonymized counts)
-r, --report-path FILE       write report to file (format inferred from extension;
                             never written through a symlink, replaced atomically)
    --redact[=N]             mask N% of each secret (default 80; --redact=0 shows all)
    --exit-code N            exit code on findings (default 1)
    --min-severity LEVEL     info | low | medium | high | critical
    --max-target-megabytes N skip larger files (default 10)
    --max-decode-depth N     base64/hex/percent decoding depth (default 2, 0 = off)
    --threads N              workers (default: CPU count)
    --verify                 check secrets against provider APIs
    --only-verified          report only live secrets (with --verify)
    --timeout DUR            abort after DUR
    --remediation MODE       short | full | none (text output guidance)
    --secret-store STORE     env | vault | aws | azure | gcp
    --fix-patch FILE         write a reviewable patch replacing literals with env lookups
    --fix [--yes]            apply those edits in place (asks first unless --yes)
    --policy P               strict (scan default) | balanced (hook default): high and medium block
    --min-confidence C       hide findings below low | medium | high (counted)
    --show-suppressed        list candidates removed by filters/allowlists, with reasons
    --no-color, -q/--quiet, --no-inline-ignore, --no-noise-filters
dir:   --follow-symlinks
git:   --staged | --pre-push [--remote NAME] | --log-opts "ARGS"
stdin: --diff, --label NAME
```

## CI

**Azure DevOps** (see [`ci/azure-pipelines.yml`](ci/azure-pipelines.yml)):

```yaml
- script: |
    secretscan git --log-opts "origin/$(System.PullRequest.TargetBranchName)..HEAD" \
      -r $(Build.ArtifactStagingDirectory)/secretscan.sarif
  displayName: Secret scan
```

**GitHub Actions** (see [`ci/github-actions.yml`](ci/github-actions.yml)): upload
the SARIF output to code scanning.

## Push proxy / server-side use

For a git push proxy (for example FINOS GitProxy, or your own `git-receive-pack`
interceptor), write the incoming pack to a temporary bare repo and run:

```sh
secretscan git /tmp/push.git --log-opts "$OLD..$NEW" -f json --redact -q
```

Alternatively, pipe the diff of the new commits into `secretscan stdin --diff`.
A non-zero exit means reject the push, and the JSON tells the proxy what to report back.

## Verification

`--verify` calls each provider's read-only identity endpoint (e.g. GitHub
`/user`, Slack `auth.test`) and marks findings `verified`, `invalid`,
`unverified` or `error`. **This sends secrets over the network.** Never use it
in hooks, and in locked-down networks expect `error`. Standard `HTTPS_PROXY`
and system CA settings are honored. Only a JSON answer from the provider
decides: proxy block or caution pages, rate limits (429) and server errors
are `unverified`, network failures `error`. GitHub and GitLab tokens the
public endpoint rejects stay `unverified` (they may belong to a
self-managed instance).

## Benchmark

Full results, versions, misses and reproduction steps:
[bench/results/2026-10-15.md](bench/results/2026-10-15.md) and
[2026-10-16](bench/results/2026-10-16.md). Everything can be regenerated with
`bench/reproduce.sh` or the `benchmark` workflow (pinned tools and datasets).
Most independent evidence first.

**1. Independent precision challenge ([Samsung CredData](https://github.com/Samsung/CredData)).**
11,565 files from 337 real repositories with manually labeled credential
lines, scored per line with CredData's method, excluding categories that are
identifiers rather than secrets. Repositories are split in half by hash;
every improvement is designed on one half and measured once on the other.
<!-- bench:holdout -->
Latest holdout ([2026-10-17](bench/results/2026-10-17.md)), on 181
repositories never used for design:

| Tool (default settings) | Precision | Recall | F1 |
|---|---|---|---|
| **secretscan** | 91.5% | **59.2%** | **0.719** |
| secretscan, before the latest round | 83.7% | 48.0% | 0.611 |
| gitleaks | 91.8% | 28.9% | 0.440 |
| gitleaks + `secretscan triage` | **93.6%** | 27.5% | 0.425 |
| trufflehog 3.97.9 | 44.7% | 3.4% | 0.064 |

On unseen repositories secretscan matches gitleaks' precision while finding
twice as many of the labeled secrets. Under balanced, the hook default,
39.9% of them block at 90.2% precision. On the half used for design
it reaches 98.8% / 89.0%; the gap is the honest measure of how much of
that transfers. Triage drops 54 of gitleaks' true findings, 41 of them
AWS WAF `ChangeToken` values that are deliberately not treated as
credentials.
<!-- /bench:holdout -->
The very first CredData run, before any CredData-informed change, is in
[2026-10-15](bench/results/2026-10-15.md).

**2. Independent ground truth ([leaky-repo](https://github.com/Plazmaz/leaky-repo), 96 labeled risk lines).**

| Tool | Risk lines found | Extra lines (FPs) |
|---|---|---|
| secretscan, before any leaky-repo-informed change | 36/96 (37.5%) | 3 |
| secretscan, current (rules added for the gaps it exposed) | 65/96 (67.7%) | 4 |
| gitleaks | 21/96 (21.9%) | 1 |
| detect-secrets 1.5.0 | 37/96 (38.5%) | 1 |

**3. Manual adjudication of package code.** All 132 secretscan findings on
44,284 files of 52 pinned npm/PyPI packages were inspected: **0 live
credentials, 116 example credentials** that packages ship (test private keys,
documented passwords, sample SAS tokens; reported on purpose) and **16 false
positives (0.36 per 1,000 files)**, mostly identifiers in minified bundles.

**4. Regression suite (generated data, tuned on).** 529 generated secrets,
91 false positives from public gitleaks/trufflehog issues, and staged-commit
latency. These numbers catch regressions; they are not proof.

| Tool | Recall | Safety set | Issue FPs | Findings / 1k package files | Commit latency p50 |
|---|---|---|---|---|---|
| secretscan | 529/529 (all block under balanced) | 40/40 | 0/91 | 2.98 (2.69 blocking under balanced) | 44 ms |
| gitleaks | 435/529 | 28/40 | 16/91 | 6.98 | 85 ms |
| gitleaks + `secretscan triage` | 435/529 | 28/40 | 0/91 | 5.04 (1.49 blocking under balanced) | – |
| detect-secrets | 388/529 | 28/40 | 23/91 | – | – |

**5. Cost of the noise filters, per alphabet.** 20,000 random secrets per
alphabet go through the generic pipeline in CI, which fails if filters remove
more than 0.02% of any alphabet (0.05% for passwords;
`TestFalseNegativesPerAlphabet`).

trufflehog 3.97.9 (run with `--no-verification`) finds 2.4% of CredData's
secrets at 57.8% precision, since it only has provider-specific detectors; see
[the results](bench/results/2026-10-16.md#5-trufflehog).

**Not yet shown:** nobody outside the project has reproduced these numbers yet. `secretscan dir . -f stats` prints
counts only (no paths, values or fingerprints) for sharing results in an issue.

Reproduce: see the [results file](bench/results/2026-10-15.md#reproduce).

## How noise is filtered

Provider rules with distinctive prefixes (`ghp_`, `AKIA`, `xoxb-`, ...) are
precise on their own. Nearly all noise comes from generic "keyword = value"
rules. Their values must pass these checks, adapted from what each tool does well:

| Filter | Rejects | Idea from |
|---|---|---|
| Character-bigram language model ("gibberish" score, `internal/wordy`), trained on CPython source | `SecurityProfiles`, `isOnDemandRevalidate`, `key-2024-primary` | detect-secrets (gibberish), trufflehog (word lists) |
| Code-identifier shape | `crypto.SHA256`, `KeyUsageCRLSign`, `C.GO_RSA_PADDING` | gitleaks (`^[a-zA-Z_.-]+$`) |
| Structure: `=` inside value, UUIDs, numbers, timestamps, `oauth-2025-04-20`, `...` truncation | kwargs, config pairs, IDs, versions | detect-secrets |
| Sequential / decoded-prose values | `0123456789…`, base64 of `a secret` or `{"foo":"bar"}` | detect-secrets |
| Key name says it isn't a secret (matched before the value) | `public_key_id`, `NextToken`, `*Name`, `*Url`, `sha256`, `nonce` | gitleaks (match allowlist) |
| Published sample credentials (stored as SHA-256) | AWS doc keys, Azure Storage emulator key, jwt.io token, Stripe doc keys | trufflehog, gitleaks |
| Charset-aware entropy floor | (raises recall) random hex at 3.0 bits, mixed-class passwords | detect-secrets |
| Symbols only in literals and env-style files | `a*b+c` in code; keeps `P@ss!...` in `.env`, YAML, Dockerfile | — |
| Word tokens: split on separators and case, words cover the value | `headersToExcludeInCacheKey`, `0011_update_proxy_permissions` | — |
| Value repeats its own key (`"webhookKey": "my_webhookKey"`) | generated API-doc placeholders | — |
| Specific rule wins over generic on overlap | duplicate reports | gitleaks |

Each filter is a few lines in `internal/detect/detect.go` with regression
tests drawn from real false positives. `--no-noise-filters` turns them off
for audits.

## Performance

All keywords are found in one Aho-Corasick pass, and each rule's regex then
runs only in a bounded window around its hits. Token rules keep RE2's
literal-prefix fast path: boundary checks happen in code, not in the regex.
Decoding candidates come from byte scanners, and huge embedded base64 blobs
are skipped. The Go stdlib (92 MB) scans in under 3 s on 2 vCPUs, and a typical
pre-commit takes a few milliseconds.

## Development

```sh
make test     # unit + end-to-end (real git repos, hooks, bare remote)
make bench
make validate # check the example config
go generate ./internal/wordy   # retrain the bigram model (default corpus: CPython stdlib)
```

Test secrets are generated at runtime, so this repository contains no
realistic tokens that would trip push protection on GitHub or Azure DevOps.

## Contributing

Issues and pull requests are welcome. False-positive and missed-secret
reports are especially useful, and so are aggregate results from your own
code (`secretscan dir . -f stats`, which contains no paths or values) and
challenges to the suppression logic. The latest security audit of triage,
`--fix` and `--verify` is in [docs/security-audit.md](docs/security-audit.md). Changes are listed in
[CHANGELOG.md](CHANGELOG.md); stability guarantees are in
[docs/compatibility.md](docs/compatibility.md). See [CONTRIBUTING.md](CONTRIBUTING.md), and
report vulnerabilities privately per [SECURITY.md](SECURITY.md).

## License

Apache License 2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE) for
third-party acknowledgements (several rule patterns are modelled on gitleaks,
MIT).
