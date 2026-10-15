# secretscan

A fast, dependency-free secret scanner for files, git history, staged changes,
outgoing pushes and raw diffs. It runs as a single static Go binary, so it
fits pre-commit/pre-push hooks, CI and git push proxies alike.

- **120+ built-in rules**: AWS (incl. Bedrock API keys), Azure (Entra ID secrets,
  storage keys, SAS, new and legacy Azure DevOps PATs), GCP, GitHub, GitLab,
  JFrog, Vault, Terraform Cloud, Slack, Stripe, OpenAI, Anthropic, LiteLLM,
  Grafana, Datadog, private keys, credentialed URLs, JWTs, generic secrets.
- **Custom patterns**: via TOML config, `--pattern` flags or a patterns file.
- **Drop-in gitleaks compatibility**: config schema, fingerprints, `.gitleaksignore`,
  `gitleaks:allow` and JSON report shape all carry over.
- **Low noise, high recall**: on the [benchmark](#benchmark) it finds more
  secrets than gitleaks or detect-secrets with equal or less noise. A
  character-level language model and structural filters reject identifiers,
  words, paths, hashes, UUIDs and published sample credentials. See
  [How noise is filtered](#how-noise-is-filtered).
- **Finds hidden secrets**: recursively decodes base64, hex and percent-encoding.
- **Safe output**: secrets are redacted by default (80% masked); reports
  carry a SHA-256 of each secret so baselines work without storing secrets.
- **Optional live verification** (`--verify`) for GitHub, GitLab, Slack,
  Stripe, OpenAI, Anthropic, Hugging Face, npm, SendGrid, DigitalOcean, Groq and Linear.
- **Reports** in text, JSON, SARIF 2.1.0, CSV and JUnit XML.

## Install

```sh
go install github.com/anirudh/secretscan/cmd/secretscan@latest
# or from source
make build            # -> bin/secretscan
make release          # linux/darwin/windows, amd64/arm64 in dist/
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
```

Exit codes: `0` clean · `1` secrets found (`--exit-code N` to change) · `2` usage or config error.

## Git hooks

`secretscan install-hook --type pre-commit|pre-push|both` writes hooks into
`git rev-parse --git-path hooks`, so `core.hooksPath` is respected.

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
  - repo: https://github.com/anirudh/secretscan
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
-f, --report-format FMT      text | json | sarif | csv | junit
-r, --report-path FILE       write report to file (format inferred from extension)
    --redact[=N]             mask N% of each secret (default 80; --redact=0 shows all)
    --exit-code N            exit code on findings (default 1)
    --min-severity LEVEL     info | low | medium | high | critical
    --max-target-megabytes N skip larger files (default 10)
    --max-decode-depth N     base64/hex/percent decoding depth (default 2, 0 = off)
    --threads N              workers (default: CPU count)
    --verify                 check secrets against provider APIs
    --only-verified          report only live secrets (with --verify)
    --timeout DUR            abort after DUR
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
and system CA settings are honored.

## Benchmark

`bench/` compares secretscan with gitleaks (v8, built from source July 2026) and
detect-secrets 1.5.0, with default settings for every tool:

- **Labeled sets:** generated secrets at known lines inside realistic files,
  including hard negatives such as commit SHAs, digests, UUIDs, `${VAR}`
  templates and AWS doc keys. The *tuning* set has 329 secrets in 10 formats.
  The *held-out* set has 160 secrets in 12 other formats (Java, C#, Kotlin,
  web.config, .properties, INI, Helm, GitHub Actions, ...) and was never used
  for tuning.
- **Real-world corpora:** popular packages that shouldn't contain live
  secrets, so every finding is noise or a published example credential.
  These are 28 npm/PyPI packages (700 MB) plus the Go standard library for
  tuning, and 24 different packages (200 MB) held out.

| Held-out (never tuned on) | Recall | Precision | npm findings | PyPI findings | Time (npm + PyPI) |
|---|---|---|---|---|---|
| **secretscan** | **100%** (96.9% before held-out fixes) | 100% | 6 | 29 | **8 s** |
| gitleaks | 85.0% | 100% | 5 | 30 | 106 s |
| detect-secrets | 73.8% | 76.6% | 616 | 37 | 746 s |

| Tuning set | Recall | Precision | npm | PyPI | Go stdlib | Time (all three corpora) |
|---|---|---|---|---|---|---|
| secretscan v1 (before this work)¹ | 96.0% | 84.5% | 628 | 1009 | 80 | 53 s |
| **secretscan** | **100%** | **100%** | **4** | **60** | **74** | **51 s** |
| gitleaks | 82.4% | 91.9% | 35 | 239 | 82 | 416 s |
| detect-secrets (labeled set only) | 73.6% | 53.1% | – | – | – | – |

¹ v1 timed with the windowing fixes from this round; as originally shipped it needed over 10 minutes on the npm corpus because of minified files.

What's left on the real-world corpora is mostly genuine-looking example
credentials: AWS documentation JSON, test fixtures with random keys, and
private keys or ECDH test vectors in Go's crypto tests. A secret scanner should
report these. gitleaks misses credentials in URLs and connection strings, Azure
SAS tokens, legacy Azure DevOps PATs and Datadog/Sentry keys. detect-secrets'
entropy plugins flag hex and base64 blobs everywhere. Times are on 2 vCPUs.

Reproduce with `bench/fetch-corpus.sh && python3 bench/run.py && HOLDOUT=1 python3 bench/run.py`.

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
