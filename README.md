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
- **Low noise**: keyword prefilters, Shannon entropy gates, allowlists
  (paths, regexes, stopwords, commits, AND/OR, per-rule or global), placeholder and
  code-identifier suppression, and specific rules taking precedence over generic ones.
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

`--no-inline-ignore` disables inline markers, which is useful for audits.

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
    --no-color, -q/--quiet, --no-inline-ignore
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

## Performance

Rules only run their regex on line windows around keyword hits, which are found in
one Aho-Corasick pass. Decoding candidates come from byte scanners rather than regexes.
On 2 vCPUs, the Go standard library source (9,952 files, 92 MB) scans in about 8 s
with decoding on. A typical pre-commit takes a few milliseconds.

## Development

```sh
make test     # unit + end-to-end (real git repos, hooks, bare remote)
make bench
make validate # check the example config
```

Test secrets are generated at runtime, so this repository contains no
realistic tokens that would trip push protection on GitHub or Azure DevOps.
