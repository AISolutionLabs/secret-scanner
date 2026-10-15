# Precision design

secretscan is a precision-first scanner: **catch real secrets, ignore the
noise, keep every commit moving.** Alert fatigue is the failure mode it is
built against. When developers keep seeing harmless matches, they add broad
exclusions or bypass the hook, and the scanner stops protecting anyone.

The constraint is that noise must never be reduced by quietly increasing
missed secrets. Every design choice below is checked against both directions
in the [benchmark](#how-it-is-measured).

## Pipeline

```
 1. Candidate extraction   provider patterns (ghp_, AKIA, xoxb-, ...) and targeted
                           "credential-name = value" generic rules; one Aho-Corasick
                           keyword pass, regexes only in bounded windows
          │
 2. Context analysis       token boundaries (no matches inside longer tokens, digests or
                           base64 runs), the key the value is assigned to, quoting,
                           file type, test/example location, placeholders, templates
          │
 3. Evidence evaluation    independent signals → confidence; noise filters with a
                           named reason; every filtered candidate goes to a ledger
          │
          ├── high      → blocks (both policies)
          ├── medium    → blocks under strict, "review" under balanced
          ├── low       → blocks under strict, "review" under balanced
          └── filtered  → not reported, but counted and listable (--show-suppressed)
```

### Evidence and confidence

A provider-specific format (a GitHub `ghp_` token, an AWS `AKIA` key ID, a
Slack `xoxb-` token, a PEM private key) is **high** confidence on its own:
the format is the evidence.

Everything else (generic `secret = value` assignments, passwords, credentials
in URLs and connection strings, JWTs, credential file names) is scored from
independent signals:

| Signal | Example |
|---|---|
| structured credential shape | URL with `user:password@host`, JWT, connection string |
| assigned to a credential-named key | `api_secret =`, `"clientSecret":` |
| random-looking value | entropy ≥ 4.0, or long hex/base64 with high entropy |
| mixed composition / length | 3+ character classes, or ≥ 32 characters |
| literal in code or config | quoted string, `.env`, YAML, properties, Dockerfile |
| outside test/example paths | not under `tests/`, `fixtures/`, `examples/`, `docs/`, `*_test.go`, ... |

Four or more signals is **high**, three is **medium**, and fewer is **low**.
In test or example files, contextual findings are capped at **medium**.
Entropy is one signal among six, never sufficient by itself.

**Location never downgrades a provider format.** A real GitHub token in
`tests/` is still high confidence and still blocks. Test paths only withhold
one supporting signal from contextual rules.

`--verify` overrides the heuristics: a verified-live secret is high
confidence, and one the provider rejects is low.

### Policies

| | strict (default) | balanced |
|---|---|---|
| high confidence | blocks | blocks |
| medium / low | blocks | listed under **Needs review**, does not block |
| filtered as noise | counted, listable | counted, listable |

The trade-off is explicit. Balanced keeps commits moving when the evidence is
ambiguous, at the cost of letting a medium-confidence real secret through the
hook (it is still printed). On the benchmark that is 1 of 529 labeled secrets.
Unstructured values (generic matches) in test/example files are capped at
medium, since without a provider format they are most likely fixtures.
Set it per run (`--policy balanced`), per hook
(`secretscan install-hook --policy balanced`) or per repo (`policy = "balanced"`
in `.secretscan.toml`). CI SARIF levels follow the policy: blocking findings
are `error`, the rest `warning`/`note`.

Uncertainty never silently becomes a pass:

- the summary always states blocking, review, hidden (`--min-confidence`) and
  filtered counts with the top filter reasons;
- `--show-suppressed` lists every filtered candidate (file, line, rule,
  reason, redacted value), so a "missing" finding can always be explained;
- `triage` keeps anything it cannot evaluate (redacted secret, unreadable
  file, no applicable evidence) as *uncorroborated*, never filtered.

### Narrow suppressions

Broad suppressions are how scanners hide real secrets. The defaults are scoped:

| Suppression | Applies to |
|---|---|
| binary/media files, `node_modules/`, `.git/`, `.venv/` | all rules (not scannable as text / third-party) |
| lockfiles, package metadata | **generic rules only**: a credential in a `resolved` registry URL or a token in a lockfile is still reported |
| scanner configs (`.gitleaks.toml`, `.secretscan.toml`) | generic rules and custom-rule self-tests only: a real token pasted into an allowlist is still reported |
| placeholder/template values (`${VAR}`, `<token>`, `example`, `changeme`) | generic and credential rules only: never a provider-format token |
| known published examples (AWS docs keys, Azure emulator key, jwt.io token) | exact SHA-256 match only |
| inline `secretscan:allow` | that line only (`allow-next-line` for the next) |

Global allowlists in your own config can be scoped the same way with
`targetRules` or `targetTags`. Every built-in filter has a regression test
proving it does not hide a valid secret next to it
(`internal/detect/precision_test.go`).

## Precision layer for other scanners

`secretscan triage` re-scores another tool's report with the same context
analysis, so you can keep existing detection rules and cut the noise:

```sh
gitleaks dir . -f json -r gitleaks.json            # unredacted, so values can be re-checked
secretscan triage gitleaks.json --policy balanced  # or trufflehog JSON lines, or any SARIF
```

Each finding becomes one of:

| Status | Meaning | Blocks? |
|---|---|---|
| verified | the source tool verified it live | yes |
| confirmed | secretscan independently reports the same secret (its confidence applies) | by policy |
| uncorroborated | no rule confirms it and no filter explains it | strict: yes; balanced: review |
| filtered: *reason* | identified as noise: inside a digest or longer token, identifier, word-like value, UUID, published example, ... | no, but listed |

Provider-shaped values are never filtered by the generic value heuristics,
and filtered findings stay in JSON/SARIF output with their reason.

## How it is measured

`bench/precision.py` runs every tool on the same data with default settings:

- **tuning** (329) and **held-out** (160) labeled secrets in realistic files
  with hard negatives (commit SHAs, digests, UUIDs, templates, doc keys). The
  held-out set uses formats and file types never used for tuning;
- **safety** (40): secrets placed where suppressions are risky: lockfiles,
  scanner configs, test dirs, next to digests, UUIDs, AWS doc keys and inline
  ignores, and tokens containing placeholder words;
- **issues** (91 negatives): false positives quoted in public gitleaks and
  trufflehog issues
  ([#1468](https://github.com/gitleaks/gitleaks/issues/1468),
  [#1775](https://github.com/gitleaks/gitleaks/issues/1775),
  [#1321](https://github.com/gitleaks/gitleaks/issues/1321),
  [#1832](https://github.com/gitleaks/gitleaks/issues/1832),
  [trufflehog#4364](https://github.com/trufflesecurity/trufflehog/issues/4364),
  [trufflehog#3578](https://github.com/trufflesecurity/trufflehog/issues/3578)),
  plus randomized variants of each class (digests, SRCREV hashes, patch
  checksums, vault key names, identifiers, schema names, docker args,
  base64 payloads, checksums, UUIDs);
- **recall safety of filters**: `TestNoiseFiltersSpareRandomSecrets` runs
  20,000 random secrets through the generic pipeline in CI and fails if
  filters remove more than 0.01% (measured: under 0.005% on 200,000);
- **package corpora**: 52 popular npm/PyPI packages (~900 MB) where no live
  secret is expected. Findings there are mostly documentation examples and
  test fixtures, reported as findings per 1,000 files;
- **latency**: p50/p95 wall time of a staged-changes scan over 60 synthetic
  commits.

Results are in the [README](../README.md#benchmark). Caveats: the labeled secrets are generated (no
real credentials), the issue set reproduces only cases whose text the issues
quote, and trufflehog is not run directly (it needs a newer Go toolchain and
network-fetched dependencies). Its report format is supported by `triage`.
