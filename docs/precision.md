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
          ├── medium    → blocks (both policies)
          ├── low       → blocks under strict, "review" under balanced
          │               (generic values in test files: blocks unless testFixtures = "review")
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
In test or example files, contextual findings are capped at **low** and
marked as such: without a provider format the evidence is weaker. Whether
they block is a policy setting (below), not a confidence judgement.
Entropy is one signal among six, never sufficient by itself.

**Location never downgrades a provider format.** A real GitHub token in
`tests/` is still high confidence and still blocks. Test paths only withhold
one supporting signal from contextual rules.

`--verify` overrides the heuristics: a verified-live secret is high
confidence, and one the provider rejects is low.

### Policies

| | strict (default for scans and CI) | balanced (default for git hooks) |
|---|---|---|
| high / medium confidence | blocks | blocks |
| generic value in a test/example file | blocks | blocks (`testFixtures = "block"`, default) or **Needs review** (`testFixtures = "review"`) |
| other low confidence (weak evidence) | blocks | listed under **Needs review**, does not block |
| filtered as noise | counted, listable | counted, listable |

<!-- bench:policy-table -->
The trade-off is measured on CredData repositories never used for design
([2026-10-17](../bench/results/2026-10-17.md)):

| Setting | Blocking recall | Blocking precision |
|---|---|---|
| strict | 59.2% | 91.5% |
| balanced (default: `testFixtures = "block"`) | 39.9% | 90.2% |
| balanced, `testFixtures = "review"` | 22.2% | 87.4% |
<!-- /bench:policy-table -->

Blocking test fixtures raises recall *and* precision on real repositories:
credential-shaped values in test directories are usually real credentials or
copies of them. On published packages, whose test suites ship many fake keys,
it raises blocking findings from 1.85 to 2.69 per 1,000 files. Repositories
with fixture-heavy tests can choose `review`. On the regression suite balanced
blocks all 529 labeled secrets.
Set it per run (`--policy balanced`), per hook
(`secretscan install-hook --policy strict`) or per repo (`policy = "balanced"`
in `.secretscan.toml`). Hooks default to balanced because an interrupted
commit on ambiguous evidence is what drives developers to bypass hooks; CI
defaults to strict so nothing ambiguous merges without a decision. CI SARIF levels follow the policy: blocking findings
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
gitleaks dir . -f json -r - | secretscan triage - --policy balanced   # streamed: no copy on disk
gitleaks dir . -f json -r - --redact=50 | secretscan triage -          # half-redacted: prefix matching
secretscan triage /tmp/gl.json --delete-input                         # file: removed after reading
```

A report file is a copy of every secret it lists. Prefer the stream; with a
file, keep it outside the repository with 0600 permissions (secretscan warns
otherwise) and delete it. Source is read only inside `--root`, and a
history finding is checked against the file at its own commit or not at all.

Each finding becomes one of:

| Status | Meaning | Blocks? |
|---|---|---|
| verified | the source tool verified it live | yes |
| confirmed | secretscan independently reports the same secret (its confidence applies) | by policy |
| uncorroborated | no rule confirms it and no filter explains it, or conservative mode kept it (below) | strict: yes; balanced: review |
| filtered: *reason* | identified as noise: inside a digest or longer token, identifier, word-like value, UUID, published example, ... | no, but listed |

Provider-shaped values are never filtered by the generic value heuristics,
and filtered findings stay in JSON/SARIF output with their reason.

**Conservative mode (default).** Shape-only filters (identifier, UUID,
word-like, word segments, camel case, operator-in-code, key=value, e-mail,
and the name allowlists) are not applied to a value assigned to a
credential-named key, because real credentials take those shapes: UUID
access tokens, letters-only `.env` values, base64 under `key =`. Exceptions
that stay filtered: namespaced/snake-case identifiers (`ALICE_secp112r2`),
values that name a secret (`prod-db-secret-id`), and UUIDs under request-style
keys (`request_token`, `idempotency_key`). `--mode standard` applies every
filter. Scans themselves now report a UUID under a credential-named key
(`access_token`, `secretVal`, `const key`) at low confidence, with the same
request-style exceptions (shared `detect.CredentialKey` / `detect.RequestIDKey`).
Concurrency and paging tokens count as request-style: an AWS WAF
`ChangeToken` only serializes updates and grants no access, so it is not
reported even though CredData labels it as a token.

<!-- bench:triage-modes -->
It was designed on one half of CredData's repositories and is measured on
the other half, which no change has seen (gitleaks: 1,110 true, 99 false):

| Triage mode | True kept | False kept | Real secrets lost |
|---|---|---|---|
| standard | 1,005 | 68 | 105 |
| conservative (default) | 1,056 | 72 | 54 (41 are `ChangeToken`) |
<!-- /bench:triage-modes -->

The cost is review volume: on published packages gitleaks + triage reports
5.0 findings per 1,000 files instead of 2.1 (1.5 blocking under balanced).
All 91 issue-derived false positives stay filtered.

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
- **recall safety of filters**: `TestFalseNegativesPerAlphabet` runs 20,000
  random secrets per alphabet (alphanumeric, hex, base64, base64url, base32,
  passwords, lowercase+digits) through the generic pipeline in CI and fails
  if filters remove more than 0.02% of any alphabet (0.05% for passwords); each filter also has
  keep / reject / borderline cases (`TestFilterAdversarialCases`);
- **package corpora**: 52 popular npm/PyPI packages (~900 MB) where no live
  secret is expected. Findings there are mostly documentation examples and
  test fixtures, reported as findings per 1,000 files;
- **latency**: p50/p95 wall time of a staged-changes scan over 60 synthetic
  commits.

- **independent precision challenge**: [Samsung CredData](https://github.com/Samsung/CredData),
  337 real repositories with labeled credential lines (`bench/creddata.py`);
- **independent ground truth**: [leaky-repo](https://github.com/Plazmaz/leaky-repo),
  scored with its own labels and method (`bench/leaky_repo.py`);
- **adjudication**: every corpus finding is labeled by hand as
  `not-a-secret`, `example-credential` or `live-credential`
  (`bench/corpus_labels.tsv`, `bench/adjudicate.py`).

Results are in [bench/results/](../bench/results/2026-10-15.md).

## Limitations

<!-- bench:limits -->
- The labeled secrets and the issue set are this project's own; they are
  a regression suite. The independent measurements are CredData's holdout
  half and the first leaky-repo run. On the holdout secretscan's precision is
  level with gitleaks (91.5% vs 91.8%); its advantage is recall
  (59.2% vs 28.9%).
- Triage still loses real secrets: 54 of 1,110 on CredData's holdout half in
  conservative mode (105 in standard mode), 41 of them AWS WAF
  `ChangeToken` values by design.
<!-- /bench:limits -->
- Nobody outside the project has run `bench/reproduce.sh` yet; the
  `benchmark` workflow lets anyone do it in a fork.
- trufflehog was run only without verification and only on CredData and
  leaky-repo ([results](../bench/results/2026-10-16.md#5-trufflehog)).
- Not detected yet: NTLM `Authorization` headers, PASETO/PASERK, NKEY
  seeds, JWKs and OTP secrets. Basic credentials are detected when they
  decode to user:password, Bearer tokens when token-shaped.
- Filters are heuristics. Known gaps, pinned as "borderline" tests:
  passphrases made only of dictionary words under a generic key, UUID-shaped
  secrets under non-credential keys, a literal placeholder word used as a real
  password (`password = "password"`), password hashes, and values below the
  rule's entropy threshold.
- One-word default passwords plus digits (`admin123`, `root@123`,
  `Welcome@2024`, `P@ssw0rd2023`) are reported at low confidence under
  password keys outside test, example and documentation files: strict
  blocks them, balanced lists them for review. In test, example and doc
  files (including `README*`, `*.md`, `*.txt`) they are dropped as
  `default-password-in-test-or-doc`.

### Trade-offs that can hide a real credential

These are deliberate. Each is listed in the ledger (`--show-suppressed`)
when it drops a value; none applies to a provider-specific format.

- **Dropped everywhere, under every policy:**
  - a placeholder word on its own, including leet spellings: `password`,
    `P@ssw0rd`, `Passw0rd!`, `letmein`, `admin`;
  - a value containing a word that says it is fake, with or without
    digits: `test`, `dummy`, `fake`, `sample`, `example`, `demo`, `mock`,
    `placeholder`, `changeme`, `invalid`, `some`, `your`, `foo`/`bar`
    (`Test@1234`, `changeme123`). The global placeholder allowlist also
    drops any value that *contains* `example`, `sample`, `dummy`,
    `placeholder`, `changeme`, `redacted` or `notreal`, so a company or
    product name such as `Samplecorp2024!` or `examplehealth-7Hq9xK` hides
    the password it is part of;
  - passphrases made of dictionary words under a password key, with or
    without digits and separators: `correct horse battery staple`,
    `purple-monkey-dishwasher-42`, `blue.river.stone.cloud`;
  - digit-free values with `-`, `_` or `.` under a password key
    (`rltskqifajd-meyphmdn`), and short low-entropy values under generic keys
    (`secret-vkinta`);
  - quoted passwords containing `$`, `<`, `{` or `%` are not candidates
    (they are read as templates): `Pa$$w0rd`;
  - all-digit keys (`number-or-date`) and identifier-shaped unquoted values
    in source code (about 2.5% of random 32-character alphanumeric values
    assigned without quotes in a `.py`/`.js`/`.go` file).
- **Reported, but not blocking under balanced** (low confidence; strict
  blocks):
  - UUID-shaped values under credential keys (Heroku legacy keys and other
    UUID API keys are blocked only by their provider rules);
  - **local context**: credentials for loopback hosts, *private IP
    addresses* (10/8, 172.16/12, 192.168/16, also in production VPCs),
    single-label host names (`db`, `redis`, `postgres`: compose service
    names, but also short production names), single-label mDNS names
    (`devbox.local`), values in `docker-compose*.yml`, `.env.test`,
    `.env.dev`, `.env.development` and `.env.ci`, and example context for
    `.env.example`/`.sample`/`.template`. A `prod`, `production`, `prd` or
    `live` path segment (`deploy/prod/`, `docker-compose.prod.yml`,
    `values-production.yaml`) removes every local hint. Multi-label `.local`
    names (`db.prod.svc.cluster.local`, `sql01.corp.local`) and `.env.local`
    files are not local.
- Bearer tokens must contain a digit, or be at least 20 characters of mixed
  case with high entropy: single-case letter-only tokens are not reported.
