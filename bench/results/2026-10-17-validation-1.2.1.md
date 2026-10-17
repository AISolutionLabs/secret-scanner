# Pre-release validation for 1.2.1, 2026-10-17

Validates the code to be released as 1.2.1. Everything below was run from
a fresh clone checked out at the commit named, with the binary built from
it. Nothing was tuned: detection code is unchanged since the 2026-10-17
measurement (`go run ./bench/fingerprint` = `df00bae9573b784f` at 9aa5f00,
at v1.0.0, and here), so the held-out run is a reproduction.

| | |
|---|---|
| Go and triage code validated | `7d34362ff5b6f925400040d3752852570388a8ec` |
| Later commits before the tag | `15d3400` changes only `.github/workflows/` and `CHANGELOG.md`; the commit adding this file changes only this file |
| Toolchain | go1.24.7 linux/amd64; gitleaks v8 @ b58d3f1; trufflehog 3.97.9 |
| Data | CredData @ 0b1940e (test half, 181 repositories); leaky-repo @ 2e95135 |

## Commands

```sh
git clone https://github.com/AISolutionLabs/secret-scanner && cd secret-scanner
git checkout 7d34362ff5b6f925400040d3752852570388a8ec
make build
gofmt -l . && go vet ./...
go test -race -count=1 ./...
go test -count=1 -run 'PerAlphabet|SpareRandomSecrets' ./internal/detect   # statistical, not under -race
python3 bench/render_docs.py --check --release && python3 bench/test_render_docs.py
for t in linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64 windows/arm64; do
  GOOS=${t%/*} GOARCH=${t#*/} CGO_ENABLED=0 go build -o /dev/null ./cmd/secretscan; done
# held-out benchmark (bench/fetch-corpus.sh or bench/reproduce.sh fetch the data)
python3 bench/creddata.py CredData --split test --tools 'secretscan,secretscan-balanced-blocking,secretscan-balanced-blocking(fixtures=review),gitleaks,gitleaks+triage,trufflehog,trufflehog+triage'
python3 bench/creddata.py CredData --split test --tools gitleaks+triage '--triage-args=--mode standard'
python3 bench/leaky_repo.py leaky-repo --tools secretscan,gitleaks,trufflehog
python3 bench/precision.py --tools secretscan --skip-latency
```

## Results

All passed:

- gofmt and vet clean; `go test -race ./...` ok in all 9 packages; the
  statistical per-alphabet false-negative test ok; published-figure check
  and its tests ok; all 6 release targets build.
- CI on `7d34362` and `15d3400`: tests on Linux and macOS; installer tests
  on Linux, macOS (`install.sh`) and Windows (`install.ps1`), including
  refusing a tampered binary; smoke test (installed binary passes clean
  code and blocks a generated token) on all three.

Held-out CredData (secrets-only), identical to the published figures in
[2026-10-17.md](2026-10-17.md):

| Tool | True | False | Precision | Recall |
|---|---|---|---|---|
| secretscan | 2,271 | 210 | 91.5% | 59.2% |
| secretscan, balanced blocking | 1,531 | 166 | 90.2% | 39.9% |
| secretscan, balanced, `testFixtures = "review"` | 853 | 123 | 87.4% | 22.2% |
| gitleaks | 1,110 | 99 | 91.8% | 28.9% |
| gitleaks + triage | 1,056 | 72 | 93.6% | 27.5% |
| gitleaks + triage `--mode standard` | 1,005 | 68 | 93.7% | 26.2% |
| trufflehog | 132 | 163 | 44.7% | 3.4% |
| trufflehog + triage | 130 | 75 | 63.4% | 3.4% |

trufflehog + triage is unchanged by the deterministic source selection:
CredData's trufflehog report has one source entry per finding.

leaky-repo: secretscan 65/96 risk lines (4 extra), gitleaks 21/96 (1),
trufflehog 10/96 (0). Regression suite: 529/529 labeled secrets found and
blocking, 40/40 safety cases, 0/91 issue-derived false positives, noise
3.03 / 2.75 per 1,000 files.

## Targeted regression tests for this release

| Behaviour | Test | Fails on the earlier code |
|---|---|---|
| trufflehog source chosen deterministically; conflicting locations stay uncorroborated and are never read | `TestTrufflehogSourceIsDeterministic` (every metadata order), `TestTrufflehogConflictingSourceCannotFilter` | yes: 22 failures against the v1.0.0 parser |
| same, end to end | `secretscan triage` on one finding in both key orders, 25 runs each: one identical result per case | n/a |
| no raw secret in any output; keyed fingerprints; plain `sha256:` entries still match | `TestRawSecretsNeverInOutput`, `TestKeyedFingerprints`, `TestUnexpandedCIVariableIsNotAKey` | n/a (new behaviour) |
| every filter has positive controls | `TestEveryFilterHasPositiveControls` (36 reasons) | a fake filter added to `genericNoise` fails it twice (no controls; a keep case removed) |
| no provider format downgraded by location | `TestNoProviderFormatDowngradedByLocation` (86 rules) | 682 failures with a downgrade injected |

## Not covered here

- The published release itself is verified by `verify-release.yml` after
  the tag is pushed (checksum and Sigstore signature required, provenance,
  `go install` and the pre-commit hook at the tag, on Linux, macOS and
  Windows). The Sigstore check needs network access this environment does
  not have.
- An outside reproduction and a second independently labeled corpus
  ([benchmark-policy.md](../../docs/benchmark-policy.md#6-second-independent-benchmark-protocol)).
