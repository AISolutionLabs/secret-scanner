# Contributing

Thanks for helping make secretscan better. Bug reports, false-positive and
missed-secret reports, new rules and docs are all welcome.

## Ground rules

- **Never commit a real or realistic secret**, not even a revoked one. Tests
  build sample tokens at runtime (see `samples()` in
  `internal/detect/detect_test.go`), so the repository never trips push
  protection. CI scans this repo's own history with secretscan.
- Keep it dependency-free: the module uses only the Go standard library.
- By contributing you agree that your contributions are licensed under the
  Apache License 2.0 (inbound = outbound). No CLA is required. Sign off your
  commits (`git commit -s`) to certify the
  [Developer Certificate of Origin](https://developercertificate.org/).

## Development

```sh
make build     # bin/secretscan
make test      # vet + race tests, including end-to-end git hook tests
make bench     # detection micro-benchmark
make validate  # example config self-tests
```

Requires Go (see `go.mod`) and git. Python 3 and Node are used, when present,
to syntax-check the remediation snippets.

## Adding or changing a rule

1. Add the rule to `internal/config/defaults.go`: an `id`, a precise regex,
   **keywords** (required: they are the prefilter that keeps scans fast), a
   severity and tags. Use `tok(...)` for prefixed tokens and `semi(...)` for
   `keyword = value` shapes.
2. Add a generated sample to `samples()` in `internal/detect/detect_test.go`.
   `TestEveryDefaultRuleDetects` fails until you do.
3. Add the issuer to `internal/remediate/remediate.go` if it has its own
   rotation steps or a keyless alternative.
4. For detection changes, run the benchmark before and after and put both
   numbers in the PR:

   ```sh
   bench/fetch-corpus.sh                  # once
   python3 bench/precision.py             # recall, precision, issue FPs, noise, latency vs gitleaks
   HOLDOUT=1 python3 bench/run.py secretscan
   ```

   A change that reduces noise must not reduce recall on the tuning,
   held-out or safety sets.

   Don't tune against the held-out set. It exists to catch overfitting.

## False-positive filters

See [docs/precision.md](docs/precision.md) for the pipeline, the evidence
model and the suppression rules.


Generic-rule filters live in `internal/detect/detect.go` (`genericNoise`,
`weakPasswordNoise`, ...) and must return a named reason (it appears in the
suppression ledger). Every filter needs:

- a regression test with the real false positive that motivated it (sanitized);
- a case in `internal/detect/precision_test.go` proving it does not hide a
  valid secret next to it;
- no recall loss on the tuning, held-out or safety sets.

Value-based suppressions must be scoped to generic rules (`targetTags`):
never filter a provider-format token with a word list.

## Reporting security issues

See [SECURITY.md](SECURITY.md). Please don't open public issues for vulnerabilities.
