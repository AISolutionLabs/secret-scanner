# Compatibility policy

secretscan follows [Semantic Versioning](https://semver.org) from 1.0.0. The
following are the stable interface; changing them incompatibly requires a
new major version and a CHANGELOG entry under "Breaking":

| Interface | Guarantee |
|---|---|
| CLI commands and flags | existing commands and flags keep their meaning; removals are deprecated (warning) for at least one minor release first |
| Exit codes | `0` clean, `1` findings (or `--exit-code N`), `2` usage/config error |
| JSON report | gitleaks-compatible fields stay; new fields may be added |
| SARIF | valid SARIF 2.1.0; rule IDs are stable |
| `stats` report | `schema` is incremented on any incompatible change |
| Config (`.secretscan.toml`, `.gitleaks.toml`) | existing keys keep their meaning; unknown keys produce a warning so typos are caught |
| Rule IDs | not renamed; a removed rule is listed in the CHANGELOG |
| Ignore files and fingerprints | `file:rule:line`, `sha256:` and `hmac-sha256:` entries keep matching; `SecretHash` is plain SHA-256 hex, or `hmac-sha256:<hex>` when a hash key is set |

**Not** covered, because improving them is the point of minor releases:
which values a rule matches, noise filters, confidence levels (qualitative
evidence levels, not probabilities), and default policy blocking decisions. Minor releases can therefore report findings that
earlier versions missed, or stop reporting noise. Pin the version in CI
(`rev:` for pre-commit, a release binary with `SHA256SUMS`) and read the
CHANGELOG before upgrading. A change that makes a previously blocking
provider-format finding non-blocking is treated as breaking.
