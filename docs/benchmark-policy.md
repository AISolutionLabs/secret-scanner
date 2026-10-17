# Benchmark policy

How secretscan's published figures are produced, what they may and may not
be compared with, and what happens when a dataset's labels disagree with
the scanner's definition of a credential. The rules here were written down
before the second independent benchmark (below) was run.

## 1. One source for every published figure

Every benchmark figure in the README, `docs/`, the CHANGELOG, the release
notes and the `install-hook` message is generated from
[`bench/results/latest.json`](../bench/results/latest.json) by
`bench/render_docs.py`. CI runs it with `--check`, which fails when:

- a generated passage differs from what `latest.json` produces;
- a figure in `latest.json` is not in the matching row or section of the
  dated results file it cites (`results_file`), or a historical baseline is
  not in the older results file it comes from;
- any percentage appears in those documents outside a generated passage,
  unless it is a listed non-benchmark constant (the redaction default, the
  false-negative limits enforced by unit tests);
- a published balanced-policy figure does not name its `testFixtures`
  setting (`bench/test_render_docs.py`).

A dated results file (`bench/results/YYYY-MM-DD.md`) records one
measurement and is not edited afterwards, except to add analysis of the same
run, marked as such.

## 2. Labels are used as given

Headline figures use each dataset's labels exactly as published. secretscan
does not relabel a dataset to agree with itself, even when the scanner's
behaviour is deliberate and arguably correct. Two views are fixed per dataset
before any tool is run (for CredData: `official`, and `secrets-only`, which
leaves out categories that are identifiers rather than secrets, such as
UUIDs and bucket names); both are published.

## 3. Label disagreements

A disagreement is a class of values the dataset labels one way and
secretscan deliberately treats the other way, by a rule decided for reasons
unrelated to the dataset. Disagreements are:

- **listed** here, with the reason the scanner treats the class as it does;
- **counted** in the dated results file (how many labeled lines they cover);
- **reported as a secondary figure only** ("recall excluding documented
  disagreements"), never in place of the as-labeled figure;
- **never added after looking at the holdout half** to explain away a result.
  A disagreement found while analysing the holdout is reported as a miss or
  false positive; it can be added to this list only for the next round.

| Class | Dataset label | secretscan | Reason | Lines (CredData test half) |
|---|---|---|---|---|
| AWS WAF `ChangeToken` | true (secret) | not reported | Orders WAF updates and grants no access; AWS returns it from `GetChangeToken` to any caller | 42 missed lines; 41 of gitleaks' true findings dropped by triage |

The count and the secondary recall are in the dated results file.

## 4. Dev / test split and the holdout

CredData's repositories are split by `sha256(RepoName)` (first hex digit
0-7: dev, otherwise test), fixed before any per-half result was seen.
Changes informed by CredData are designed on dev only. The test half is
measured once per round, after all changes are merged; analysis of that
run (`bench/breakdown.py`) re-scores the same report and runs no scanner.

## 5. Frozen detection code

`bench/results/latest.json` records `detection_fingerprint`, a hash of the
detection code the figures were measured on (rules, filters, scoring and
input handling in `internal/detect`, `internal/config`, `internal/wordy` and
`internal/sources`; tests excluded), and `measured_commit`.

- On ordinary pushes CI warns when the detection code no longer matches.
- The release workflow runs `render_docs.py --check --release`, which
  fails: a release cannot ship benchmark figures measured on different
  detection code.

## 6. Second independent benchmark: protocol

CredData and leaky-repo are the only independent labeled data used so far.
CredData's dev half has informed changes, and leaky-repo informed several
rules, so neither is a fully clean test any more. The next benchmark must be
run on a corpus that:

1. was **labeled by someone other than this project**, before secretscan
   was run on it;
2. **has not been used** to design or tune secretscan, and will not be until
   the run is published;
3. is **frozen** (commit or archive hash recorded) before the run.

Procedure:

1. Record the corpus hash, the label file hash and the detection
   fingerprint (`python3 -c 'import sys; sys.path.insert(0, "bench"); import render_docs; print(render_docs.fingerprint())'`).
2. Run `bench/score_labeled.py CORPUS LABELS.csv --json results.json`
   (default settings for every tool, verification off for every tool).
3. Publish the table, the JSON (missed and false-positive lines included)
   and the hashes as a dated results file, whatever the outcome.
4. Only then look at individual misses; changes they inspire are measured
   on a different corpus.

An outside reproduction of the CredData figures is equally welcome:
`bench/reproduce.sh`, or the `benchmark` workflow in a fork, regenerates
every number with pinned tool and dataset versions.

## 7. What the figures do not show

- **Confidence is not a probability.** Precision by confidence level is
  published, and it is not monotonic on CredData (see
  [docs/precision.md](precision.md#what-confidence-means-and-what-it-does-not)).
- **Detection recall is not blocking recall.** Strict blocks everything it
  reports; balanced blocks less. Both are published for every setting.
- **No real-developer dismissal rates yet.** `secretscan dir . -f stats`
  produces anonymized counts that teams can share.
