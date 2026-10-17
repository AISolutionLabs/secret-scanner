#!/usr/bin/env python3
"""Render every benchmark figure the project publishes from one source of
truth, bench/results/latest.json, and check that nothing else is published.

  python3 bench/render_docs.py                   # rewrite the generated regions
  python3 bench/render_docs.py --check           # CI: exit 1 if anything is stale or unsourced
  python3 bench/render_docs.py --check --release # also fail if detection code changed since measurement

What --check enforces:
  1. Every generated region matches latest.json. A region in a Markdown file:
       <!-- bench:NAME -->
       ...generated text...
       <!-- /bench:NAME -->
     The install-hook message is generated into cmd/secretscan/benchfigures.go.
  2. Every figure in latest.json appears in the matching row or section of the
     dated results file it cites (results_file), so latest.json cannot drift
     from the measurement it claims to summarise.
  3. No percentage is published outside a generated region, except the
     non-benchmark constants listed in ALLOWED (with the reason). Covered:
     README.md, docs/*.md, the release notes and the CHANGELOG section of
     the current version (older sections and notes are history).
  4. The detection code (rules, filters, scoring, sources; tests excluded)
     has the fingerprint recorded in latest.json. A mismatch means the
     published figures were measured on different detection code: a warning
     on ordinary pushes, an error with --release.
"""
import glob, hashlib, json, os, re, subprocess, sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
DETECTION_DIRS = ("internal/detect", "internal/config", "internal/wordy", "internal/sources")

# Percentages that are not benchmark figures. (file, exact text, reason)
ALLOWED = [
    ("README.md", "80% masked", "redaction default"),
    ("README.md", "more than 0.02% of any alphabet (0.05% for passwords", "false-negative limit enforced by tests"),
    ("docs/precision.md", "more than 0.02% of any alphabet (0.05% for passwords)", "false-negative limit enforced by tests"),
    ("docs/precision.md", "about 2.5% of random 32-character alphanumeric values", "property of random strings, measured by a unit test"),
    ("CHANGELOG.md", "`operator-in-code` about 40% of the time", "description of a fixed bug"),
]
PCT = re.compile(r"\d+(?:\.\d+)?\s?%")
REGION = re.compile(r"<!-- bench:(\S+) -->\n.*?<!-- /bench:\1 -->", re.S)


def pct(x):
    return f"{x:.1f}%"


def num(n):
    return f"{n:,}"


def current_version():
    """The version of the top CHANGELOG section: its release notes carry figures."""
    m = re.search(r"^## (\d+\.\d+\.\d+)", open(os.path.join(ROOT, "CHANGELOG.md")).read(), re.M)
    return m.group(1)


def regions(d):
    ver = current_version()
    t, p, tr, s = d["tools"], d["policy"], d["triage"], d["policy_settings"]
    lk, bd = d["leaky_repo"], d["breakdown"]
    rf = d["results_file"]
    lost_c = tr["gitleaks_true"] - tr["conservative"]["true"]
    lost_s = tr["gitleaks_true"] - tr["standard"]["true"]
    ratio = t["secretscan"]["recall"] / t["gitleaks"]["recall"]
    times = "twice" if 1.8 <= ratio < 2.3 else f"{ratio:.1f} times"
    cbp = bd["confidence_by_path"]
    conf = bd["confidence"]

    def lk_row(name, k):
        r = lk[k]
        return f"| {name} | {r['found']}/{lk['risk_lines']} ({pct(100 * r['found'] / lk['risk_lines'])}) | {r['extra']} |"

    holdout_table = f"""| Tool (default settings) | Precision | Recall | F1 |
|---|---|---|---|
| **secretscan** | {pct(t['secretscan']['precision'])} | **{pct(t['secretscan']['recall'])}** | **{t['secretscan']['f1']:.3f}** |
| secretscan, before the latest round | {pct(t['secretscan_prev']['precision'])} | {pct(t['secretscan_prev']['recall'])} | {t['secretscan_prev']['f1']:.3f} |
| gitleaks | {pct(t['gitleaks']['precision'])} | {pct(t['gitleaks']['recall'])} | {t['gitleaks']['f1']:.3f} |
| gitleaks + `secretscan triage` | **{pct(t['gitleaks_triage']['precision'])}** | {pct(t['gitleaks_triage']['recall'])} | {t['gitleaks_triage']['f1']:.3f} |
| trufflehog {t['trufflehog']['version']} (`--no-verification`) | {pct(t['trufflehog']['precision'])} | {pct(t['trufflehog']['recall'])} | {t['trufflehog']['f1']:.3f} |"""

    return {
        "README.md": {
            "policy": f"""- Balanced blocks high and medium confidence, and generic values in
  test/example files. Only weak evidence (low confidence: dictionary-style
  passwords, values with few supporting signals) is printed under
  "Needs review" without blocking. On CredData repositories never used for
  design ([{d['date']}]({rf})), balanced with the default
  `testFixtures = "block"` blocks {pct(p['balanced']['recall'])} of labeled secrets at
  {pct(p['balanced']['precision'])} precision; strict blocks everything it reports, {pct(p['strict']['recall'])} at {pct(p['strict']['precision'])}.
- A real credential committed as a test fixture is still a credential, so
  fixtures block by default. A repository whose tests are full of fake
  credentials can set `testFixtures = "review"` in `.secretscan.toml` (or
  `--test-fixtures review`) to list them for review instead; balanced then
  blocks {pct(p['balanced_review']['recall'])} of those labeled secrets at {pct(p['balanced_review']['precision'])}. Provider-format tokens
  (`ghp_`, `AKIA`, private keys, ...) block in test files under every setting.""",
            "triage-modes": f"""every filter: fewer findings to review, more real secrets lost. On CredData
repositories never used to design it, conservative lost {lost_c} of gitleaks'
{num(tr['gitleaks_true'])} true findings ({tr['changetoken_lost']} of them AWS WAF `ChangeToken` values, deliberately
not treated as credentials) and standard lost {lost_s}.""",
            "holdout": f"""Latest holdout ([{d['date']}]({rf})), on {d['holdout_repos']}
repositories never used for design:

{holdout_table}

On unseen repositories secretscan matches gitleaks' precision while finding
{times} as many of the labeled secrets. Under balanced, the hook default
(`testFixtures = "block"`), {pct(p['balanced']['recall'])} of them block at {pct(p['balanced']['precision'])} precision. On the half used for design
it reaches {pct(d['dev']['precision'])} / {pct(d['dev']['recall'])}; the gap is the honest measure of how much of
that transfers. Triage drops {lost_c} of gitleaks' true findings, {tr['changetoken_lost']} of them
AWS WAF `ChangeToken` values that are deliberately not treated as
credentials ([label disagreements](docs/benchmark-policy.md)).""",
            "leaky": f"""| Tool | Risk lines found | Extra lines (FPs) |
|---|---|---|
{lk_row("secretscan, before any leaky-repo-informed change", "secretscan_first")}
{lk_row("secretscan, current (rules added for the gaps it exposed)", "secretscan")}
{lk_row("gitleaks", "gitleaks")}
{lk_row(f"trufflehog {t['trufflehog']['version']}", "trufflehog")}
{lk_row(f"detect-secrets {lk['detect_secrets']['version']}", "detect_secrets")}""",
            "trufflehog-note": f"""trufflehog {t['trufflehog']['version']} (run with `--no-verification`) finds {pct(t['trufflehog']['recall'])} of CredData's
secrets on the holdout at {pct(t['trufflehog']['precision'])} precision, since it only has provider-specific
detectors; its recall reflects detector coverage, not its usual verified-only
workflow. See [the results]({rf}).""",
        },
        "docs/precision.md": {
            "policy-table": f"""The trade-off is measured on CredData repositories never used for design
([{d['date']}](../{rf})). Detection recall is what strict reports; blocking
recall is what each policy blocks:

| Setting | Blocking recall | Blocking precision |
|---|---|---|
| strict | {pct(p['strict']['recall'])} | {pct(p['strict']['precision'])} |
| balanced (default: `testFixtures = "block"`) | {pct(p['balanced']['recall'])} | {pct(p['balanced']['precision'])} |
| balanced, `testFixtures = "review"` | {pct(p['balanced_review']['recall'])} | {pct(p['balanced_review']['precision'])} |""",
            "confidence": f"""Measured on CredData's holdout ([{d['date']}](../{rf}#6-breakdown-of-the-holdout-run)),
with paths classified by the same test/example rule the scanner uses:

| Confidence | Other paths | Test/example paths | All |
|---|---|---|---|
| high | {pct(cbp['high, other path']['precision'])} ({num(cbp['high, other path']['true'])} true) | {pct(cbp['high, test/example path']['precision'])} ({num(cbp['high, test/example path']['true'])} true) | {pct(conf['high']['precision'])} |
| medium | {pct(cbp['medium, other path']['precision'])} ({num(cbp['medium, other path']['true'])} true) | none (capped at low) | {pct(conf['medium']['precision'])} |
| low | {pct(cbp['low, other path']['precision'])} ({num(cbp['low, other path']['true'])} true) | {pct(cbp['low, test/example path']['precision'])} ({num(cbp['low, test/example path']['true'])} true) | {pct(conf['low']['precision'])} |

Low is the most precise level because CredData labels credential-shaped
test fixtures as real secrets, and those are exactly the generic values
secretscan caps at low; outside test paths high is more precise than medium,
but the few low findings there are precise too. Provider formats
({pct(bd['detector_family']['provider format']['precision'])}) and generic rules ({pct(bd['detector_family']['generic']['precision'])}) are equally precise.""",
            "triage-modes": f"""It was designed on one half of CredData's repositories and is measured on
the other half, which no change has seen (gitleaks: {num(tr['gitleaks_true'])} true, {tr['gitleaks_false']} false):

| Triage mode | True kept | False kept | Real secrets lost |
|---|---|---|---|
| standard | {num(tr['standard']['true'])} | {tr['standard']['false']} | {lost_s} |
| conservative (default) | {num(tr['conservative']['true'])} | {tr['conservative']['false']} | {lost_c} ({tr['changetoken_lost']} are `ChangeToken`) |""",
            "limits": f"""- The labeled secrets and the issue set are this project's own; they are
  a regression suite. The independent measurements are CredData's holdout
  half and the first leaky-repo run. On the holdout secretscan's precision is
  level with gitleaks ({pct(t['secretscan']['precision'])} vs {pct(t['gitleaks']['precision'])}); its advantage is recall
  ({pct(t['secretscan']['recall'])} vs {pct(t['gitleaks']['recall'])}).
- Triage still loses real secrets: {lost_c} of {num(tr['gitleaks_true'])} on CredData's holdout half in
  conservative mode ({lost_s} in standard mode), {tr['changetoken_lost']} of them AWS WAF
  `ChangeToken` values by design.""",
        },
        f"docs/release-notes/v{ver}.md": {
            "release": f"""Samsung CredData, {d['holdout_repos']} repositories never used for design
(secrets-only labels, default settings):

| Tool | Precision | Recall | F1 |
|---|---|---|---|
| **secretscan {ver}** | {pct(t['secretscan']['precision'])} | **{pct(t['secretscan']['recall'])}** | **{t['secretscan']['f1']:.3f}** |
| gitleaks | {pct(t['gitleaks']['precision'])} | {pct(t['gitleaks']['recall'])} | {t['gitleaks']['f1']:.3f} |
| gitleaks + `secretscan triage` | **{pct(t['gitleaks_triage']['precision'])}** | {pct(t['gitleaks_triage']['recall'])} | {t['gitleaks_triage']['f1']:.3f} |
| trufflehog {t['trufflehog']['version']} (`--no-verification`) | {pct(t['trufflehog']['precision'])} | {pct(t['trufflehog']['recall'])} | {t['trufflehog']['f1']:.3f} |

secretscan matches gitleaks' precision on these repositories and finds
{times} as many of the labelled secrets. With the hook default (balanced,
`testFixtures = "block"`), {pct(p['balanced']['recall'])} of the labelled secrets block, at {pct(p['balanced']['precision'])}
precision; strict blocks all {pct(p['strict']['recall'])} it reports. On the half of CredData used
for design, secretscan reaches {pct(d['dev']['precision'])} precision and {pct(d['dev']['recall'])} recall. The gap
between the two halves shows how much of the tuning carries over to
repositories it has not seen. trufflehog was run without verification, so
its recall reflects detector coverage, not its usual verified-only workflow.""",
            "release-limits": f"""- {100 - t['secretscan']['recall']:.0f}% of CredData's labelled secrets on unseen repositories are not
  found ({pct(t['secretscan']['recall'])} recall). Balanced trades recall for fewer interruptions
  ({pct(p['balanced']['recall'])} of labelled secrets block with the default `testFixtures = "block"`);
  use strict where that matters more.
- In its default conservative mode, triage drops {lost_c} of gitleaks'
  {num(tr['gitleaks_true'])} true findings on unseen repositories. {tr['changetoken_lost']} of those are AWS WAF
  `ChangeToken` values, which are deliberately not treated as
  credentials ([label policy](https://github.com/AISolutionLabs/secret-scanner/blob/v{ver}/docs/benchmark-policy.md)).""",
        },
    }


def sourced(d):
    """(section number, row label or None, [expected cells or phrases]) for
    every figure in latest.json, checked against the dated results file."""
    t, p, tr, bd, lk = d["tools"], d["policy"], d["triage"], d["breakdown"], d["leaky_repo"]

    def tp(x):
        return [pct(x["precision"]), pct(x["recall"])]

    out = [
        (1, "secretscan, now", tp(t["secretscan"]) + [f"{t['secretscan']['f1']:.3f}"]),
        (1, "secretscan, before this round", tp(t["secretscan_prev"]) + [f"{t['secretscan_prev']['f1']:.3f}"]),
        (1, "gitleaks", tp(t["gitleaks"]) + [num(tr["gitleaks_true"]), str(tr["gitleaks_false"])]),
        (1, "gitleaks + triage, now", tp(t["gitleaks_triage"]) + [num(tr["conservative"]["true"]), str(tr["conservative"]["false"])]),
        (1, "gitleaks + triage `--mode standard`", [num(tr["standard"]["true"]), str(tr["standard"]["false"])]),
        (1, "trufflehog", tp(t["trufflehog"]) + [f"{t['trufflehog']['f1']:.3f}"]),
        (1, "secretscan, blocking under balanced", tp(p["balanced"])),
        (1, 'secretscan, blocking under balanced with `testFixtures = "review"`', tp(p["balanced_review"])),
        (1, None, [f"{tr['changetoken_lost']} of them"]),
        (0, None, [f"{d['holdout_repos']} repositories", t["trufflehog"]["version"]]),
        (2, "secretscan, now", [pct(d["dev"]["precision"]), pct(d["dev"]["recall"])]),
        (6, "strict (detection)", tp(p["strict"])),
        (7, None, [str(d["disagreements"]["changetoken_missed_lines"]), pct(d["disagreements"]["recall_excluding"])]),
    ]
    for group in ("confidence", "path", "context", "detector_family", "confidence_by_path"):
        for name, r in bd[group].items():
            out.append((6, name, [num(r["true"]), str(r["false"]), pct(r["precision"])]))
    for k, label in (("secretscan", "secretscan"), ("gitleaks", "gitleaks"), ("trufflehog", "trufflehog"), ("detect_secrets", "detect-secrets")):
        out.append((8, label, [f"{lk[k]['found']}/{lk['risk_lines']}", str(lk[k]["extra"])]))
    return out


def historical(d):
    """(results file, row prefix, cells) for baselines from earlier rounds."""
    lk = d["leaky_repo"]
    f = lk["secretscan_first"]
    return [(lk["first_results_file"], "| secretscan |", [f"{f['found']}/{lk['risk_lines']}", f" {f['extra']} |"])]


def sections(text):
    out, cur = {}, 0  # 0: the preamble before "## 1."
    for line in text.splitlines():
        m = re.match(r"## (\d+)\.", line)
        if m:
            cur = int(m.group(1))
        out.setdefault(cur, []).append(line)
    return out


def check_sourced(d, results_text):
    errs = []
    secs = sections(results_text)
    for sec, label, want in sourced(d):
        lines = secs.get(sec)
        if not lines:
            errs.append(f"section {sec} missing")
            continue
        if label is None:
            body = "\n".join(lines)
            errs += [f"section {sec}: {w!r} not found" for w in want if w not in body]
            continue
        rows = [l.replace("*", "") for l in lines if l.startswith("|")]
        def first(r):
            return [c.strip() for c in r.strip("|").split("|")][0].rstrip("¹")
        row = [r for r in rows if first(r) == label] or [r for r in rows if first(r).startswith(label + " ")]
        if not row:
            errs.append(f"section {sec}: no row {label!r}")
            continue
        cells = [c.strip() for c in row[0].strip("|").split("|")]
        errs += [f"section {sec}, row {label!r}: {w!r} not in {cells}" for w in want if not any(w == c or c.startswith(w + " ") for c in cells)]
    return errs


def published(d):
    """Files whose figures must all come from latest.json: (path, text)."""
    files = ["README.md"] + sorted(glob.glob(os.path.join(ROOT, "docs", "*.md")))
    out = []
    for f in files:
        rel = os.path.relpath(f, ROOT) if os.path.isabs(f) else f
        out.append((rel, open(os.path.join(ROOT, rel)).read()))
    ch = open(os.path.join(ROOT, "CHANGELOG.md")).read()
    m = re.search(r"^## (\d+\.\d+\.\d+)[^\n]*\n(.*?)(?=^## |\Z)", ch, re.S | re.M)
    if m:
        out.append(("CHANGELOG.md", m.group(2)))
        notes = os.path.join(ROOT, "docs", "release-notes", f"v{m.group(1)}.md")
        if os.path.exists(notes):
            out.append((os.path.relpath(notes, ROOT), open(notes).read()))
    return out


def check_unsourced(d):
    errs = []
    for rel, text in published(d):
        if rel == "docs/security-audit.md":
            continue  # no benchmark figures; percentages there describe bugs
        outside = REGION.sub("", text)
        for a_file, a_text, _ in ALLOWED:
            if a_file == rel:
                outside = outside.replace(a_text, "")
        for i, line in enumerate(outside.splitlines(), 1):
            if PCT.search(line):
                errs.append(f"{rel}: figure outside a generated region: {line.strip()[:100]!r} "
                            "(generate it from latest.json, or add it to ALLOWED if it is not a benchmark figure)")
    return errs


def fingerprint(root=ROOT):
    """Hash of the detection code without comments (bench/fingerprint)."""
    p = subprocess.run(["go", "run", "./bench/fingerprint", os.path.abspath(root)], cwd=ROOT, capture_output=True, text=True)
    if p.returncode != 0:
        raise SystemExit("bench/fingerprint failed: " + p.stderr)
    return p.stdout.strip()


def render(d, root=ROOT):
    """Return {path: new text} for every file whose generated content changed."""
    changed = {}
    for rel, regs in regions(d).items():
        path = os.path.join(root, rel)
        text = open(path).read()
        new = text
        for name, body in regs.items():
            pat = re.compile(r"(<!-- bench:%s -->\n)(.*?)(<!-- /bench:%s -->)" % (re.escape(name), re.escape(name)), re.S)
            if not pat.search(new):
                raise SystemExit(f"{rel}: region bench:{name} not found")
            new = pat.sub(lambda m: m.group(1) + body + "\n" + m.group(3), new)
        if new != text:
            changed[rel] = new
    p = d["policy"]
    go = GO.format(b=pct(p["balanced"]["recall"]), bp=pct(p["balanced"]["precision"]),
                   s=pct(p["strict"]["recall"]), sp=pct(p["strict"]["precision"]))
    gopath = os.path.join(root, "cmd", "secretscan", "benchfigures.go")
    if not os.path.exists(gopath) or open(gopath).read() != go:
        changed["cmd/secretscan/benchfigures.go"] = go
    return changed


GO = '''// Code generated by bench/render_docs.py from bench/results/latest.json. DO NOT EDIT.

package main

// balancedPolicyFigures is quoted by install-hook.
const balancedPolicyFigures = "On CredData repositories never used for design, balanced (testFixtures = \\"block\\")\\n" +
	"blocks {b} of labeled secrets at {bp} precision; strict blocks {s} at {sp}.\\n"
'''


def main():
    args = sys.argv[1:]
    check, release = "--check" in args, "--release" in args
    d = json.load(open(os.path.join(HERE, "results", "latest.json")))
    changed = render(d)
    if not check:
        for rel, text in changed.items():
            open(os.path.join(ROOT, rel), "w").write(text)
    errs = check_sourced(d, open(os.path.join(ROOT, d["results_file"])).read())
    errs = [f"{d['results_file']}: {e}" for e in errs]
    # Historical baselines quoted next to current figures come from older results files.
    for rel, row, cells in historical(d):
        text = open(os.path.join(ROOT, rel)).read()
        if not any(l.startswith(row) and all(c in l for c in cells) for l in text.splitlines()):
            errs.append(f"{rel}: no line starting {row!r} with {cells}")
    # Region contents are generated, so only text outside them is checked;
    # with --check, check the files as they would be after rendering.
    errs += check_unsourced(d)
    fp = fingerprint()
    if fp != d.get("detection_fingerprint"):
        msg = (f"detection code fingerprint {fp} differs from {d.get('detection_fingerprint')} recorded in latest.json "
               f"(measured at {d.get('measured_commit')}): the published figures describe different detection code. "
               "Re-run bench/reproduce.sh and update latest.json and the results file.")
        if release:
            errs.append(msg)
        else:
            print(f"::warning::{msg}" if os.environ.get("GITHUB_ACTIONS") else f"warning: {msg}", file=sys.stderr)
    if check and changed:
        errs.append("stale generated figures (run python3 bench/render_docs.py): " + ", ".join(sorted(changed)))
    if errs:
        sys.exit("\n".join(errs))
    print("up to date" if check or not changed else "rendered: " + ", ".join(sorted(changed)))


if __name__ == "__main__":
    main()
