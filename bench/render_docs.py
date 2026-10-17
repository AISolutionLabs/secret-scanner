#!/usr/bin/env python3
"""Render the benchmark figures quoted in the docs from one source of truth,
bench/results/latest.json, so a number can never be updated in one place and
left stale in another.

  python3 bench/render_docs.py           # rewrite the marked regions
  python3 bench/render_docs.py --check   # exit 1 if any region is stale (CI)

A region in a Markdown file looks like
  <!-- bench:NAME -->
  ...generated text...
  <!-- /bench:NAME -->
and the install-hook message is generated into cmd/secretscan/benchfigures.go.
"""
import json, os, re, sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)


def pct(x):
    return f"{x:.1f}%"


def num(n):
    return f"{n:,}"


def regions(d):
    t, p, tr = d["tools"], d["policy"], d["triage"]
    rf = d["results_file"]
    lost_c = tr["gitleaks_true"] - tr["conservative"]["true"]
    lost_s = tr["gitleaks_true"] - tr["standard"]["true"]
    ratio = t["secretscan"]["recall"] / t["gitleaks"]["recall"]
    times = "twice" if 1.8 <= ratio < 2.3 else f"{ratio:.1f} times"
    return {
        "README.md": {
            "policy": f"""- Balanced blocks high and medium confidence, and generic values in
  test/example files. Only weak evidence (low confidence: dictionary-style
  passwords, values with few supporting signals) is printed under
  "Needs review" without blocking. On CredData repositories never used for
  design ([{d['date']}]({rf})), balanced blocks {pct(p['balanced']['recall'])} of
  labeled secrets at {pct(p['balanced']['precision'])} precision, strict {pct(p['strict']['recall'])} at {pct(p['strict']['precision'])}.
- A real credential committed as a test fixture is still a credential, so
  fixtures block by default. A repository whose tests are full of fake
  credentials can set `testFixtures = "review"` in `.secretscan.toml` (or
  `--test-fixtures review`) to list them for review instead; balanced then
  blocks {pct(p['balanced_review']['recall'])} of those labeled secrets. Provider-format tokens
  (`ghp_`, `AKIA`, private keys, ...) block in test files under every setting.""",
            "triage-modes": f"""every filter: fewer findings to review, more real secrets lost. On CredData
repositories never used to design it, conservative lost {lost_c} of gitleaks'
{num(tr['gitleaks_true'])} true findings ({tr['changetoken_lost']} of them AWS WAF `ChangeToken` values, deliberately
not treated as credentials) and standard lost {lost_s}.""",
            "holdout": f"""Latest holdout ([{d['date']}]({rf})), on {d['holdout_repos']}
repositories never used for design:

| Tool (default settings) | Precision | Recall | F1 |
|---|---|---|---|
| **secretscan** | {pct(t['secretscan']['precision'])} | **{pct(t['secretscan']['recall'])}** | **{t['secretscan']['f1']:.3f}** |
| secretscan, before the latest round | {pct(t['secretscan_prev']['precision'])} | {pct(t['secretscan_prev']['recall'])} | {t['secretscan_prev']['f1']:.3f} |
| gitleaks | {pct(t['gitleaks']['precision'])} | {pct(t['gitleaks']['recall'])} | {t['gitleaks']['f1']:.3f} |
| gitleaks + `secretscan triage` | **{pct(t['gitleaks_triage']['precision'])}** | {pct(t['gitleaks_triage']['recall'])} | {t['gitleaks_triage']['f1']:.3f} |
| trufflehog {t['trufflehog']['version']} | {pct(t['trufflehog']['precision'])} | {pct(t['trufflehog']['recall'])} | {t['trufflehog']['f1']:.3f} |

On unseen repositories secretscan matches gitleaks' precision while finding
{times} as many of the labeled secrets. Under balanced, the hook default,
{pct(p['balanced']['recall'])} of them block at {pct(p['balanced']['precision'])} precision. On the half used for design
it reaches {pct(d['dev']['precision'])} / {pct(d['dev']['recall'])}; the gap is the honest measure of how much of
that transfers. Triage drops {lost_c} of gitleaks' true findings, {tr['changetoken_lost']} of them
AWS WAF `ChangeToken` values that are deliberately not treated as
credentials.""",
        },
        "docs/precision.md": {
            "policy-table": f"""The trade-off is measured on CredData repositories never used for design
([{d['date']}](../{rf})):

| Setting | Blocking recall | Blocking precision |
|---|---|---|
| strict | {pct(p['strict']['recall'])} | {pct(p['strict']['precision'])} |
| balanced (default: `testFixtures = "block"`) | {pct(p['balanced']['recall'])} | {pct(p['balanced']['precision'])} |
| balanced, `testFixtures = "review"` | {pct(p['balanced_review']['recall'])} | {pct(p['balanced_review']['precision'])} |""",
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
    }


GO = '''// Code generated by bench/render_docs.py from bench/results/latest.json. DO NOT EDIT.

package main

// balancedPolicyFigures is quoted by install-hook.
const balancedPolicyFigures = "On CredData repositories never used for design, balanced blocks {b} of\\n" +
	"labeled secrets at {bp} precision; strict blocks {s} at {sp}.\\n"
'''


def main():
    check = "--check" in sys.argv[1:]
    d = json.load(open(os.path.join(HERE, "results", "latest.json")))
    stale = []
    for rel, regs in regions(d).items():
        path = os.path.join(ROOT, rel)
        text = open(path).read()
        new = text
        for name, body in regs.items():
            pat = re.compile(r"(<!-- bench:%s -->\n)(.*?)(<!-- /bench:%s -->)" % (re.escape(name), re.escape(name)), re.S)
            if not pat.search(new):
                sys.exit(f"{rel}: region bench:{name} not found")
            new = pat.sub(lambda m: m.group(1) + body + "\n" + m.group(3), new)
        if new != text:
            stale.append(rel)
            if not check:
                open(path, "w").write(new)
    p = d["policy"]
    go = GO.format(b=pct(p["balanced"]["recall"]), bp=pct(p["balanced"]["precision"]),
                   s=pct(p["strict"]["recall"]), sp=pct(p["strict"]["precision"]))
    gopath = os.path.join(ROOT, "cmd", "secretscan", "benchfigures.go")
    if not os.path.exists(gopath) or open(gopath).read() != go:
        stale.append("cmd/secretscan/benchfigures.go")
        if not check:
            open(gopath, "w").write(go)
    # latest.json must agree with the dated results file it cites.
    results = open(os.path.join(ROOT, d["results_file"])).read()
    t = d["tools"]
    for name in ("secretscan", "gitleaks", "gitleaks_triage"):
        for k in ("precision", "recall"):
            if pct(t[name][k]) not in results:
                sys.exit(f"{d['results_file']} does not contain {name} {k} {pct(t[name][k])} from latest.json")
    if check and stale:
        sys.exit("stale benchmark figures (run python3 bench/render_docs.py): " + ", ".join(stale))
    print(("up to date" if not stale else "rendered: " + ", ".join(stale)))


if __name__ == "__main__":
    main()
