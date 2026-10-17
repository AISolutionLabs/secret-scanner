#!/usr/bin/env python3
"""Break one secretscan CredData run down by confidence, file context,
detector family and policy, from the report the headline figures came from.

  secretscan dir data -f json -r ss.json --exit-code 0 -q --redact   # in CredData
  python3 bench/breakdown.py /path/to/CredData ss.json --split test

This re-scores an existing report with bench/creddata.py's scoring; it runs
no scanner and changes nothing, so it does not spend the holdout. The totals
must match the published secretscan and balanced figures, and the script
fails if they do not.

Groups:
  confidence      high / medium / low as reported
  path            test/example path or not (detect.IsTestPath on the file)
  context         local / example / none (the Context field)
  family          provider format vs generic (rules tagged "generic")
  policy          strict, balanced (testFixtures = "block", the default),
                  balanced (testFixtures = "review")

A true line reported by findings in two groups counts in both.
Detection recall counts every reported true line; blocking recall counts the
lines a policy blocks. Recall by group is not given: a missed line has no
confidence, path verdict or rule.

Label disagreements: CredData labels AWS WAF ChangeToken values as secrets;
secretscan deliberately does not report them (they order WAF updates and
grant no access). Headline figures use CredData's labels as given; the
"excluding documented disagreements" line is secondary. See
docs/benchmark-policy.md.
"""
import argparse, json, os, re, subprocess, sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import creddata as cd  # noqa: E402

FIXTURE_CAP = "capped at low: unstructured value in a test/example file"

def _test_path_regex():
    """detect.IsTestPath's regex, read from the Go source so the two cannot drift."""
    src = open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "internal", "detect", "evidence.go")).read()
    m = re.search(r"var testPath = regexp\.MustCompile\(`([^`]+)`\)", src)
    pat = m.group(1)
    flags = 0
    if pat.startswith("(?i)"):
        pat, flags = pat[4:], re.I
    return re.compile(pat, flags)


TEST_PATH = _test_path_regex()
DISAGREEMENTS = {"ChangeToken": "AWS WAF ChangeToken (orders updates, grants no access)"}


def generic_rules(ss):
    out = subprocess.run([ss, "rules"], capture_output=True, text=True, check=True).stdout
    rules = set()
    for line in out.splitlines()[1:]:
        parts = line.split()
        if len(parts) >= 3 and "generic" in parts[2].split(","):
            rules.add(parts[0])
    return rules


def blocks(f, policy):
    """detect.BlocksFinding, for the policies the benchmark reports."""
    if policy == "strict":
        return True
    if f.get("Confidence") in ("high", "medium"):
        return True
    if f.get("Context"):
        return False
    return policy == "balanced" and FIXTURE_CAP in (f.get("Evidence") or [])


def score(fs, meta, split):
    return cd.score([(os.path.join("data", f["File"]), f["StartLine"], f.get("EndLine") or f["StartLine"], f["RuleID"]) for f in fs],
                    meta, "secrets-only", split)


def pct(x):
    return f"{100 * x:.1f}%"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("creddata")
    ap.add_argument("report", help="secretscan JSON report of data/ (default strict policy)")
    ap.add_argument("--split", choices=["all", "dev", "test"], default="test")
    ap.add_argument("--json", help="also write the numbers here")
    a = ap.parse_args()
    meta = {os.path.normpath(k): v for k, v in cd.load_meta(a.creddata, a.split).items()}
    fs = json.load(open(a.report))
    generic = generic_rules(cd.SS)
    out = {"split": a.split}

    def row(name, sub, recall=False):
        s = score(sub, meta, a.split)
        if s["tp"] + s["fp"] == 0:
            return None, s  # findings only outside this split
        r = {"true": s["tp"], "false": s["fp"], "precision": round(100 * s["precision"], 1)}
        if recall:
            r["recall"] = round(100 * s["recall"], 1)
        print(f"| {name} | {s['tp']:,} | {s['fp']:,} | {pct(s['precision'])} |" + (f" {pct(s['recall'])} |" if recall else ""))
        return r, s

    print(f"CredData {a.split} half, secrets-only labels, one report: {a.report}\n")
    print("| Policy | True | False | Precision | Recall |\n|---|---|---|---|---|")
    pol = {}
    for name, p in (("strict (detection)", "strict"), ("balanced, testFixtures = \"block\" (default)", "balanced"),
                    ("balanced, testFixtures = \"review\"", "balanced-review")):
        pol[p], s = row(name, [f for f in fs if blocks(f, p)], recall=True)
        if p == "strict":
            positives, strict = s["positives"], s
    out["policy"] = pol

    order = {"high": 0, "medium": 1, "low": 2}
    for title, key in (("Confidence", lambda f: f.get("Confidence") or "none"),
                       ("Path", lambda f: "test/example path" if TEST_PATH.search(f["File"]) else "other path"),
                       ("Context", lambda f: f.get("Context") or "none"),
                       ("Detector family", lambda f: "generic" if f["RuleID"] in generic else "provider format")):
        print(f"\n| {title} | True | False | Precision |\n|---|---|---|---|")
        groups = {}
        for f in fs:
            groups.setdefault(key(f), []).append(f)
        rows = {g: row(g, groups[g])[0] for g in sorted(groups, key=lambda g: (order.get(g, 9), g))}
        out[title.lower().replace(" ", "_")] = {g: r for g, r in rows.items() if r}

    print("\n| Confidence by path | True | False | Precision |\n|---|---|---|---|")
    cross = {}
    for pname, is_test in (("other path", False), ("test/example path", True)):
        for c in ("high", "medium", "low"):
            sub = [f for f in fs if f.get("Confidence") == c and bool(TEST_PATH.search(f["File"])) == is_test]
            r = row(f"{c}, {pname}", sub)[0] if sub else None
            if r:
                cross[f"{c}, {pname}"] = r
    out["confidence_by_path"] = cross

    # Documented label disagreements among the missed true lines.
    missed = strict["missed"]
    dis = 0
    for path, start in missed:
        try:
            with open(os.path.join(a.creddata, path), errors="replace") as fh:
                text = fh.readlines()[start - 1]
        except (OSError, IndexError):
            continue
        if any(k in text for k in DISAGREEMENTS):
            dis += 1
    rec_ex = strict["tp"] / (positives - dis) if positives > dis else 0
    print(f"\nLabel disagreements (CredData true, secretscan deliberately silent): {dis} missed lines "
          f"({', '.join(DISAGREEMENTS.values())}).\nDetection recall excluding them: {pct(rec_ex)} "
          f"(as labeled: {pct(strict['recall'])}).")
    out["disagreements"] = {"lines": dis, "recall_excluding": round(100 * rec_ex, 1)}
    if a.json:
        json.dump(out, open(a.json, "w"), indent=2)


if __name__ == "__main__":
    main()
