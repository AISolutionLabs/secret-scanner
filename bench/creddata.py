#!/usr/bin/env python3
"""Score scanners on Samsung CredData (https://github.com/Samsung/CredData):
~11.5k files from 337 real GitHub repositories with manually labeled
credential lines (secrets obfuscated, formats preserved). secretscan was not
developed or tuned on it.

  python3 bench/creddata.py /path/to/CredData [--tools secretscan,gitleaks,gitleaks+triage,detect-secrets]

detect-secrets is run with --no-verify: by default it sends matches to provider
APIs. Expect it to take about an hour on CredData; the others take minutes.

Scoring is per line, as in CredData's own benchmark: a reported line inside
a row labeled T is a true positive; a reported line whose rows are all F/X is
a false positive; T lines not reported are misses. Findings on lines with no
label at all are counted separately as "unlabeled": CredData's labels were
built by reviewing what earlier tools reported, so they are neither true nor
false positives by its method.

Two views, fixed before any tool was run on the data:
  official      CredData's labels as given
  secrets-only  the same, without categories that are identifiers rather
                than secrets: UUID, AWS S3 Bucket, Firebase Domain,
                Tencent WeChat API App ID, Nonce, Salt. A T row in only these
                categories counts as unlabeled in this view.
"""
import argparse, collections, csv, glob, json, os, shutil, subprocess, sys, tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
SS = os.environ.get("SECRETSCAN", os.path.join(HERE, "..", "bin", "secretscan"))
GL = os.environ.get("GITLEAKS", shutil.which("gitleaks") or "")
IDENTIFIER_CATEGORIES = {"UUID", "AWS S3 Bucket", "Firebase Domain", "Tencent WeChat API App ID", "Nonce", "Salt"}


def load_meta(root):
    rows = collections.defaultdict(list)  # path -> [(start, end, label, categories)]
    for p in glob.glob(os.path.join(root, "meta", "*.csv")):
        for r in csv.DictReader(open(p)):
            rows[r["FilePath"]].append((int(r["LineStart"]), int(r["LineEnd"]), r["GroundTruth"], set(r["Category"].split(":"))))
    return rows


def label(rows, line, view):
    """T, F or None (unlabeled) for one reported line."""
    hits = [r for r in rows if r[0] <= line <= max(r[0], r[1])]
    if not hits:
        return None
    if view == "secrets-only":
        t = [r for r in hits if r[2] == "T" and not r[3] <= IDENTIFIER_CATEGORIES]
        if t:
            return "T"
        if any(r[2] == "T" for r in hits):
            return None  # identifier-only: excluded in this view
        return "F"
    return "T" if any(r[2] == "T" for r in hits) else "F"


def true_lines(meta, view):
    out = set()
    for path, rows in meta.items():
        for s, e, gt, cats in rows:
            if gt == "T" and (view == "official" or not cats <= IDENTIFIER_CATEGORIES):
                out.add((path, s))
    return out


def run(cmd, cwd):
    return subprocess.run(cmd, cwd=cwd, capture_output=True, text=True)


def tmpjson():
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as t:
        return t.name


def secretscan(root):
    out = tmpjson()
    try:
        run([SS, "dir", "data", "-f", "json", "-r", out, "--exit-code", "0", "-q", "--redact"], root)
        # secretscan reports paths relative to the scanned directory
        return [(os.path.join("data", f["File"]), f["StartLine"], f.get("EndLine") or f["StartLine"], f["RuleID"]) for f in json.load(open(out))]
    finally:
        os.remove(out)


def gitleaks(root):
    out = tmpjson()
    try:
        run([GL, "dir", "data", "-f", "json", "-r", out, "--exit-code", "0", "--no-banner", "--log-level", "error", "--redact"], root)
        return [(f["File"], f["StartLine"], f.get("EndLine") or f["StartLine"], f["RuleID"]) for f in json.load(open(out))]
    finally:
        os.remove(out)


def gitleaks_triage(root):
    """gitleaks streamed into `secretscan triage` (no report on disk); findings
    triage filters as noise are dropped, everything else is kept."""
    out = tmpjson()
    try:
        gl = subprocess.Popen([GL, "dir", "data", "-f", "json", "-r", "-", "--no-banner", "--log-level", "error", "--exit-code", "0"],
                              cwd=root, stdout=subprocess.PIPE)
        subprocess.run([SS, "triage", "-", "--root", ".", "-f", "json", "-r", out, "--exit-code", "0", "-q"], cwd=root, stdin=gl.stdout)
        gl.wait()
        return [(f["File"], f["StartLine"], f.get("EndLine") or f["StartLine"], f["RuleID"]) for f in json.load(open(out))
                if not (f.get("Triage") or "").startswith("filtered")]
    finally:
        os.remove(out)


def detect_secrets(root):
    p = run(["detect-secrets", "scan", "--no-verify", "--all-files", "data"], root)
    res = json.loads(p.stdout)["results"]
    return [(f, it["line_number"], it["line_number"], it["type"]) for f, items in res.items() for it in items]


TOOLS = {"secretscan": secretscan, "gitleaks": gitleaks, "gitleaks+triage": gitleaks_triage, "detect-secrets": detect_secrets}


def score(findings, meta, view):
    tl = true_lines(meta, view)
    found_t, fp, unl = set(), set(), set()
    for f, s, e, _ in findings:
        f = os.path.normpath(f)
        rows = meta.get(f, [])
        lab = None
        for line in range(s, max(s, e) + 1):  # multi-line findings (keys) match any covered line
            lab = label(rows, line, view)
            if lab == "T":
                # credit the T row this line belongs to
                for r in rows:
                    if r[2] == "T" and r[0] <= line <= max(r[0], r[1]):
                        found_t.add((f, r[0]))
                break
        if lab == "F":
            fp.add((f, s))
        elif lab is None:
            unl.add((f, s))
    tp = len(found_t & tl)
    prec = tp / (tp + len(fp)) if tp + len(fp) else 0
    rec = tp / len(tl) if tl else 0
    f1 = 2 * prec * rec / (prec + rec) if prec + rec else 0
    return {"tp": tp, "fp": len(fp), "fn": len(tl) - tp, "unlabeled": len(unl), "precision": prec, "recall": rec, "f1": f1,
            "positives": len(tl), "unlabeled_lines": sorted(unl), "fp_lines": sorted(fp), "missed": sorted(tl - found_t)}


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("creddata")
    ap.add_argument("--tools", default="secretscan,gitleaks,gitleaks+triage,detect-secrets")
    ap.add_argument("--dump", help="write per-tool line lists (JSON) here")
    a = ap.parse_args()
    meta = load_meta(a.creddata)
    commit = run(["git", "rev-parse", "--short", "HEAD"], a.creddata).stdout.strip()
    nfiles = sum(len(fs) for _, _, fs in os.walk(os.path.join(a.creddata, "data")))
    print(f"CredData @ {commit}: {nfiles} files, {len(true_lines(meta, 'official'))} true lines "
          f"({len(true_lines(meta, 'secrets-only'))} excluding identifier categories)\n")
    dump = {}
    results = {}
    for name in a.tools.split(","):
        if name.startswith("gitleaks") and not GL or name == "detect-secrets" and not shutil.which("detect-secrets"):
            print(f"skipping {name}: not installed", file=sys.stderr)
            continue
        results[name] = TOOLS[name](a.creddata)
    for view in ("official", "secrets-only"):
        print(f"### {view}\n")
        print("| Tool | TP | FP | FN | Precision | Recall | F1 | Findings on unlabeled lines |\n|---|---|---|---|---|---|---|---|")
        for name, fs in results.items():
            r = score(fs, meta, view)
            dump[f"{name}/{view}"] = {k: r[k] for k in ("unlabeled_lines", "fp_lines", "missed")}
            print(f"| {name} | {r['tp']} | {r['fp']} | {r['fn']} | {r['precision']:.1%} | {r['recall']:.1%} | {r['f1']:.3f} | {r['unlabeled']} |")
        print()
    if a.dump:
        json.dump(dump, open(a.dump, "w"))
