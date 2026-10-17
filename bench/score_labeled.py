#!/usr/bin/env python3
"""Score scanners on any line-labeled corpus: the tool for a second,
independent benchmark (docs/benchmark-policy.md).

  python3 bench/score_labeled.py CORPUS_DIR LABELS.csv [--tools secretscan,gitleaks,trufflehog] [--json out.json]

LABELS.csv has a header and one row per labeled line range:

  path,line_start,line_end,label[,category]
  src/settings.py,12,12,T,password
  docs/example.md,40,40,F,placeholder

path is relative to CORPUS_DIR; label is T (a real credential) or F (not
one). Scoring follows bench/creddata.py: a reported line inside a T range is
a true positive, one inside only F ranges a false positive, a T range nobody
reports a miss; findings on unlabeled lines are counted separately and
count neither way. Tools run with verification off (trufflehog
--no-verification, without network access where unshare allows it): no
value is sent anywhere.

The output records secretscan's version and the detection-code
fingerprint, so a reader can check that the frozen detection code
(bench/results/latest.json: detection_fingerprint) was the one measured.
"""
import argparse, collections, csv, json, os, shutil, subprocess, sys, tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import render_docs  # noqa: E402  (fingerprint)

SS = os.environ.get("SECRETSCAN", os.path.join(HERE, "..", "bin", "secretscan"))
GL = os.environ.get("GITLEAKS", shutil.which("gitleaks") or "")
TH = os.environ.get("TRUFFLEHOG", shutil.which("trufflehog") or "")


def load_labels(path):
    rows = collections.defaultdict(list)
    with open(path, newline="") as f:
        for r in csv.DictReader(f):
            lab = r["label"].strip().upper()
            if lab not in ("T", "F"):
                raise SystemExit(f"{path}: label must be T or F, got {r['label']!r}")
            s = int(r["line_start"])
            e = int(r.get("line_end") or s)
            rows[os.path.normpath(r["path"])].append((s, max(s, e), lab, r.get("category", "")))
    return rows


def tmpjson():
    fd, p = tempfile.mkstemp(suffix=".json")
    os.close(fd)
    return p


def secretscan(corpus, extra=()):
    out = tmpjson()
    try:
        subprocess.run([SS, "dir", ".", "-f", "json", "-r", out, "--exit-code", "0", "-q", "--redact", *extra], cwd=corpus,
                       capture_output=True)
        return [(f["File"], f["StartLine"], f.get("EndLine") or f["StartLine"]) for f in json.load(open(out))]
    finally:
        os.remove(out)


def secretscan_balanced(corpus):
    out = tmpjson()
    try:
        subprocess.run([SS, "dir", ".", "-f", "json", "-r", out, "--exit-code", "0", "-q", "--redact", "--policy", "balanced"],
                       cwd=corpus, capture_output=True)
        return [(f["File"], f["StartLine"], f.get("EndLine") or f["StartLine"]) for f in json.load(open(out)) if f.get("Blocking")]
    finally:
        os.remove(out)


def gitleaks(corpus):
    out = tmpjson()
    try:
        subprocess.run([GL, "dir", ".", "-f", "json", "-r", out, "--exit-code", "0", "--no-banner", "--log-level", "error", "--redact"],
                       cwd=corpus, capture_output=True)
        return [(f["File"], f["StartLine"], f.get("EndLine") or f["StartLine"]) for f in json.load(open(out))]
    finally:
        os.remove(out)


def trufflehog(corpus):
    u = shutil.which("unshare")
    pre = [u, "-rn"] if u and subprocess.run([u, "-rn", "true"], capture_output=True).returncode == 0 else []
    p = subprocess.run(pre + [TH, "filesystem", ".", "--json", "--no-verification", "--no-update", "--no-color"],
                       cwd=corpus, capture_output=True, text=True)
    out = []
    for line in p.stdout.splitlines():
        if line.startswith("{"):
            r = json.loads(line)
            fs = (r.get("SourceMetadata") or {}).get("Data", {}).get("Filesystem")
            if fs and r.get("DetectorName"):
                n = fs.get("line") or 1
                out.append((fs["file"], n, n))
    return out


TOOLS = {"secretscan": (secretscan, SS), "secretscan-balanced-blocking": (secretscan_balanced, SS),
         "gitleaks": (gitleaks, GL), "trufflehog": (trufflehog, TH)}


def score(findings, labels):
    positives = {(p, s) for p, rows in labels.items() for s, e, lab, _ in rows if lab == "T"}
    found, fp, unl = set(), set(), set()
    for f, s, e in findings:
        f = os.path.normpath(f)
        rows = labels.get(f, [])
        hit = None
        for line in range(s, max(s, e) + 1):
            inside = [r for r in rows if r[0] <= line <= r[1]]
            if any(r[2] == "T" for r in inside):
                found.update((f, r[0]) for r in inside if r[2] == "T")
                hit = "T"
                break
            if inside:
                hit = "F"
        if hit == "F":
            fp.add((f, s))
        elif hit is None:
            unl.add((f, s))
    tp = len(found & positives)
    prec = tp / (tp + len(fp)) if tp + len(fp) else 0.0
    rec = tp / len(positives) if positives else 0.0
    f1 = 2 * prec * rec / (prec + rec) if prec + rec else 0.0
    return {"tp": tp, "fp": len(fp), "fn": len(positives) - tp, "unlabeled": len(unl), "precision": round(100 * prec, 1),
            "recall": round(100 * rec, 1), "f1": round(f1, 3), "missed": sorted(positives - found), "false_positives": sorted(fp)}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("corpus")
    ap.add_argument("labels")
    ap.add_argument("--tools", default="secretscan,secretscan-balanced-blocking,gitleaks,trufflehog")
    ap.add_argument("--json", help="write full results, including missed and false-positive lines, here")
    a = ap.parse_args()
    labels = load_labels(a.labels)
    ver = subprocess.run([SS, "version"], capture_output=True, text=True).stdout.strip()
    res = {"corpus": os.path.abspath(a.corpus), "labels": os.path.abspath(a.labels), "secretscan_version": ver,
           "detection_fingerprint": render_docs.fingerprint(), "tools": {}}
    print(f"{ver}, detection fingerprint {res['detection_fingerprint']}\n")
    print("| Tool | True | False | Missed | Precision | Recall | F1 | Unlabeled |\n|---|---|---|---|---|---|---|---|")
    for name in a.tools.split(","):
        fn, binary = TOOLS[name]
        if not binary or not os.path.exists(binary) and not shutil.which(binary):
            print(f"skipping {name}: not installed", file=sys.stderr)
            continue
        s = score(fn(a.corpus), labels)
        res["tools"][name] = s
        print(f"| {name} | {s['tp']} | {s['fp']} | {s['fn']} | {s['precision']}% | {s['recall']}% | {s['f1']} | {s['unlabeled']} |")
    if a.json:
        json.dump(res, open(a.json, "w"), indent=2)


if __name__ == "__main__":
    main()
