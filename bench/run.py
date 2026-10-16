#!/usr/bin/env python3
"""Run secretscan, gitleaks and detect-secrets on labeled positives and on
real-world package corpora; report recall, precision and noise.

  bench/fetch-corpus.sh           # once: downloads corpora, generates labeled sets
  python3 bench/run.py [tools]    # tuning set (positives + npm/pypi/Go stdlib)
  HOLDOUT=1 python3 bench/run.py  # held-out set

gitleaks is used from $BENCH_DIR/tools/gitleaks if present (or PATH)."""
import collections, json, os, subprocess, sys, time

B = os.environ.get("BENCH_DIR", os.path.join(os.path.dirname(os.path.abspath(__file__)), "work"))
S = B
TOOLS = os.path.join(B, "tools")
HOLD = os.environ.get("HOLDOUT") == "1"
POS = os.path.join(B, "holdout" if HOLD else "positives")
GOROOT_SRC = os.path.join(subprocess.run(["go", "env", "GOROOT"], capture_output=True, text=True).stdout.strip(), "src")
NEG = ({"npm": os.path.join(S, "holdneg/npm"), "pypi": os.path.join(S, "holdneg/pypi")} if HOLD else
       {"npm": os.path.join(S, "corpus/npm"), "pypi": os.path.join(S, "corpus/pypi"), "gostd": GOROOT_SRC})
SECRETSCAN = os.environ.get("SECRETSCAN", os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "bin", "secretscan"))
only = set(sys.argv[1].split(",")) if len(sys.argv) > 1 else None

def norm(root, f):
    f = os.path.normpath(f)
    return os.path.relpath(f, root) if os.path.isabs(f) else f

def run_secretscan(root):
    out = os.path.join(B, "out.ss.json")
    t = time.time()
    subprocess.run([SECRETSCAN, "dir", ".", "-f", "json", "-r", out, "--exit-code", "0", "-q", "--no-color"],
                   cwd=root, stderr=subprocess.DEVNULL)
    dt = time.time() - t
    return [(norm(root, f["File"]), f["StartLine"], f["RuleID"], f["Secret"]) for f in json.load(open(out))], dt

def run_gitleaks(root):
    out = os.path.join(B, "out.gl.json")
    t = time.time()
    gl = os.path.join(TOOLS, "gitleaks")
    gl = gl if os.path.exists(gl) else "gitleaks"
    subprocess.run([gl, "dir", ".", "-f", "json", "-r", out, "--exit-code", "0",
                    "--no-banner", "--log-level", "error", "--redact=80"], cwd=root)
    dt = time.time() - t
    return [(norm(root, f["File"]), f["StartLine"], f["RuleID"], f["Secret"]) for f in json.load(open(out))], dt

def run_detect_secrets(root):
    t = time.time()
    p = subprocess.run(["detect-secrets", "scan", "--no-verify", "--all-files", "."], cwd=root, capture_output=True, text=True)
    dt = time.time() - t
    res = []
    for f, items in json.loads(p.stdout)["results"].items():
        for it in items:
            res.append((norm(root, f), it["line_number"], it["type"], ""))
    return res, dt

RUNNERS = {"secretscan": run_secretscan, "gitleaks": run_gitleaks, "detect-secrets": run_detect_secrets}

def score_positives(findings, truth):
    want = {(t["file"], t["line"]): t for t in truth}
    hit, fp = set(), []
    for f, line, rule, sec in findings:
        if (f, line) in want:
            hit.add((f, line))
        else:
            fp.append((f, line, rule))
    by_cat = collections.defaultdict(lambda: [0, 0])
    missed = []
    for k, t in want.items():
        by_cat[t["category"]][1] += 1
        if k in hit:
            by_cat[t["category"]][0] += 1
        else:
            missed.append(t)
    return len(hit), len(want), fp, dict(by_cat), missed

truth = json.load(open(os.path.join(B, "truth_holdout.json" if HOLD else "truth.json")))
report = {}
for name, fn in RUNNERS.items():
    if only and name not in only:
        continue
    r = {}
    fs, dt = fn(POS)
    tp, total, fp, cats, missed = score_positives(fs, truth)
    r["pos"] = {"tp": tp, "total": total, "fp": len(fp), "secs": round(dt, 1),
                "recall": round(tp / total, 3), "precision": round(tp / max(tp + len(fp), 1), 3),
                "by_cat": cats, "fp_rules": collections.Counter(x[2] for x in fp).most_common(),
                "missed": collections.Counter(m["kind"] for m in missed).most_common()}
    for corpus, root in NEG.items():
        fs, dt = fn(root)
        r[corpus] = {"findings": len(fs), "secs": round(dt, 1), "files": len({f[0] for f in fs}),
                     "rules": collections.Counter(x[2] for x in fs).most_common(12)}
        json.dump(fs, open(os.path.join(B, f"neg{'.hold' if HOLD else ''}.{name}.{corpus}.json"), "w"))
    report[name] = r
    print(f"== {name}: recall {r['pos']['recall']}  precision {r['pos']['precision']}  "
          + "  ".join(f"{c}={r[c]['findings']}" for c in NEG), flush=True)
prev = {}
p = os.path.join(B, "report_holdout.json" if HOLD else "report.json")
if os.path.exists(p):
    prev = json.load(open(p))
prev.update(report)
json.dump(prev, open(p, "w"), indent=1)
