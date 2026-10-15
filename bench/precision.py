#!/usr/bin/env python3
"""Precision benchmark: secretscan vs gitleaks (and detect-secrets on the
labeled sets), plus gitleaks re-scored by `secretscan triage`.

Layout under $BENCH_DIR (default bench/work), created by fetch-corpus.sh and
gen_precision_sets.py:
  positives/ truth.json            tuning positives (generic + provider)
  holdout/   truth_holdout.json    held-out positives (never tuned on)
  safety/    safety/truth.json     secrets placed where suppressions are risky
  issues/    issues/manifest.json  false positives from public issue trackers
  corpus/ holdneg/                 popular npm/PyPI packages (no live secrets expected)
  tools/gitleaks                   optional (else gitleaks on PATH)

Metrics
  recall          labeled secrets found (any report) / labeled secrets
  recall@block    labeled secrets that would block (policy) / labeled secrets
  precision       true findings / all findings in labeled sets
  issue FP rate   issue-derived negative files flagged / issue cases
  noise / 1k      findings per 1,000 files in package corpora
  latency         p50 / p95 per staged commit (60 synthetic commits)

  python3 bench/precision.py [--skip-corpora] [--skip-latency] [--tools secretscan,gitleaks,...]
"""
import argparse, collections, json, os, random, shutil, statistics, string, subprocess, sys, tempfile, time

HERE = os.path.dirname(os.path.abspath(__file__))
B = os.environ.get("BENCH_DIR", os.path.join(HERE, "work"))
SS = os.environ.get("SECRETSCAN", os.path.join(HERE, "..", "bin", "secretscan"))
GL = os.path.join(B, "tools", "gitleaks") if os.path.exists(os.path.join(B, "tools", "gitleaks")) else shutil.which("gitleaks")
CACHE = os.path.join(B, "cache")
os.makedirs(CACHE, exist_ok=True)

LABELED = {  # name -> (dir, truth file)
    "tuning": ("positives", "truth.json"),
    "holdout": ("holdout", "truth_holdout.json"),
    "safety": ("safety", "safety/truth.json"),
}
CORPORA = ["corpus/npm", "corpus/pypi", "holdneg/npm", "holdneg/pypi"]


def norm(root, f):
    f = os.path.normpath(f)
    return os.path.relpath(f, root) if os.path.isabs(f) else f


def files_in(root):
    n = 0
    for _, _, fs in os.walk(root):
        n += len(fs)
    return n


# Each runner returns [(file, (start, end), rule, reported, blocking)]
def span(f):
    return (f["StartLine"], max(f["StartLine"], f.get("EndLine") or f["StartLine"]))

def secretscan(root, policy="balanced"):
    out = os.path.join(CACHE, "ss.json")
    subprocess.run([SS, "dir", ".", "-f", "json", "-r", out, "--exit-code", "0", "-q", "--no-color", "--redact=0",
                    "--policy", policy], cwd=root, stderr=subprocess.DEVNULL, check=True)
    return [(norm(root, f["File"]), span(f), f["RuleID"], True, f["Blocking"]) for f in json.load(open(out))]


def gitleaks_raw(root, key):
    out = os.path.join(CACHE, f"gl.{key.replace('/', '_')}.json")
    if not (os.environ.get("REUSE") and os.path.exists(out)):
        subprocess.run([GL, "dir", ".", "-f", "json", "-r", out, "--exit-code", "0", "--no-banner", "--log-level", "error"],
                       cwd=root, check=True)
    return out


def gitleaks(root, key):
    return [(norm(root, f["File"]), span(f), f["RuleID"], True, True) for f in json.load(open(gitleaks_raw(root, key)))]


def gitleaks_triaged(root, key):
    raw = gitleaks_raw(root, key)
    out = os.path.join(CACHE, "tri.json")
    subprocess.run([SS, "triage", raw, "--root", root, "-f", "json", "-r", out, "--policy", "balanced", "--redact=0", "-q"],
                   cwd=root, stderr=subprocess.DEVNULL)
    res = []
    for f in json.load(open(out)):
        reported = not f.get("Triage", "").startswith("filtered")
        res.append((norm(root, f["File"]), span(f), f["RuleID"], reported, f["Blocking"]))
    return res


def detect_secrets(root, key):
    p = subprocess.run(["detect-secrets", "scan", "--all-files", "."], cwd=root, capture_output=True, text=True, check=True)
    return [(norm(root, f), (it["line_number"], it["line_number"]), it["type"], True, True)
            for f, items in json.loads(p.stdout)["results"].items() for it in items]


TOOLS = {
    "secretscan": lambda root, key: secretscan(root),
    "gitleaks": gitleaks,
    "gitleaks+triage": gitleaks_triaged,
    "detect-secrets": detect_secrets,
}


def score_labeled(fs, truth):
    """A finding is true if its line range covers a labeled secret line."""
    want = {(t["file"], t["line"]) for t in truth}
    by_file = collections.defaultdict(set)
    for f, l in want:
        by_file[f].add(l)
    def hits(f, sp):
        return {(f, l) for l in by_file.get(f, ()) if sp[0] <= l <= sp[1]}
    rep, blk = set(), set()
    fp_r = fp_b = 0
    for f, sp, _, r, b in fs:
        if not r:
            continue
        h = hits(f, sp)
        rep |= h
        if b:
            blk |= h
        if not h:
            fp_r += 1
            fp_b += 1 if b else 0
    return {"n": len(want), "tp": len(rep), "tp_block": len(blk), "fp": fp_r, "fp_block": fp_b,
            "missed": sorted({t["kind"] for t in truth if (t["file"], t["line"]) not in rep})}


def run_quality(tools, skip_corpora):
    res = collections.defaultdict(dict)
    for name in tools:
        fn = TOOLS[name]
        if name.startswith("gitleaks") and not GL:
            print(f"skip {name}: gitleaks not found", file=sys.stderr)
            continue
        if name == "detect-secrets" and not shutil.which("detect-secrets"):
            continue
        for set_name, (d, tf) in LABELED.items():
            root = os.path.join(B, d)
            if not os.path.isdir(root):
                continue
            truth = json.load(open(os.path.join(B, tf)))
            res[name][set_name] = score_labeled(fn(root, set_name), truth)
        root = os.path.join(B, "issues")
        man = json.load(open(os.path.join(root, "manifest.json")))
        fs = fn(root, "issues")
        flagged = {f for f, _, _, r, _ in fs if r}
        blocked = {f for f, _, _, r, b in fs if r and b}
        res[name]["issues"] = {"n": len(man), "flagged": len(flagged), "blocked": len(blocked),
                               "flagged_cases": sorted(c["source"].rsplit("/", 1)[-1] + ":" + c["path"] for c in man if c["path"] in flagged)}
        if skip_corpora or name == "detect-secrets":
            continue
        for c in CORPORA:
            root = os.path.join(B, c)
            if not os.path.isdir(root):
                continue
            t = time.time()
            fs = fn(root, c)
            nfiles = files_in(root)
            res[name][c] = {"files": nfiles, "reported": sum(1 for x in fs if x[3]), "blocking": sum(1 for x in fs if x[3] and x[4]),
                            "secs": round(time.time() - t, 1)}
        print(f"done {name}", file=sys.stderr, flush=True)
    return res


def run_latency(n=60):
    """p50/p95 wall time of a staged-changes scan per commit."""
    src = [os.path.join(dp, f) for dp, _, fs in os.walk(os.path.dirname(os.__file__)) for f in fs if f.endswith(".py")][:400]
    R = random.Random(7)
    repo = tempfile.mkdtemp(prefix="latency-", dir=CACHE)
    env = dict(os.environ, GIT_AUTHOR_NAME="b", GIT_AUTHOR_EMAIL="b@b", GIT_COMMITTER_NAME="b", GIT_COMMITTER_EMAIL="b@b",
               GIT_CONFIG_GLOBAL="/dev/null")
    git = lambda *a: subprocess.run(["git", "-C", repo, *a], env=env, check=True, capture_output=True)
    git("init", "-q")
    cmds = {"secretscan": [SS, "git", "--staged", "--exit-code", "0", "-q", repo]}
    if GL:
        cmds["gitleaks"] = [GL, "git", "--pre-commit", "--staged", "--exit-code", "0", "--no-banner", "--log-level", "error", repo]
    times = collections.defaultdict(list)
    for i in range(n):
        for j in range(R.randint(2, 8)):  # typical commit: a few files, tens to hundreds of lines
            body = open(R.choice(src), errors="ignore").read()[: R.randint(2_000, 20_000)]
            p = os.path.join(repo, f"pkg{j}", f"mod_{i}_{j}.py")
            os.makedirs(os.path.dirname(p), exist_ok=True)
            open(p, "w").write(body)
        git("add", "-A")
        for name, cmd in cmds.items():
            t = time.perf_counter()
            subprocess.run(cmd, cwd=repo, capture_output=True)
            times[name].append((time.perf_counter() - t) * 1000)
        git("commit", "-q", "--no-verify", "-m", f"c{i}")
    shutil.rmtree(repo, ignore_errors=True)
    q = lambda xs, p: sorted(xs)[min(len(xs) - 1, int(round(p * (len(xs) - 1))))]
    return {k: {"p50_ms": round(statistics.median(v), 1), "p95_ms": round(q(v, 0.95), 1)} for k, v in times.items()}


def table(res, lat):
    lines = ["| Tool | Recall (reported) | Recall (blocking) | Safety-set recall | Precision | Issue FPs flagged | Noise / 1k files (reported / blocking) |",
             "|---|---|---|---|---|---|---|"]
    for name, r in res.items():
        tp = sum(r[s]["tp"] for s in LABELED if s in r)
        tpb = sum(r[s]["tp_block"] for s in LABELED if s in r)
        n = sum(r[s]["n"] for s in LABELED if s in r)
        fp = sum(r[s]["fp"] for s in LABELED if s in r)
        prec = tp / max(1, tp + fp)
        iss = r.get("issues", {})
        cf = [r[c] for c in CORPORA if c in r]
        noise = (f"{1000 * sum(c['reported'] for c in cf) / max(1, sum(c['files'] for c in cf)):.2f} / "
                 f"{1000 * sum(c['blocking'] for c in cf) / max(1, sum(c['files'] for c in cf)):.2f}") if cf else "–"
        sf = r.get("safety", {"tp": 0, "n": 0})
        lines.append(f"| {name} | {100*tp/n:.1f}% ({tp}/{n}) | {100*tpb/n:.1f}% | {sf['tp']}/{sf['n']} | {100*prec:.1f}% | "
                     f"{iss.get('flagged', 0)}/{iss.get('n', 0)} | {noise} |")
    if lat:
        lines += ["", "| Staged-commit latency | p50 | p95 |", "|---|---|---|"]
        lines += [f"| {k} | {v['p50_ms']} ms | {v['p95_ms']} ms |" for k, v in lat.items()]
    return "\n".join(lines)


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--tools", default="secretscan,gitleaks,gitleaks+triage,detect-secrets")
    ap.add_argument("--skip-corpora", action="store_true")
    ap.add_argument("--skip-latency", action="store_true")
    a = ap.parse_args()
    res = run_quality(a.tools.split(","), a.skip_corpora)
    lat = None if a.skip_latency else run_latency()
    json.dump({"quality": res, "latency": lat}, open(os.path.join(B, "precision.json"), "w"), indent=1)
    print(table(res, lat))
