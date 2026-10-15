#!/usr/bin/env python3
"""Score scanners on Plazmaz/leaky-repo, an independently labeled benchmark
(https://github.com/Plazmaz/leaky-repo), using its own method: per-file line
counts from .leaky-meta/secrets.csv; found > expected counts as false positives.

Two views are reported:
  official   expected = risk + informative lines (leaky-repo's benchmark.py)
  risk-only  expected = risk lines (credentials, keys, hashes); a stricter
             view of what a secret scanner should flag

  python3 bench/leaky_repo.py /path/to/leaky-repo [--tools secretscan,gitleaks,detect-secrets]
"""
import argparse, collections, csv, json, os, shutil, subprocess, sys, tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
SS = os.environ.get("SECRETSCAN", os.path.join(HERE, "..", "bin", "secretscan"))
GL = os.environ.get("GITLEAKS", shutil.which("gitleaks") or "")


def truth(repo):
    rows = []
    with open(os.path.join(repo, ".leaky-meta", "secrets.csv")) as f:
        lines = [l for l in f if l.strip() and not l.startswith("#")]
    for name, risk, info in csv.reader(lines):
        rows.append((name.strip(), int(risk), int(info)))
    return rows


def run(cmd, cwd):
    return subprocess.run(cmd, cwd=cwd, capture_output=True, text=True)


def count_lines(findings):
    """Distinct (file, line) pairs, matching leaky-repo's line counting."""
    by = collections.defaultdict(set)
    for f, line in findings:
        by[os.path.normpath(f)].add(line)
    return {k: len(v) for k, v in by.items()}


def secretscan(repo):
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as t:
        out = t.name
    try:
        run([SS, "dir", ".", "-f", "json", "-r", out, "--exit-code", "0", "-q", "--exclude-path", r"^\.leaky-meta/|^README\.md$|^LICENSE$"], repo)
        fs = json.load(open(out))
    finally:
        os.remove(out)
    return count_lines((f["File"], f["StartLine"]) for f in fs)


def gitleaks(repo):
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as t:
        out = t.name
    try:
        run([GL, "dir", ".", "-f", "json", "-r", out, "--exit-code", "0", "--no-banner", "--log-level", "error", "--redact"], repo)
        fs = json.load(open(out))
    finally:
        os.remove(out)
    return count_lines((f["File"], f["StartLine"]) for f in fs if not f["File"].startswith(".leaky-meta"))


def detect_secrets(repo):
    p = run(["detect-secrets", "scan", "--all-files", "."], repo)
    res = json.loads(p.stdout)["results"]
    return count_lines((f, it["line_number"]) for f, items in res.items() for it in items if not f.startswith(".leaky-meta"))


TOOLS = {"secretscan": secretscan, "gitleaks": gitleaks, "detect-secrets": detect_secrets}


def score(found, rows, risk_only):
    tot_found = tot_exp = fps = covered = 0
    for name, risk, info in rows:
        exp = risk if risk_only else risk + info
        if exp == 0:
            continue
        n = found.get(os.path.normpath(name), 0)
        fp = max(n - exp, 0)
        tot_found += n - fp
        tot_exp += exp
        fps += fp
        covered += n > 0
    files = sum(1 for _, r, i in rows if (r if risk_only else r + i) > 0)
    # Findings in files with no labeled lines at all are false positives too.
    labeled = {os.path.normpath(n) for n, _, _ in rows}
    extra = sum(v for k, v in found.items() if k not in labeled)
    return {"files": f"{covered}/{files}", "finds": f"{tot_found}/{tot_exp}", "coverage": round(100 * tot_found / tot_exp, 1),
            "false_positives": fps + extra}


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("repo")
    ap.add_argument("--tools", default="secretscan,gitleaks,detect-secrets")
    a = ap.parse_args()
    rows = truth(a.repo)
    commit = run(["git", "rev-parse", "--short", "HEAD"], a.repo).stdout.strip()
    print(f"leaky-repo @ {commit}: {len(rows)} labeled files, "
          f"{sum(r for _, r, _ in rows)} risk lines, {sum(i for _, _, i in rows)} informative lines\n")
    print("| Tool | Official: finds (coverage) | Official FPs | Risk-only: finds (coverage) | Risk-only FPs | Files with findings (risk) |")
    print("|---|---|---|---|---|---|")
    detail = {}
    for name in a.tools.split(","):
        if name == "gitleaks" and not GL or name == "detect-secrets" and not shutil.which("detect-secrets"):
            continue
        found = TOOLS[name](a.repo)
        o, r = score(found, rows, False), score(found, rows, True)
        detail[name] = found
        print(f"| {name} | {o['finds']} ({o['coverage']}%) | {o['false_positives']} | {r['finds']} ({r['coverage']}%) | {r['false_positives']} | {r['files']} |")
    print("\nPer-file risk lines found (tool counts vs expected):")
    for n, risk, info in rows:
        print(f"  {n:42s} risk={risk:<2d} " + "  ".join(f"{t}={detail[t].get(os.path.normpath(n), 0)}" for t in detail))
