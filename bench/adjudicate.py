#!/usr/bin/env python3
"""Apply the manual labels in bench/corpus_labels.tsv to every secretscan
finding on the package corpora, so "noise per 1k files" is split into what is
actually a false positive and what is example credential material.

  python3 bench/adjudicate.py [BENCH_DIR]      # default: bench/work

Exits non-zero if any finding has no label: a new finding must be inspected
and labeled before results are published.
"""
import collections, csv, json, os, re, subprocess, sys, tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
SS = os.environ.get("SECRETSCAN", os.path.join(HERE, "..", "bin", "secretscan"))
SETS = ["corpus/npm", "corpus/pypi", "holdneg/npm", "holdneg/pypi"]


def labels():
    rows = []
    with open(os.path.join(HERE, "corpus_labels.tsv")) as f:
        for row in csv.reader((l for l in f if l.strip() and not l.startswith("#")), delimiter="\t"):
            label, rule, path, value, note = row
            rows.append((label, re.compile(rule), re.compile(path), re.compile(value), note))
    return rows


def scan(d):
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as t:
        out = t.name
    try:
        # Values are needed to apply the labels; the report is deleted right after.
        subprocess.run([SS, "dir", ".", "-f", "json", "-r", out, "--exit-code", "0", "-q", "--redact=0"], cwd=d, check=True, stderr=subprocess.DEVNULL)
        return json.load(open(out))
    finally:
        os.remove(out)


def files(d):
    return sum(len(fs) for _, _, fs in os.walk(d))


def main():
    work = sys.argv[1] if len(sys.argv) > 1 else os.path.join(HERE, "work")
    rows = labels()
    total_files, counts, unlabeled = 0, collections.Counter(), []
    per = collections.defaultdict(collections.Counter)
    for s in SETS:
        d = os.path.join(work, s)
        if not os.path.isdir(d):
            continue
        total_files += files(d)
        for f in scan(d):
            for label, rule, path, value, note in rows:
                if rule.fullmatch(f["RuleID"]) and path.search(f["File"]) and value.search(f["Secret"]):
                    counts[label] += 1
                    per[label][(f["RuleID"], note, f.get("Blocking", True))] += 1
                    break
            else:
                unlabeled.append(f"{s}/{f['File']}:{f['StartLine']} {f['RuleID']}")
    k = total_files / 1000
    print(f"{total_files} files, {sum(counts.values())} findings\n")
    print("| Label | Findings | Per 1k files |\n|---|---|---|")
    for label in ("live-credential", "example-credential", "not-a-secret"):
        print(f"| {label} | {counts[label]} | {counts[label] / k:.2f} |")
    for label in ("not-a-secret", "example-credential"):
        print(f"\n{label}:")
        for (rule, note, blocking), n in sorted(per[label].items(), key=lambda x: -x[1]):
            print(f"  {n:3d}  {rule:24s} {note}")
    if unlabeled:
        print(f"\n{len(unlabeled)} UNLABELED findings (inspect and add to corpus_labels.tsv):")
        print("\n".join("  " + u for u in unlabeled))
        sys.exit(1)


if __name__ == "__main__":
    main()
