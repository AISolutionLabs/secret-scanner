#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Reproduce every published benchmark with pinned tools and datasets:
#
#   bench/reproduce.sh [OUT_DIR]          # default: bench/work/reproduce
#
# Runs the CredData challenge (all repositories and the dev/test halves), the
# leaky-repo comparison, the package-corpus regression suite with manual
# adjudication, and the per-alphabet filter test. Writes one Markdown summary
# plus raw outputs to OUT_DIR. Needs Go, Python 3.12 (CredData's downloader
# misdetects Python 3.13), git and network access to GitHub, PyPI and npm.
# Expect about 2 hours, most of it detect-secrets on CredData.
#
# The same script runs in GitHub Actions (.github/workflows/benchmark.yml), so
# anyone can reproduce the numbers in a fork without trusting this machine.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
OUT="${1:-$HERE/work/reproduce}"
DATA="${BENCH_DATA:-$HERE/work}"

# Pinned versions (update deliberately, together with bench/results).
GITLEAKS_REF="b58d3f102cf3a2c84cb7f923d05c25c9b1aed84b"   # gitleaks v8, 2026-07-22
DETECT_SECRETS_VERSION="1.5.0"
CREDDATA_REF="0b1940e171725ad8937311120b191602608a4801"   # Samsung/CredData, 2026-09-29
LEAKY_REF="2e951359cac53addbee56437da3ffb546e3dfe24"      # Plazmaz/leaky-repo, 2020-02-29

mkdir -p "$OUT" "$DATA/tools"
log() { printf '\n== %s\n' "$*" >&2; }

log "building secretscan"
(cd "$ROOT" && make build >/dev/null)
export SECRETSCAN="$ROOT/bin/secretscan"

log "installing gitleaks @ ${GITLEAKS_REF:0:7} and detect-secrets $DETECT_SECRETS_VERSION"
if [ ! -x "$DATA/tools/gitleaks" ]; then
  GOBIN="$DATA/tools" go install "github.com/zricethezav/gitleaks/v8@$GITLEAKS_REF"
fi
export GITLEAKS="$DATA/tools/gitleaks"
python3 -m pip install -q "detect-secrets==$DETECT_SECRETS_VERSION" 2>/dev/null ||
  python3 -m pip install -q --break-system-packages "detect-secrets==$DETECT_SECRETS_VERSION"

clone_at() { # url dir ref
  if [ ! -d "$2/.git" ]; then git clone -q "$1" "$2"; fi
  git -C "$2" fetch -q origin "$3" 2>/dev/null || true
  git -C "$2" checkout -q "$3"
}

log "CredData @ ${CREDDATA_REF:0:7}"
clone_at https://github.com/Samsung/CredData "$DATA/CredData" "$CREDDATA_REF"
if [ ! -d "$DATA/CredData/data" ]; then
  python3 -m pip install -q -r "$DATA/CredData/requirements.txt" 2>/dev/null ||
    python3 -m pip install -q --break-system-packages GitPython pybase62 tabulate colorama
  (cd "$DATA/CredData" && python3 download_data.py --data_dir data)
fi
# One gitleaks scan, reused for the triage rows and both halves.
(cd "$DATA/CredData" && "$GITLEAKS" dir data -f json -r "$OUT/creddata.gitleaks.json" --no-banner --log-level error --exit-code 0)
chmod 600 "$OUT/creddata.gitleaks.json"
python3 "$HERE/creddata.py" "$DATA/CredData" > "$OUT/creddata.all.md"
for split in dev test; do
  python3 "$HERE/creddata.py" "$DATA/CredData" --split "$split" --tools secretscan,gitleaks,gitleaks+triage \
    --gitleaks-report "$OUT/creddata.gitleaks.json" > "$OUT/creddata.$split.md"
done
rm -f "$OUT/creddata.gitleaks.json" # contains the dataset's (obfuscated) values

log "leaky-repo @ ${LEAKY_REF:0:7}"
clone_at https://github.com/Plazmaz/leaky-repo "$DATA/leaky-repo" "$LEAKY_REF"
python3 "$HERE/leaky_repo.py" "$DATA/leaky-repo" > "$OUT/leaky-repo.md"

log "package corpora (pinned versions), regression suite and adjudication"
[ -d "$DATA/corpus" ] || BENCH_DIR="$DATA" sh "$HERE/fetch-corpus.sh"
BENCH_DIR="$DATA" python3 "$HERE/precision.py" > "$OUT/regression.md"
python3 "$HERE/adjudicate.py" "$DATA" > "$OUT/adjudication.md"

log "noise-filter false negatives per alphabet"
(cd "$ROOT" && go test -count=1 -run 'PerAlphabet|SpareRandomSecrets' -v ./internal/detect) | grep -E '^\s*\||lost|^ok' > "$OUT/filters.md"

{
  echo "# secretscan benchmark reproduction"
  echo
  echo "Run $(date -u +%Y-%m-%dT%H:%MZ) on $(uname -sm), $(nproc 2>/dev/null || sysctl -n hw.ncpu) CPUs."
  echo "secretscan $(git -C "$ROOT" rev-parse --short HEAD), gitleaks ${GITLEAKS_REF:0:7},"
  echo "detect-secrets $DETECT_SECRETS_VERSION, CredData ${CREDDATA_REF:0:7}, leaky-repo ${LEAKY_REF:0:7}."
  for f in creddata.all creddata.dev creddata.test leaky-repo regression adjudication filters; do
    echo; echo "## $f"; echo; cat "$OUT/$f.md"
  done
} > "$OUT/SUMMARY.md"
log "done: $OUT/SUMMARY.md"
