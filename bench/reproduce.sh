#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Reproduce every published benchmark with pinned tools and datasets:
#
#   bench/reproduce.sh [OUT_DIR]          # default: bench/work/reproduce
#
# Runs the CredData challenge (all repositories and the dev/test halves; with
# gitleaks, trufflehog and detect-secrets for comparison), the
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
TRUFFLEHOG_VERSION="3.97.9"                                # trufflehog release, 2026-09-24
# SHA-256 of the release archives, from trufflehog_3.97.9_checksums.txt
# (linux_amd64 also checked by hand against the downloaded file).
TRUFFLEHOG_SHA256_linux_amd64="40377e6572495412fb9ba0bc21c9401f73b72f1d2afd11b9931bc4a5ed622866"
TRUFFLEHOG_SHA256_linux_arm64="372c568695d49e53517075b5f74d1ee9a19053f13661d689c7928ee1fc27d705"
TRUFFLEHOG_SHA256_darwin_amd64="4451ba8d17106da0d0a2f1952d3b1c2d20a6e5c97c21ccd1f8fc04ecf2ff77d9"
TRUFFLEHOG_SHA256_darwin_arm64="3d25c178fe1a2563687b22547adcaebcf08cc8a607315c6741fe396c597951f7"
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

# trufflehog: prebuilt release archive (building it needs a newer Go), checked
# against the pinned SHA-256. Only the binary is extracted. It always runs with
# --no-verification (bench/*.py), so no detected value is sent anywhere.
log "installing trufflehog $TRUFFLEHOG_VERSION"
if [ ! -x "$DATA/tools/trufflehog" ]; then
  os="$(uname -s | tr '[:upper:]' '[:lower:]')"
  case "$(uname -m)" in x86_64|amd64) arch=amd64 ;; aarch64|arm64) arch=arm64 ;; *) arch="$(uname -m)" ;; esac
  want_var="TRUFFLEHOG_SHA256_${os}_${arch}"
  want="${!want_var:-}"
  [ -n "$want" ] || { echo "no pinned trufflehog checksum for ${os}_${arch}" >&2; exit 1; }
  asset="trufflehog_${TRUFFLEHOG_VERSION}_${os}_${arch}.tar.gz"
  tmp="$(mktemp -d)"
  curl -fsSL -o "$tmp/$asset" "https://github.com/trufflesecurity/trufflehog/releases/download/v$TRUFFLEHOG_VERSION/$asset"
  got="$( (sha256sum "$tmp/$asset" 2>/dev/null || shasum -a 256 "$tmp/$asset") | cut -d' ' -f1)"
  [ "$got" = "$want" ] || { echo "trufflehog checksum mismatch: got $got, want $want" >&2; exit 1; }
  mkdir "$tmp/x" && tar -xzf "$tmp/$asset" -C "$tmp/x" trufflehog
  install -m 755 "$tmp/x/trufflehog" "$DATA/tools/trufflehog"
  rm -rf "$tmp"
fi
export TRUFFLEHOG="$DATA/tools/trufflehog"

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
# One trufflehog scan, likewise. --no-verification: never send values to providers.
noNet=(); if unshare -rn true 2>/dev/null; then noNet=(unshare -rn); fi
(cd "$DATA/CredData" && umask 077 && ${noNet[@]+"${noNet[@]}"} "$TRUFFLEHOG" filesystem data --json --no-verification --no-update --no-color \
  > "$OUT/creddata.trufflehog.jsonl" 2>/dev/null)
python3 "$HERE/creddata.py" "$DATA/CredData" --trufflehog-report "$OUT/creddata.trufflehog.jsonl" > "$OUT/creddata.all.md"
for split in dev test; do
  python3 "$HERE/creddata.py" "$DATA/CredData" --split "$split" --tools secretscan,gitleaks,gitleaks+triage,trufflehog,trufflehog+triage \
    --gitleaks-report "$OUT/creddata.gitleaks.json" --trufflehog-report "$OUT/creddata.trufflehog.jsonl" > "$OUT/creddata.$split.md"
done
rm -f "$OUT/creddata.gitleaks.json" "$OUT/creddata.trufflehog.jsonl" # contain the dataset's (obfuscated) values

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
  echo "detect-secrets $DETECT_SECRETS_VERSION, trufflehog $TRUFFLEHOG_VERSION, CredData ${CREDDATA_REF:0:7}, leaky-repo ${LEAKY_REF:0:7}."
  for f in creddata.all creddata.dev creddata.test leaky-repo regression adjudication filters; do
    echo; echo "## $f"; echo; cat "$OUT/$f.md"
  done
} > "$OUT/SUMMARY.md"
log "done: $OUT/SUMMARY.md"
