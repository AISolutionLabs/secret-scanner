#!/bin/sh
# Downloads the benchmark corpora (popular npm and PyPI packages) and
# generates the labeled positive sets into bench/work/.
set -e
cd "$(dirname "$0")"
W=${BENCH_DIR:-$PWD/work}
mkdir -p "$W/dl/npm" "$W/dl/py" "$W/dl2/npm" "$W/dl2/py" "$W/corpus/npm" "$W/corpus/pypi" "$W/holdneg/npm" "$W/holdneg/pypi"

fetch_npm() { (cd "$1" && npm pack --silent $2 >/dev/null); for f in "$1"/*.tgz; do d="$3/$(basename "$f" .tgz)"; mkdir -p "$d"; tar -xzf "$f" -C "$d"; done; }
fetch_py()  { (cd "$1" && for p in $2; do pip download --no-deps -q -d . "$p" >/dev/null 2>&1 || true; done)
              for f in "$1"/*; do d="$3/$(basename "$f")"; mkdir -p "$d"; case $f in *.tar.gz) tar -xzf "$f" -C "$d";; *) python3 -m zipfile -e "$f" "$d";; esac; done; }

# Tuning corpus
fetch_npm "$W/dl/npm" "react lodash express webpack typescript axios moment jquery @aws-sdk/client-s3 @azure/storage-blob firebase-admin googleapis eslint jest next" "$W/corpus/npm"
fetch_py  "$W/dl/py" "django requests boto3 botocore ansible-core kubernetes azure-storage-blob paramiko sqlalchemy flask google-cloud-storage openai anthropic" "$W/corpus/pypi"
# Held-out corpus (never used for tuning)
fetch_npm "$W/dl2/npm" "vue @angular/core rxjs three d3 socket.io mongoose sequelize @prisma/client discord.js stripe twilio @slack/web-api" "$W/holdneg/npm"
fetch_py  "$W/dl2/py" "fastapi pydantic celery msal azure-identity hvac stripe twilio slack-sdk google-api-core httpx" "$W/holdneg/pypi"

python3 gen_positives.py "$W/positives"
python3 gen_holdout.py "$W/holdout"
python3 gen_precision_sets.py "$W"
echo "corpora ready in $W"
