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

# Versions are pinned so published results are reproducible; bump them
# deliberately and re-run bench/adjudicate.py (new findings must be labeled).
# Tuning corpus
fetch_npm "$W/dl/npm" "react@19.3.1 lodash@4.18.1 express@5.3.0 webpack@5.111.1 typescript@7.0.2 axios@1.20.0 moment@2.31.0 jquery@4.0.0 @aws-sdk/client-s3@3.1152.0 @azure/storage-blob@12.34.0 firebase-admin@14.5.0 googleapis@186.0.0 eslint@10.12.0 jest@30.5.2 next@16.4.1" "$W/corpus/npm"
fetch_py  "$W/dl/py" "django==6.1.2 requests==2.34.2 boto3==1.43.114 botocore==1.43.114 ansible-core==2.21.5 kubernetes==37.0.1 azure-storage-blob==12.31.0 paramiko==5.0.0 sqlalchemy==2.1.4 flask==3.1.3 google-cloud-storage==3.17.0 openai==3.31.0 anthropic==1.14.0" "$W/corpus/pypi"
# Held-out corpus (never used for tuning)
fetch_npm "$W/dl2/npm" "vue@3.5.44 @angular/core@21.2.25 rxjs@7.8.2 three@0.186.1 d3@7.9.0 socket.io@4.8.4 mongoose@9.11.2 sequelize@6.37.8 @prisma/client@7.10.0 discord.js@14.27.0 stripe@23.0.0 twilio@6.2.0 @slack/web-api@8.2.0" "$W/holdneg/npm"
fetch_py  "$W/dl2/py" "fastapi==0.143.1 pydantic==2.14.1 celery==5.6.3 msal==1.39.0 azure-identity==1.26.0 hvac==2.4.0 stripe==16.0.0 twilio==9.12.0 slack-sdk==3.45.0 google-api-core==2.42.0 httpx==0.28.1" "$W/holdneg/pypi"

python3 gen_positives.py "$W/positives"
python3 gen_holdout.py "$W/holdout"
python3 gen_precision_sets.py "$W"
echo "corpora ready in $W"
