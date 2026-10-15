#!/usr/bin/env python3
"""Generate two labeled sets for the precision benchmark.

issues/   NEGATIVES: false-positive patterns reported in public issue trackers,
          reproduced verbatim where the issue quotes them, plus randomized
          variants of the same class. Nothing here should be reported.
safety/   POSITIVES: real-shaped secrets placed where suppressions are risky
          (lockfiles, scanner configs, test dirs, next to digests/UUIDs/doc
          keys, tokens containing placeholder words). Everything must be found.

Writes issues/manifest.json (with source URLs) and safety/truth.json.
"""
import base64, json, os, random, string, sys

out = sys.argv[1]
R = random.Random(1015)
A = string.ascii_letters + string.digits
HEX = "0123456789abcdef"
def g(cs, n): return "".join(R.choice(cs) for _ in range(n))
def uuid(): return f"{g(HEX,8)}-{g(HEX,4)}-4{g(HEX,3)}-{g(HEX,4)}-{g(HEX,12)}"

GL = "https://github.com/gitleaks/gitleaks/issues/"
TH = "https://github.com/trufflesecurity/trufflehog/issues/"

# ---------------------------------------------------------------- negatives
issues = []
def neg(cls, src, path, text):
    issues.append({"class": cls, "source": src, "path": path, "text": text})

# Verbatim from the issues.
neg("C:digest", GL + "1468", "base-images.yaml", "image: my-super.registry.docker/aws-cli@sha256:eaaa7b11777babe28e6133a8b19ff71cea687e0d7f05158dee95a71f76ce3d00")
neg("A:hash", GL + "1775", "docker-moby.bb", 'SRCREV_moby = "43fc912ef59a83054ea7f6706df4d53a7dea4d80"')
neg("A:hash", GL + "1775", "vendor.patch", '-{"files":{"Cargo.toml":"32a7c9ac508dc33ad03b44010f7cd1bb3592fd069e9e0b9caffd909ff2795184",')
neg("B:identifier", GL + "1321", "Jenkinsfile", "    [envVar: 'TF_VAR_APPROLESECRETID', vaultKey: 'inf-vsqt-01-secret-id']]]]) {")
neg("B:identifier", GL + "1832", "vault.tf", '  "vault.hashicorp.com/agent-inject-secret-ingest.json" : "kv/ops/ingest"')
neg("A:placeholder", GL + "1832", "policy.tf", '  password_policy = "excellent"')
neg("C:digest", TH + "4364", "composer.lock", '"url": "https://api.github.com/repos/symfony/monolog-bridge/zipball/9d14621e59f22c2b6d030d92d37ffe5ae1e60452",')
neg("A:placeholder", TH + "3578", "appsettings.json", '"ConnectionString": "Server=myServerAddress;Database=myDataBase;User Id=myUsername;Password=myPassword;"')

# Randomized variants of each reported class.
for i in range(10):
    neg("C:digest", GL + "1468", f"images-{i}.yaml", f"  image: registry.io/team/app-{i}@sha256:{g(HEX, 64)}")
    neg("A:hash", GL + "1775", f"recipe-{i}.bb", f'SRCREV_{g(string.ascii_lowercase, 5)} = "{g(HEX, 40)}"')
    neg("A:hash", GL + "1775", f"vendor-{i}.patch", f'-{{"files":{{"src/lib.rs":"{g(HEX, 64)}","Cargo.toml":"{g(HEX, 64)}"}}')
    neg("C:digest", TH + "4364", f"composer-{i}.lock", f'"url": "https://api.github.com/repos/{g(string.ascii_lowercase, 6)}/{g(string.ascii_lowercase, 7)}/zipball/{g(HEX, 40)}",')
    neg("B:identifier", GL + "1321", f"Jenkinsfile.{i}", f"    [envVar: 'TF_VAR_{g(string.ascii_uppercase, 8)}', vaultKey: '{g(string.ascii_lowercase, 3)}-{g(string.ascii_lowercase, 4)}-0{i}-secret-id']")
for name in ["isOnDemandRevalidate", "SecurityProfiles", "accessTokenProvider", "apiKeyHeaderName", "secretRotationSchedule",
             "authorizationEndpoint", "credentialsProviderChain", "tokenRefreshInterval", "passwordResetTemplate", "keyVaultSecretReference"]:
    neg("B:identifier", "class B (identifiers matching credential rules)", f"{name}.ts", f'export const authProvider = "{name}";')
for name in ["public.api_keys", "auth.access_tokens", "secrets_manager.rotation_config", "app_credentials_v2"]:
    neg("B:identifier", "class B (schema names)", f"schema-{name}.sql", f"-- table: {name}\nCREATE TABLE {name} (id uuid primary key, secret_ref text);")
for arg in ["--build-arg GITHUB_TOKEN_FILE=/run/secrets/gh", "ARG NPM_TOKEN_PATH=/run/secrets/npm", "--secret id=api_key,src=.secrets/api_key"]:
    neg("B:identifier", "class B (docker args)", f"Dockerfile.{len(issues)}", arg)
for i in range(6):
    blob = base64.b64encode(os.urandom(3000)).decode()
    neg("C:encoded", "class C (token-like substrings in base64 payloads)", f"model-{i}.gltf",
        '{"buffers":[{"byteLength":3000,"uri":"data:application/octet-stream;base64,' + blob + '"}]}')
for i in range(5):
    neg("A:hash", "class A (checksums)", f"checksums-{i}.txt", f"sha256  {g(HEX, 64)}  dist/app-{i}.tar.gz")
    neg("A:id", "class A (identifiers)", f"ids-{i}.json", f'{{"request_token": "{uuid()}", "idempotency_key": "{uuid()}"}}')

d = os.path.join(out, "issues")
os.makedirs(d, exist_ok=True)
for c in issues:
    p = os.path.join(d, c["path"])
    with open(p, "w") as f:
        f.write(c["text"] + "\n")
json.dump([{k: v for k, v in c.items() if k != "text"} for c in issues], open(os.path.join(d, "manifest.json"), "w"), indent=1)

# ---------------------------------------------------------------- positives
safety = []
def pos(kind, path, lines, line):
    safety.append({"kind": kind, "path": path, "lines": lines, "line": line})

for i in range(4):
    pos("lockfile-registry-credential", f"lock-{i}/package-lock.json",
        ['{', f'  "resolved": "https://ci-{g(string.ascii_lowercase,4)}:{g(A, 22)}@artifactory.acme-{i}.io/api/npm/npm/x/-/x-1.0.{i}.tgz",',
         f'  "integrity": "sha512-{base64.b64encode(os.urandom(64)).decode()}"', '}'], 2)
    pos("lockfile-provider-token", f"lock-{i}/yarn.lock",
        [f'"x@^1.{i}.0":', f'  resolved "https://npm.pkg.github.com/download/x/1.{i}.0?token=ghp_{g(A, 36)}"'], 2)
    pos("scanner-config-token", f"cfg-{i}/.gitleaks.toml",
        ["[allowlist]", f"regexes = ['''ghp_{g(A, 36)}''']"], 2)
    word = ["Example", "Sample", "Dummy", "Placeholder"][i]
    pos("token-with-placeholder-word", f"words-{i}/client.py", [f'TOKEN = "ghp_{word}{g(A, 36 - len(word))}"'], 1)
    pos("provider-token-in-tests", f"tests-{i}/test_api.py",
        ["import pytest", f'STRIPE = "sk_live_{g(A, 24)}"'], 2)
    pos("next-to-digest", f"digest-{i}/values.yaml",
        [f"image: reg.io/app@sha256:{g(HEX, 64)}", f"slackToken: xoxb-{g(string.digits,12)}-{g(string.digits,12)}-{g(A,24)}"], 2)
    pos("next-to-uuid", f"uuid-{i}/config.py",
        [f'request_token = "{uuid()}"', f'api_secret = "{g(A, 32)}"'], 2)
    pos("next-to-doc-key", f"dockey-{i}/deploy.env",
        ["AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE", f"GITLAB_TOKEN=glpat-{g(A, 20)}"], 2)
    pos("after-inline-ignore", f"inline-{i}/app.js",
        [f'const demo = "ghp_{g(A, 36)}"; // secretscan:allow gitleaks:allow', f'const real = "ghp_{g(A, 36)}";'], 2)
    pos("provider-key-on-id-named-key", f"names-{i}/settings.py",
        [f'public_key_id = "sk-ant-api03-{g(A, 93)}AA"'], 1)

d = os.path.join(out, "safety")
os.makedirs(d, exist_ok=True)
truth = []
for c in safety:
    p = os.path.join(d, c["path"])
    os.makedirs(os.path.dirname(p), exist_ok=True)
    with open(p, "w") as f:
        f.write("\n".join(c["lines"]) + "\n")
    truth.append({"file": c["path"], "line": c["line"], "kind": c["kind"], "category": "safety"})
json.dump(truth, open(os.path.join(d, "truth.json"), "w"), indent=1)
print(f"{len(issues)} issue-derived negatives, {len(truth)} safety positives")
