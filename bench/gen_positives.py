#!/usr/bin/env python3
"""Generate a labeled corpus: each file holds exactly one real-looking secret
at a known line, surrounded by benign lines including hard negatives
(hashes, digests, UUIDs, templated values) that must NOT be reported.
Writes truth.json: [{file, line, kind, category}]."""
import base64, json, os, random, string, sys

out = sys.argv[1]
os.makedirs(out, exist_ok=True)
R = random.Random(20261015)
A = string.ascii_letters + string.digits
def g(cs, n): return "".join(R.choice(cs) for _ in range(n))
HEX = "0123456789abcdef"
def uuid(): return f"{g(HEX,8)}-{g(HEX,4)}-4{g(HEX,3)}-{g(HEX,4)}-{g(HEX,12)}"
def pw(n=None):
    n = n or R.randint(12, 20)
    s = g(A + "!@#%^&*-_+", n)
    return s if any(c.isdigit() for c in s) else s + "7"

# ---- secrets by kind: (kind, category, value-generator) ----------------------
prefixed = {
    "github-pat": lambda: "ghp_" + g(A, 36),
    "github-fine-grained": lambda: "github_pat_" + g(A, 22) + "_" + g(A, 59),
    "gitlab-pat": lambda: "glpat-" + g(A + "_-", 20),
    "slack-bot": lambda: f"xoxb-{g(string.digits,12)}-{g(string.digits,13)}-{g(A,24)}",
    "slack-webhook": lambda: f"https://hooks.slack.com/services/T{g(string.ascii_uppercase+string.digits,8)}/B{g(string.ascii_uppercase+string.digits,10)}/{g(A,24)}",
    "stripe-live": lambda: "sk_live_" + g(A, 24),
    "aws-key-id": lambda: "AKIA" + g("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567", 16),
    "openai": lambda: "sk-proj-" + g(A + "_-", 48) + "T3BlbkFJ" + g(A + "_-", 48),
    "anthropic": lambda: "sk-ant-api03-" + g(A + "_-", 93) + "AA",
    "npm": lambda: "npm_" + g(A, 36),
    "sendgrid": lambda: f"SG.{g(A+'_-',22)}.{g(A+'_-',43)}",
    "gcp-api-key": lambda: "AIza" + g(A + "_-", 35),
    "jfrog-api-key": lambda: "AKCp" + g(A, 69),
    "digitalocean": lambda: "dop_v1_" + g(HEX, 64),
    "databricks": lambda: "dapi" + g(HEX, 32),
    "huggingface": lambda: "hf_" + g(string.ascii_letters, 34),
    "shopify": lambda: "shpat_" + g(HEX, 32),
    "vault": lambda: "hvs." + g(A + "_-", 95),
    "azure-ad-secret": lambda: g(A, 3) + str(R.randint(0, 9)) + "Q~" + g(A + "_~.-", 34),
    "twilio-key": lambda: "SK" + g(HEX, 32),
    "pypi": lambda: "pypi-AgEIcHlwaS5vcmc" + g(A + "_-", 70),
    "docker-pat": lambda: "dckr_pat_" + g(A + "_-", 27),
    "grafana-sa": lambda: "glsa_" + g(A, 32) + "_" + g(HEX, 8),
    "ado-pat-new": lambda: g(A, 52) + "JQQJ99" + g(A, 18) + "AZDO" + g(A, 4),
}
# generic secrets need context: (name, value)
generic_names = ["api_key", "API_KEY", "apiKey", "client_secret", "clientSecret", "SECRET_KEY",
                 "auth_token", "access_token", "AUTH_TOKEN", "app_secret", "private_token",
                 "DB_PASSWORD", "db_password", "password", "admin_password", "credentials", "token",
                 "signing_key", "encryption_key", "webhook_secret", "jwt_secret", "session_secret"]
def generic_value():
    k = R.choice(["alnum", "hex32", "hex40", "hex64", "b64", "pw", "alnum-long"])
    return {"alnum": lambda: g(A, R.randint(20, 32)), "hex32": lambda: g(HEX, 32), "hex40": lambda: g(HEX, 40),
            "hex64": lambda: g(HEX, 64), "b64": lambda: base64.b64encode(os.urandom(R.choice([24, 32]))).decode(),
            "pw": pw, "alnum-long": lambda: g(A, 40)}[k]()

# ---- file templates ------------------------------------------------------------
benign = [
    'import os', 'import logging', 'LOG_LEVEL = "info"', 'TIMEOUT_SECONDS = 30', 'REGION = "eu-west-1"',
    '# configuration for the service', 'MAX_RETRIES = 5',
]
hard_negatives = [
    lambda: f'COMMIT_SHA = "{g(HEX, 40)}"',
    lambda: f'IMAGE = "registry.example.io/app@sha256:{g(HEX, 64)}"',
    lambda: f'REQUEST_ID = "{uuid()}"',
    lambda: f'CHECKSUM = "{g(HEX, 64)}"',
    lambda: 'DB_PASSWORD = os.environ["DB_PASSWORD"]',
    lambda: 'api_key = "${API_KEY}"',
    lambda: 'secret: "{{ .Values.secret }}"',
    lambda: 'aws_access_key_id = AKIAIOSFODNN7EXAMPLE',
    lambda: 'token_url = "https://login.example.com/oauth2/token"',
    lambda: 'key_name = "my-app-signing-key"',
    lambda: 'public_key_id = "key-2024-primary"',
    lambda: f'"integrity": "sha512-{base64.b64encode(os.urandom(64)).decode()}"',
    lambda: 'password_min_length = 12',
    lambda: 'secretName: app-credentials',
    lambda: f'git_revision = "{g(HEX, 12)}"',
    lambda: 'auth_header = "Authorization"',
    lambda: 'TOKEN_TTL = "3600s"',
    lambda: 'api_version = "2023-11-01"',
    lambda: 'credentials_file = "/etc/app/credentials.json"',
    lambda: 'secret_key_ref = valueFrom.secretKeyRef.name',
]

def render(fmt, name, value):
    """Return (lines, index_of_secret_line)."""
    pre = [R.choice(benign) for _ in range(R.randint(1, 3))] + [R.choice(hard_negatives)() for _ in range(R.randint(1, 3))]
    post = [R.choice(hard_negatives)() for _ in range(R.randint(0, 2))] + [R.choice(benign)]
    line = {
        "env": f"{name.upper()}={value}",
        "yaml": f"  {name}: {value}",
        "yaml-q": f'  {name}: "{value}"',
        "json": f'  "{name}": "{value}",',
        "py": f'{name} = "{value}"',
        "js": f"const {name} = '{value}';",
        "go": f'\t{name} := "{value}"',
        "sh": f'export {name.upper()}="{value}"',
        "tf": f'  {name} = "{value}"',
        "docker": f"ENV {name.upper()}={value}",
    }[fmt]
    return pre + [line] + post, len(pre)

EXT = {"env": ".env", "yaml": ".yaml", "yaml-q": ".yml", "json": ".json", "py": ".py", "js": ".js",
       "go": ".go", "sh": ".sh", "tf": ".tfvars", "docker": "Dockerfile"}
truth, n = [], 0
def emit(lines, idx, kind, cat, fmt):
    global n
    n += 1
    fname = f"{n:04d}-{kind}" + (EXT[fmt] if EXT[fmt].startswith(".") else "-" + EXT[fmt])
    with open(os.path.join(out, fname), "w") as f:
        f.write("\n".join(lines) + "\n")
    truth.append({"file": fname, "line": idx + 1, "kind": kind, "category": cat})

fmts = list(EXT)
for kind, gen in prefixed.items():
    for _ in range(6):
        name = R.choice(["token", "key", "secret", "credential", "api_key", "value", "conf", "x"])  # weak names too
        fmt = R.choice(fmts)
        lines, i = render(fmt, name, gen())
        emit(lines, i, kind, "prefixed", fmt)
for _ in range(110):
    fmt = R.choice(fmts)
    lines, i = render(fmt, R.choice(generic_names), generic_value())
    emit(lines, i, "generic", "generic", fmt)
for _ in range(25):
    u, p = g(string.ascii_lowercase, 6), pw()
    p = p.replace("@", "x").replace("/", "x").replace("#", "x").replace("%", "x")
    scheme = R.choice(["postgres", "mysql", "mongodb+srv", "redis", "amqp", "https"])
    lines, i = render("env", "DATABASE_URL", f"{scheme}://{u}:{p}@db-{g(string.ascii_lowercase,4)}.internal.corp:5432/app")
    emit(lines, i, "url-credentials", "connection", "env")
for _ in range(10):
    p = pw()
    lines, i = render("env", "CONN", f"Server=tcp:sql-{g(HEX,6)}.database.windows.net,1433;User ID=svc;Password={p};Encrypt=True;")
    emit(lines, i, "conn-string", "connection", "env")
for _ in range(10):
    body = "\n".join(base64.b64encode(os.urandom(48)).decode() for _ in range(12))
    kind = R.choice(["RSA PRIVATE KEY", "PRIVATE KEY", "EC PRIVATE KEY", "OPENSSH PRIVATE KEY"])
    lines = ["# deploy key"] + [f"-----BEGIN {kind}-----"] + body.split("\n") + [f"-----END {kind}-----"]
    emit(lines, 1, "private-key", "key", "env")
for _ in range(15):
    tokv = R.choice([lambda: "ghp_" + g(A, 36), pw, lambda: g(A, 32)])()
    enc = base64.b64encode(tokv.encode()).decode()
    lines = ["apiVersion: v1", "kind: Secret", "metadata:", "  name: app", "type: Opaque", "data:", f"  password: {enc}"]
    emit(lines, 6, "k8s-secret-b64", "encoded", "yaml")
for _ in range(15):
    hdr = base64.urlsafe_b64encode(b'{"alg":"HS256","typ":"JWT"}').decode().rstrip("=")
    pay = base64.urlsafe_b64encode(json.dumps({"sub": uuid(), "iat": 1700000000, "role": "admin"}).encode()).decode().rstrip("=")
    sig = base64.urlsafe_b64encode(os.urandom(32)).decode().rstrip("=")
    fmt = R.choice(["env", "js", "py"])
    lines, i = render(fmt, "auth", f"{hdr}.{pay}.{sig}")
    emit(lines, i, "jwt", "token", fmt)

json.dump(truth, open(os.path.join(out, "..", "truth.json"), "w"), indent=1)
print(f"{len(truth)} labeled secrets in {out}")
