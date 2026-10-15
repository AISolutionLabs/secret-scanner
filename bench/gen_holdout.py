#!/usr/bin/env python3
"""Held-out labeled corpus, written independently of the tuning set: different
seed, variable names, file types and secret shapes. Never used for tuning."""
import base64, json, os, random, string, sys, hashlib

out = sys.argv[1]
os.makedirs(out, exist_ok=True)
R = random.Random(777)
A = string.ascii_letters + string.digits
HEX = "0123456789abcdef"
def g(cs, n): return "".join(R.choice(cs) for _ in range(n))

secrets = [
    # (kind, generator, typical names)
    ("github-oauth", lambda: "gho_" + g(A, 36), ["GH_OAUTH", "github.oauth.token"]),
    ("gitlab-runner", lambda: "glrt-" + g(A + "_-", 20), ["RUNNER_TOKEN", "gitlab.runner.token"]),
    ("slack-user", lambda: f"xoxp-{g(string.digits,11)}-{g(string.digits,11)}-{g(string.digits,13)}-{g(HEX,32)}", ["SLACK_USER_TOKEN"]),
    ("stripe-restricted", lambda: "rk_live_" + g(A, 99)[:30], ["STRIPE_RESTRICTED"]),
    ("aws-secret", lambda: g(A + "/+", 40), ["aws_secret_access_key", "AWS_SECRET_ACCESS_KEY"]),
    ("azure-sas", lambda: f"https://acct{g(string.ascii_lowercase,5)}.blob.core.windows.net/c?sv=2023-01-03&ss=b&srt=co&sp=rl&se=2027-01-01&sig={g(A,43)}%3D", ["SAS_URL"]),
    ("gcp-oauth-secret", lambda: "GOCSPX-" + g(A + "_-", 28), ["GOOGLE_CLIENT_SECRET"]),
    ("terraform", lambda: g(string.ascii_lowercase + string.digits, 14) + ".atlasv1." + g(A + "_-", 67), ["TFE_TOKEN"]),
    ("datadog", lambda: g(HEX, 32), ["DD_API_KEY", "datadog.api.key"]),
    ("sentry", lambda: "sntrys_" + g(A, 70), ["SENTRY_AUTH_TOKEN"]),
    ("linear", lambda: "lin_api_" + g(A, 40), ["LINEAR_API_KEY"]),
    ("groq", lambda: "gsk_" + g(A, 52), ["GROQ_API_KEY"]),
    ("hf-org", lambda: "api_org_" + g(string.ascii_letters, 34), ["HF_ORG_TOKEN"]),
    ("litellm", lambda: "sk-" + g(A, 22), ["LITELLM_MASTER_KEY"]),
    ("jfrog-ref", lambda: "cmVmd" + g(A, 59), ["ARTIFACTORY_TOKEN"]),
    ("ado-pat-legacy", lambda: g("abcdefghijklmnopqrstuvwxyz234567", 52), ["AZURE_DEVOPS_PAT", "SYSTEM_ACCESSTOKEN"]),
    ("generic-hex", lambda: g(HEX, R.choice([32, 40, 48, 64])), ["signingSecret", "hmac_key", "apiSecret", "privateToken", "authKey"]),
    ("generic-b64", lambda: base64.b64encode(os.urandom(R.choice([18, 24, 32, 48]))).decode(), ["encryptionKey", "master_key", "client.secret", "app.secret", "secretValue"]),
    ("generic-alnum", lambda: g(A, R.randint(16, 48)), ["apiToken", "service_api_key", "accessKey", "bearerToken", "oauthSecret"]),
    ("generic-password", lambda: g(A + "!$%&*#@?", R.randint(10, 24)) + str(R.randint(0, 9)), ["dbPassword", "spring.datasource.password", "admin.pass", "smtp_password", "redisPassword"]),
]

templates = {
    "properties": ("application.properties", lambda n, v: f"{n}={v}"),
    "ini": ("settings.ini", lambda n, v: f"{n.split('.')[-1]} = {v}"),
    "java": ("Config.java", lambda n, v: f'    private static final String {n.replace(".", "_").upper()} = "{v}";'),
    "cs": ("Settings.cs", lambda n, v: f'        public const string {n.replace(".", "")} = "{v}";'),
    "kt": ("Config.kt", lambda n, v: f'    val {n.replace(".", "_")} = "{v}"'),
    "xml": ("web.config", lambda n, v: f'    <add key="{n}" value="{v}" />'),
    "helm": ("values.yaml", lambda n, v: f"  {n.split('.')[-1]}: {v}"),
    "gha": ("deploy.yml", lambda n, v: f"      {n.upper().replace('.', '_')}: {v}"),
    "php": ("config.php", lambda n, v: f"    '{n}' => '{v}',"),
    "rb": ("secrets.rb", lambda n, v: f'  config.{n.replace(".", "_")} = "{v}"'),
    "jsonc": ("appsettings.json", lambda n, v: f'    "{n}": "{v}",'),
    "ts": ("env.ts", lambda n, v: f"export const {n.replace('.', '_')} = `{v}`;"),
}
context = [
    "// TODO: clean up", "    timeout: 30", "    retries: 3", 'name = "billing-service"', "port=8080",
    "    <add key=\"Environment\" value=\"prod\" />", "log.level=INFO",
    lambda: f'build_id = "{hashlib.sha1(os.urandom(8)).hexdigest()}"',
    lambda: f"    digest: sha256:{g(HEX, 64)}",
    lambda: f'    "correlationId": "{g(HEX,8)}-{g(HEX,4)}-{g(HEX,4)}-{g(HEX,4)}-{g(HEX,12)}",',
    "    password: ${DB_PASSWORD}", "secretRef: app-secrets", 'tokenEndpoint = "https://auth.internal/token"',
    "    apiVersion: apps/v1", "keyAlias=release-key", "    passwordPolicy: strong",
]
truth, n = [], 0
for kind, gen, names in secrets:
    for _ in range(8):
        fmt = R.choice(list(templates))
        fname, tpl = templates[fmt]
        pre = [c() if callable(c) else c for c in R.sample(context, R.randint(2, 4))]
        post = [c() if callable(c) else c for c in R.sample(context, R.randint(1, 3))]
        lines = pre + [tpl(R.choice(names), gen())] + post
        n += 1
        f = f"{n:04d}-{kind}-{fname}"
        open(os.path.join(out, f), "w").write("\n".join(lines) + "\n")
        truth.append({"file": f, "line": len(pre) + 1, "kind": kind,
                      "category": "generic" if kind.startswith("generic") else "prefixed"})
json.dump(truth, open(os.path.join(out, "..", "truth_holdout.json"), "w"), indent=1)
print(len(truth), "held-out secrets")
