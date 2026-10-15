package remediate

import (
	"sort"
	"strings"
)

// Snippet returns a code pattern for loading the secret in lang from store.
// Patterns follow the same rules: one shared client, fetch at startup or on
// first use, cache in memory with a TTL shorter than the rotation period,
// refetch once on an auth failure, never log the value.
func Snippet(lang, store, env string) (string, bool) {
	if lang == "typescript" {
		lang = "javascript"
	}
	store = storeOrDefault(store)
	byStore, ok := snippets[lang]
	if !ok {
		return "", false
	}
	tpl, ok := byStore[store]
	if !ok {
		tpl, ok = byStore["*"] // platform snippet independent of store
		if !ok {
			tpl = byStore["env"]
		}
	}
	return render(tpl, env), true
}

// Languages lists languages with snippets.
func Languages() []string {
	var ls []string
	for k := range snippets {
		ls = append(ls, k)
	}
	sort.Strings(ls)
	return ls
}

func render(tpl, env string) string {
	kebab := strings.ToLower(strings.ReplaceAll(env, "_", "-"))
	lower := strings.ToLower(env)
	pascal := ""
	for _, p := range strings.Split(lower, "_") {
		if p != "" {
			pascal += strings.ToUpper(p[:1]) + p[1:]
		}
	}
	camel := pascal
	if camel != "" {
		camel = strings.ToLower(camel[:1]) + camel[1:]
	}
	return strings.NewReplacer("{{ENV}}", env, "{{NAME}}", kebab, "{{LOWER}}", lower,
		"{{CAMEL}}", camel, "{{PASCAL}}", pascal).Replace(strings.TrimLeft(tpl, "\n"))
}

var snippets = map[string]map[string]string{
	"python": {
		"env": `
import os

def require_env(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        raise RuntimeError(f"{name} is not set")  # fail fast at startup, never print the value
    return value

{{ENV}} = require_env("{{ENV}}")  # read once at import/startup, not per request
`,
		"aws": `
# pip install aws-secretsmanager-caching boto3
import botocore.session
from aws_secretsmanager_caching import SecretCache, SecretCacheConfig

# One cache per process: served from memory, refreshed in the background
# every 5 minutes, so rotations are picked up without per-request API calls.
_secrets = SecretCache(
    config=SecretCacheConfig(secret_refresh_interval=300),
    client=botocore.session.get_session().create_client("secretsmanager"),
)

def {{LOWER}}() -> str:
    return _secrets.get_secret_string("prod/my-app/{{NAME}}")
`,
		"azure": `
# pip install azure-identity azure-keyvault-secrets
import os, threading, time
from azure.identity import DefaultAzureCredential   # managed / workload identity, no secret
from azure.keyvault.secrets import SecretClient

_client = SecretClient(os.environ["KEY_VAULT_URL"], DefaultAzureCredential())
_lock, _cache, _TTL = threading.Lock(), {}, 300.0   # TTL shorter than the rotation period

def get_secret(name: str, refresh: bool = False) -> str:
    now = time.monotonic()
    with _lock:
        hit = _cache.get(name)
        if hit and not refresh and now - hit[1] < _TTL:
            return hit[0]
    value = _client.get_secret(name).value
    with _lock:
        _cache[name] = (value, now)
    return value

# usage: get_secret("{{NAME}}"); on a 401 from the downstream API call
# get_secret("{{NAME}}", refresh=True) once, then retry.
`,
		"vault": `
# Preferred: let Vault Agent / the Vault CSI provider write the secret to a file
# (rendered on rotation) and read the file; no Vault code in the app.
# With the SDK (pip install hvac), authenticate with the pod's identity:
import os, hvac

client = hvac.Client(url=os.environ["VAULT_ADDR"])
with open("/var/run/secrets/kubernetes.io/serviceaccount/token") as f:
    client.auth.kubernetes.login(role="my-app", jwt=f.read())   # no static VAULT_TOKEN

_resp = client.secrets.kv.v2.read_secret_version(path="my-app/config", mount_point="secret")
{{ENV}} = _resp["data"]["data"]["{{LOWER}}"]   # read once; re-read on lease expiry or 401
`,
		"gcp": `
# pip install google-cloud-secret-manager
import functools, os
from google.cloud import secretmanager   # Application Default Credentials, no key file

_client = secretmanager.SecretManagerServiceClient()

@functools.lru_cache(maxsize=None)   # once per process; call .cache_clear() after rotation
def get_secret(secret_id: str, version: str = "latest") -> str:
    name = f"projects/{os.environ['GOOGLE_CLOUD_PROJECT']}/secrets/{secret_id}/versions/{version}"
    return _client.access_secret_version(request={"name": name}).payload.data.decode()

# usage: get_secret("{{NAME}}")
`,
	},
	"go": {
		"env": `
// Read once at startup into your config struct; fail fast if missing.
func mustEnv(name string) string {
	v := os.Getenv(name)
	if v == "" {
		log.Fatalf("%s is not set", name) // never log the value itself
	}
	return v
}

// At startup (main / config loading):
//   cfg.{{PASCAL}} = mustEnv("{{ENV}}")
`,
		"aws": `
// go get github.com/aws/aws-sdk-go-v2/config github.com/aws/aws-sdk-go-v2/service/secretsmanager
awsCfg, err := config.LoadDefaultConfig(ctx) // role from Pod Identity / IRSA / instance profile
if err != nil {
	return err
}
sm := secretsmanager.NewFromConfig(awsCfg)
{{CAMEL}} := NewCachedSecret(5*time.Minute, func(ctx context.Context) (string, error) {
	out, err := sm.GetSecretValue(ctx, &secretsmanager.GetSecretValueInput{SecretId: aws.String("prod/my-app/{{NAME}}")})
	if err != nil {
		return "", err
	}
	return aws.ToString(out.SecretString), nil
})
token, err := {{CAMEL}}.Get(ctx) // memory hit on the hot path

` + goCache,
		"azure": `
// go get github.com/Azure/azure-sdk-for-go/sdk/azidentity github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azsecrets
cred, err := azidentity.NewDefaultAzureCredential(nil) // managed / workload identity
if err != nil {
	return err
}
kv, err := azsecrets.NewClient(os.Getenv("KEY_VAULT_URL"), cred, nil)
if err != nil {
	return err
}
{{CAMEL}} := NewCachedSecret(5*time.Minute, func(ctx context.Context) (string, error) {
	resp, err := kv.GetSecret(ctx, "{{NAME}}", "", nil) // "" = latest version
	if err != nil {
		return "", err
	}
	return *resp.Value, nil
})

` + goCache,
		"vault": `
// go get github.com/hashicorp/vault/api github.com/hashicorp/vault/api/auth/kubernetes
client, err := vault.NewClient(vault.DefaultConfig()) // VAULT_ADDR from env
if err != nil {
	return err
}
k8s, err := auth.NewKubernetesAuth("my-app") // pod service-account JWT, no static token
if err != nil {
	return err
}
if _, err := client.Auth().Login(ctx, k8s); err != nil {
	return err
}
{{CAMEL}} := NewCachedSecret(5*time.Minute, func(ctx context.Context) (string, error) {
	s, err := client.KVv2("secret").Get(ctx, "my-app/config")
	if err != nil {
		return "", err
	}
	v, _ := s.Data["{{LOWER}}"].(string)
	return v, nil
})
// Renew the auth token with client.NewLifetimeWatcher, or use Vault Agent.

` + goCache,
		"gcp": `
// go get cloud.google.com/go/secretmanager
sm, err := secretmanager.NewClient(ctx) // Application Default Credentials
if err != nil {
	return err
}
defer sm.Close()
{{CAMEL}} := NewCachedSecret(5*time.Minute, func(ctx context.Context) (string, error) {
	name := "projects/" + os.Getenv("GOOGLE_CLOUD_PROJECT") + "/secrets/{{NAME}}/versions/latest"
	resp, err := sm.AccessSecretVersion(ctx, &secretmanagerpb.AccessSecretVersionRequest{Name: name})
	if err != nil {
		return "", err
	}
	return string(resp.Payload.Data), nil
})

` + goCache,
	},
	"javascript": {
		"env": `
function requireEnv(name) {
  const value = process.env[name];
  if (!value) throw new Error(` + "`${name} is not set`" + `); // fail fast, never log the value
  return value;
}

export const {{CAMEL}} = requireEnv("{{ENV}}"); // read once at startup
`,
		"aws": `
// npm i @aws-sdk/client-secrets-manager
import { SecretsManagerClient, GetSecretValueCommand } from "@aws-sdk/client-secrets-manager";

const sm = new SecretsManagerClient({}); // role from Pod Identity / IRSA / instance profile
` + jsCache + `
export const {{CAMEL}} = cachedSecret(5 * 60_000, async () =>
  (await sm.send(new GetSecretValueCommand({ SecretId: "prod/my-app/{{NAME}}" }))).SecretString);
// usage: const token = await {{CAMEL}}.get();  on 401: await {{CAMEL}}.get(true)
`,
		"azure": `
// npm i @azure/identity @azure/keyvault-secrets
import { DefaultAzureCredential } from "@azure/identity";
import { SecretClient } from "@azure/keyvault-secrets";

const kv = new SecretClient(process.env.KEY_VAULT_URL, new DefaultAzureCredential());
` + jsCache + `
export const {{CAMEL}} = cachedSecret(5 * 60_000, async () => (await kv.getSecret("{{NAME}}")).value);
// usage: const token = await {{CAMEL}}.get();  on 401: await {{CAMEL}}.get(true)
`,
		"vault": `
// Vault Agent / CSI writes the secret to a file and re-renders it on rotation.
// Read it once and reload on change; no Vault SDK or token in the app.
import { readFileSync, watch } from "node:fs";

const path = "/vault/secrets/{{NAME}}";
let {{CAMEL}} = readFileSync(path, "utf8").trim();
watch(path, () => { {{CAMEL}} = readFileSync(path, "utf8").trim(); });
export const get{{PASCAL}} = () => {{CAMEL}};
`,
		"gcp": `
// npm i @google-cloud/secret-manager
import { SecretManagerServiceClient } from "@google-cloud/secret-manager";

const sm = new SecretManagerServiceClient(); // Application Default Credentials
` + jsCache + `
export const {{CAMEL}} = cachedSecret(5 * 60_000, async () => {
  const [v] = await sm.accessSecretVersion({
    name: ` + "`projects/${process.env.GOOGLE_CLOUD_PROJECT}/secrets/{{NAME}}/versions/latest`" + `,
  });
  return v.payload.data.toString("utf8");
});
`,
	},
	"java": {
		"env": `
// Read once into configuration; fail fast at startup.
String {{CAMEL}} = Objects.requireNonNull(System.getenv("{{ENV}}"), "{{ENV}} is not set");
// Spring: in application.properties use  my.{{CAMEL}}=${{{ENV}}}  and inject with @Value.
`,
		"aws": `
// software.amazon.secretsmanager:aws-secretsmanager-caching-java (in-memory cache, 1h refresh default)
private static final SecretCache SECRETS = new SecretCache(); // role from Pod Identity / IRSA

String {{CAMEL}}() {
    return SECRETS.getSecretString("prod/my-app/{{NAME}}");
}
`,
		"azure": `
// Spring Boot: com.azure.spring:spring-cloud-azure-starter-keyvault-secrets
// application.properties
//   spring.cloud.azure.keyvault.secret.property-sources[0].endpoint=${KEY_VAULT_URL}
//   spring.cloud.azure.keyvault.secret.property-sources[0].refresh-interval=5m
@Value("${{{NAME}}}")
private String {{CAMEL}}; // resolved from Key Vault via managed/workload identity

// Plain SDK (com.azure:azure-security-keyvault-secrets + azure-identity):
SecretClient kv = new SecretClientBuilder().vaultUrl(System.getenv("KEY_VAULT_URL"))
        .credential(new DefaultAzureCredentialBuilder().build()).buildClient();
String value = kv.getSecret("{{NAME}}").getValue(); // cache it; don't call per request
`,
		"vault": `
// Spring Cloud Vault (org.springframework.cloud:spring-cloud-starter-vault-config)
// application.properties
//   spring.config.import=vault://
//   spring.cloud.vault.authentication=KUBERNETES
//   spring.cloud.vault.kubernetes.role=my-app
@Value("${{{LOWER}}}")   // key "{{LOWER}}" in secret/my-app
private String {{CAMEL}}; // read at startup, lease renewal handled
`,
		"gcp": `
// com.google.cloud:google-cloud-secretmanager
try (SecretManagerServiceClient sm = SecretManagerServiceClient.create()) { // ADC
    String {{CAMEL}} = sm.accessSecretVersion(
            SecretVersionName.of(System.getenv("GOOGLE_CLOUD_PROJECT"), "{{NAME}}", "latest"))
        .getPayload().getData().toStringUtf8(); // read once at startup and keep in config
}
`,
	},
	"csharp": {
		"env": `
// Bind through IConfiguration (env vars, user-secrets locally, Key Vault in prod).
var {{CAMEL}} = builder.Configuration["{{ENV}}"]
    ?? throw new InvalidOperationException("{{ENV}} is not set");
// Local dev: dotnet user-secrets set {{ENV}} <value>   (stored outside the repo)
`,
		"azure": `
// dotnet add package Azure.Extensions.AspNetCore.Configuration.Secrets Azure.Identity
builder.Configuration.AddAzureKeyVault(
    new Uri(builder.Configuration["KeyVaultUrl"]!),
    new DefaultAzureCredential(), // managed / workload identity, no secret
    new AzureKeyVaultConfigurationOptions { ReloadInterval = TimeSpan.FromMinutes(5) });

var {{CAMEL}} = builder.Configuration["{{NAME}}"]; // Key Vault "a--b" maps to config key "a:b"
// Use IOptionsMonitor<T> so reloaded values flow to running code.
`,
		"aws": `
// dotnet add package AWSSDK.SecretsManager.Caching
private static readonly SecretsManagerCache Secrets = new(); // in-memory, refreshed hourly by default

public static Task<string> {{PASCAL}}() => Secrets.GetSecretString("prod/my-app/{{NAME}}");
`,
		"vault": `
// Vault Agent / Secrets Store CSI writes one file per key into a mounted directory.
// dotnet add package Microsoft.Extensions.Configuration.KeyPerFile
builder.Configuration.AddKeyPerFile("/mnt/secrets", optional: false, reloadOnChange: true);
var {{CAMEL}} = builder.Configuration["{{NAME}}"]; // file name = key; reloads on rotation
`,
		"gcp": `
// dotnet add package Google.Cloud.SecretManager.V1
var sm = SecretManagerServiceClient.Create(); // Application Default Credentials
var {{CAMEL}} = sm.AccessSecretVersion(
    new SecretVersionName(Environment.GetEnvironmentVariable("GOOGLE_CLOUD_PROJECT"), "{{NAME}}", "latest"))
    .Payload.Data.ToStringUtf8(); // read once at startup
`,
	},
	"kubernetes": {"*": `
# Sync from the store with External Secrets Operator (or use the Secrets Store CSI driver).
apiVersion: external-secrets.io/v1
kind: ExternalSecret
metadata:
  name: my-app
spec:
  refreshInterval: 15m                 # rotation propagates without redeploying
  secretStoreRef: { kind: ClusterSecretStore, name: platform-store }  # Vault / AWS SM / Key Vault
  target: { name: my-app-secrets }
  data:
    - secretKey: {{LOWER}}
      remoteRef: { key: my-app/{{NAME}} }
---
# In the Deployment, prefer a volume (updates in place) over env (needs a restart):
#   volumes: [{ name: secrets, secret: { secretName: my-app-secrets } }]
#   volumeMounts: [{ name: secrets, mountPath: /var/run/secrets/app, readOnly: true }]
# or, if the app only reads env:
#   env: [{ name: {{ENV}}, valueFrom: { secretKeyRef: { name: my-app-secrets, key: {{LOWER}} } } }]
`},
	"terraform": {"*": `
# Never put secrets in .tf/.tfvars. Declare a sensitive input or read from the store:
variable "{{LOWER}}" {
  type      = string
  sensitive = true          # supply via TF_VAR_{{LOWER}} from the pipeline's secret store
}

# Terraform 1.10+: ephemeral resources keep the value out of plan and state
ephemeral "aws_secretsmanager_secret_version" "{{LOWER}}" {
  secret_id = "prod/my-app/{{NAME}}"
}
# Terraform 1.11+: pass it to write-only arguments (e.g. password_wo) so state never stores it.
# Better still: dynamic provider credentials / OIDC so the runner holds no static keys.
`},
	"dockerfile": {"*": `
# syntax=docker/dockerfile:1
# Build-time secret: mounted for one RUN step, never stored in a layer or image history.
RUN --mount=type=secret,id={{LOWER}},env={{ENV}} \
    ./build.sh            # e.g. npm ci with an .npmrc that reads ${{{ENV}}}

# docker build --secret id={{LOWER}},env={{ENV}} .
# Runtime secrets come from the orchestrator (Kubernetes Secret, ECS secrets, App Service Key Vault
# references), not ENV/ARG, which are baked into the image metadata.
`},
	"github-actions": {"*": `
permissions:
  id-token: write   # OIDC: exchange the job's identity for short-lived cloud credentials
  contents: read
steps:
  - uses: aws-actions/configure-aws-credentials@v4
    with: { role-to-assume: arn:aws:iam::123456789012:role/deploy, aws-region: eu-west-1 }
  # or azure/login@v2 with client-id/tenant-id/subscription-id (federated credential, no secret)
  - run: ./deploy.sh
    env:
      {{ENV}}: ${{ secrets.{{ENV}} }}   # only for third-party tokens with no OIDC option
`},
	"azure-pipelines": {"*": `
# Service connection with workload identity federation (no client secret), and a
# variable group linked to Key Vault for third-party tokens.
variables:
  - group: my-app-kv          # Library > Variable groups > "Link secrets from an Azure key vault"
steps:
  - task: AzureCLI@2
    inputs:
      azureSubscription: my-wif-connection
      scriptType: bash
      scriptLocation: inlineScript
      inlineScript: ./deploy.sh
    env:
      {{ENV}}: $({{NAME}})          # secret variables must be mapped explicitly into env
      SYSTEM_ACCESSTOKEN: $(System.AccessToken)   # instead of a PAT for Azure DevOps APIs
`},
	"shell": {"*": `
: "${{{ENV}}:?{{ENV}} must be set}"     # fail fast; injected by CI or 'op run' / 'aws-vault exec'
# Fetch at runtime when needed (identity-based, no static credentials):
#   {{ENV}}="$(vault kv get -field={{LOWER}} secret/my-app)"
#   {{ENV}}="$(aws secretsmanager get-secret-value --secret-id prod/my-app/{{NAME}} --query SecretString --output text)"
#   {{ENV}}="$(az keyvault secret show --vault-name my-kv -n {{NAME}} --query value -o tsv)"
# Pass secrets on stdin, not argv (visible in ps):  printf %s "${{ENV}}" | docker login --password-stdin ...
# Never 'set -x' around secret handling.
`},
	"powershell": {"*": `
if (-not $env:{{ENV}}) { throw "{{ENV}} is not set" }
# Fetch with identity: (Get-AzKeyVaultSecret -VaultName my-kv -Name {{NAME}} -AsPlainText)
`},
	"ruby": {"env": `
{{ENV}} = ENV.fetch("{{ENV}}") # raises KeyError at boot if missing
# Rails: bin/rails credentials:edit (encrypted, key outside the repo) or the cloud store.
`},
	"php": {"env": `
${{LOWER}} = getenv('{{ENV}}') ?: throw new RuntimeException('{{ENV}} is not set');
// Laravel/Symfony: reference env('{{ENV}}') / %env({{ENV}})% and inject via the platform.
`},
	"spring": {"*": `
# application.properties: reference, don't embed
my.{{LOWER}}=${{{ENV}}}
# and resolve {{ENV}} from Spring Cloud Vault / Spring Cloud Azure Key Vault property sources
# (see the java snippets for the store you use).
`},
	"dotnet-config": {"*": `
<!-- web.config / app.config: remove the value. On App Service / Functions use a Key Vault reference: -->
<!--   App setting {{ENV}} = @Microsoft.KeyVault(SecretUri=https://my-kv.vault.azure.net/secrets/{{NAME}}/) -->
<!-- In code read it from configuration (see the csharp snippets: AddAzureKeyVault + DefaultAzureCredential). -->
<add key="{{ENV}}" value="" />
`},
	"dotenv": {"*": `
# .env must not be committed. Add it to .gitignore and commit a template instead:
#   .env.example
{{ENV}}=
# Populate locally from the store, e.g.:
#   op run --env-file=.env.example -- ./app        (1Password)
#   vault kv get -format=json secret/my-app | jq -r '.data.data | to_entries[] | "\(.key)=\(.value)"' > .env
`},
	"json-config": {"*": `
// appsettings.json / config.json: delete the value and bind the key from the environment or a store.
// .NET local dev: dotnet user-secrets set "{{ENV}}" "<value>"; production: AddAzureKeyVault (see csharp).
// Node: load config defaults from JSON but read secrets via process.env / the store (see javascript).
`},
}

const goCache = `// CachedSecret: one fetch per TTL, shared by all goroutines. Call Invalidate
// after a 401 from the downstream API, then Get once more.
type CachedSecret struct {
	mu      sync.Mutex
	ttl     time.Duration
	fetch   func(context.Context) (string, error)
	value   string
	fetched time.Time
}

func NewCachedSecret(ttl time.Duration, fetch func(context.Context) (string, error)) *CachedSecret {
	return &CachedSecret{ttl: ttl, fetch: fetch}
}

func (c *CachedSecret) Get(ctx context.Context) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.value != "" && time.Since(c.fetched) < c.ttl {
		return c.value, nil
	}
	v, err := c.fetch(ctx)
	if err != nil {
		if c.value != "" {
			return c.value, nil // store unavailable: keep serving the last good value
		}
		return "", err
	}
	c.value, c.fetched = v, time.Now()
	return v, nil
}

func (c *CachedSecret) Invalidate() { c.mu.Lock(); c.fetched = time.Time{}; c.mu.Unlock() }
`

const jsCache = `
// One fetch per TTL; concurrent callers share the in-flight request.
function cachedSecret(ttlMs, fetch) {
  let value, fetchedAt = 0, inflight;
  return {
    async get(refresh = false) {
      if (!refresh && value && Date.now() - fetchedAt < ttlMs) return value;
      inflight ??= fetch()
        .then((v) => { value = v; fetchedAt = Date.now(); return v; })
        .catch((e) => { if (value) return value; throw e; }) // keep last good value
        .finally(() => { inflight = undefined; });
      return inflight;
    },
  };
}
`
