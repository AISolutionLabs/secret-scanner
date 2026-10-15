# Using secrets in code, efficiently and safely

secretscan tells you *that* a credential is in your code. This guide covers
what to do instead. The same advice is built into the tool:

```sh
secretscan dir . --remediation full                 # steps + code for each finding
secretscan explain <rule-id> --lang go --store azure  # patterns for one credential type
secretscan dir . --fix                              # replace literals with env lookups
```

## 0. A verified secret is an incident

If `--verify` marks a finding `VERIFIED LIVE`, **revoke it first**, then fix
the code. Deleting the line doesn't help: the value is in git history, CI
logs, forks and clones. Order of operations:

1. Revoke or rotate at the issuer (`fix:` line / `secretscan explain <rule>`).
2. Check the issuer's audit log for use since the commit date.
3. Fix the code (below) and redeploy with the new credential.
4. Only rewrite history (git filter-repo) if policy requires it. Rotation is what makes you safe.

## 1. Best: don't have a static secret

Most cloud and CI credentials can be replaced by workload identity, so there's
nothing to leak or rotate:

| Instead of | Use |
|---|---|
| AWS access keys | IAM roles: **EKS Pod Identity / IRSA**, instance profiles, OIDC-federated roles in CI, `aws sso login` for people. The SDK default credential chain needs **no code**. |
| Bedrock API keys | IAM role auth (SigV4), or route through the LLM gateway |
| Entra ID client secrets | **Managed identity** or **workload identity federation** (AKS, GitHub, Azure DevOps). Use `DefaultAzureCredential`. |
| Storage account keys / SAS | Entra RBAC (Storage Blob Data roles) + `DefaultAzureCredential`; disable shared-key auth |
| Azure DevOps PATs | `$(System.AccessToken)` in pipelines; service connections with **workload identity federation**; service principals for automation |
| GitHub PATs | `GITHUB_TOKEN` with least-privilege `permissions:` in Actions; GitHub Apps for services |
| Artifactory / registry tokens | **JFrog OIDC** from CI; npm/PyPI **trusted publishing** |
| Vault tokens | Vault **auth methods** (Kubernetes, JWT/OIDC, AWS/Azure) via Vault Agent or the CSI provider |
| Database passwords | RDS/Aurora IAM auth, Entra auth for Azure SQL/PostgreSQL, Vault **dynamic** DB credentials |
| SSH / signing keys | KMS/HSM-held keys; short-lived SSH certificates (Vault SSH CA) |
| AI provider keys in apps | One **LLM gateway** (e.g. LiteLLM) holds provider keys. Apps get per-team virtual keys with budgets and rate limits; Bedrock is reached via the gateway's IAM role. |

## 2. Otherwise: inject at runtime, read once, cache sensibly

When a third-party token is unavoidable (Slack, Stripe, SaaS APIs), keep it in
a secret store and deliver it to the process. Efficient patterns all follow
the same rules:

- **Read once at startup, or lazily on first use.** Never fetch from the store
  per request: it adds latency, costs money (AWS Secrets Manager bills per API
  call) and hits rate limits (Key Vault throttles per vault).
- **Cache in memory with a TTL shorter than the rotation period** (e.g. 5–15 min).
  Use the store's caching client when one exists (AWS
  `aws-secretsmanager-caching` for Python/Java/.NET, the Key Vault
  configuration provider's `ReloadInterval` in .NET, Spring Cloud property
  sources).
- **Share one client per process.** Clients hold connection pools and tokens.
- **On 401/403 from the downstream API, refresh once and retry once.** That
  handles rotation without a restart. Don't loop.
- **Serve the last good value if the store is briefly unavailable.** Don't
  take the service down because the vault blinked.
- **Prefer files over env vars when rotation matters.** Mounted secrets
  (Vault Agent, Secrets Store CSI, Kubernetes Secret volumes) update in place.
  Env vars are fixed at process start, inherited by child processes, and
  visible in `/proc/<pid>/environ` and crash dumps.
- **Never log, print or put secrets in URLs or argv.** Pass them on stdin
  (`--password-stdin`). Wrap them in a type whose `String()`/`__repr__`
  redacts. Keep `set -x` off around them.
- **Fail fast if missing:** a clear startup error beats a 401 in production.

### Delivery options, simplest first

1. **Platform injection, no code:** Kubernetes Secret synced by **External
   Secrets Operator** or mounted by the **Secrets Store CSI driver**; App
   Service/Functions **Key Vault references**; ECS/Lambda secrets; CI secret
   variables (Key Vault-linked variable groups in Azure DevOps). The app just
   reads an env var or file.
2. **Sidecar / agent:** Vault Agent renders files and handles auth and lease
   renewal. The app reads a file and reloads on change.
3. **SDK in the app:** use the cached patterns from `secretscan explain`.
   Best when the app needs many secrets or dynamic credentials.

## 3. Patterns by language

Run `secretscan explain <rule> --lang <lang> --store <env|vault|aws|azure|gcp>`
for complete snippets. The core shapes:

**Python**: env with fail-fast, or the AWS caching client:

```python
from aws_secretsmanager_caching import SecretCache, SecretCacheConfig
_secrets = SecretCache(config=SecretCacheConfig(secret_refresh_interval=300))
token = _secrets.get_secret_string("prod/my-app/github-token")   # memory hit after first call
```

**Go**: one `CachedSecret` per secret (in `secretscan explain ... --lang go`):
mutex-guarded value, TTL, `Invalidate()` after a 401, and the last good value
kept on store errors.

**.NET**: configuration provider with reload, so values flow through `IOptionsMonitor`:

```csharp
builder.Configuration.AddAzureKeyVault(new Uri(kvUrl), new DefaultAzureCredential(),
    new AzureKeyVaultConfigurationOptions { ReloadInterval = TimeSpan.FromMinutes(5) });
```

**Node/TypeScript**: a cached promise, where concurrent callers share one
in-flight fetch.

**Kubernetes**: ExternalSecret with `refreshInterval`, mounted as a volume.

**Terraform**: `sensitive = true` inputs; on 1.10+ ephemeral resources, on
1.11+ write-only arguments, so values never reach state.

**Docker**: `RUN --mount=type=secret` at build time. Never `ENV`/`ARG`: they
are stored in image metadata.

**CI**: OIDC to the cloud (`id-token: write` in GitHub Actions; workload
identity federation service connections in Azure DevOps). Map secret
variables into `env:` explicitly.

## 4. Local development

- Commit `.env.example` (names only) and keep `.env` in `.gitignore`.
- Populate from the store instead of copy-paste: `op run --env-file=.env.example -- ./app`,
  `aws-vault exec`, `vault kv get`, `dotnet user-secrets`.
- Use your own identity locally (`az login`, `aws sso login`, `gcloud auth
  application-default login`). `DefaultAzureCredential` and the AWS/GCP
  default chains pick these up, so the same code runs in dev and prod.

## 5. Org setup for secretscan

Point guidance at your platform's store and runbook in `.secretscan.toml` (or an
org-wide config referenced with `[extend] path`):

```toml
[remediation]
store   = "azure"                       # env | vault | aws | azure | gcp
runbook = "https://wiki.example.com/platform/secrets-rotation"
```

Every finding, SARIF help entry and `explain` output then targets that store
and links the runbook.
