// Package remediate turns findings into actionable guidance: how urgent it
// is, how to rotate the credential, how to stop needing it at all (keyless /
// workload identity), and how to load it efficiently in the file's language.
package remediate

import (
	"path/filepath"
	"regexp"
	"strings"
)

// Guidance is attached to every finding.
type Guidance struct {
	Urgency   string   `json:"Urgency"`             // revoke-now | rotate | review
	Family    string   `json:"Family"`              // provider family, e.g. "AWS"
	Rotate    string   `json:"Rotate"`              // how to revoke/rotate
	Eliminate string   `json:"Eliminate,omitempty"` // how to stop needing a static secret
	EnvVar    string   `json:"EnvVar"`              // suggested variable / secret name
	Language  string   `json:"Language,omitempty"`  // detected from the file
	Replace   string   `json:"Replace,omitempty"`   // drop-in expression replacing the literal
	Store     string   `json:"Store,omitempty"`     // secret store the snippet targets
	Steps     []string `json:"Steps,omitempty"`     // ordered checklist
	Runbook   string   `json:"Runbook,omitempty"`   // org runbook link from config
}

// Family describes one credential issuer.
type Family struct {
	Name      string
	Rotate    string
	Eliminate string
	EnvVar    string
	// SDKChain: the official SDK resolves credentials itself (AWS/Azure/GCP),
	// so the right fix is deleting the literal, not reading an env var.
	SDKChain bool
}

var families = []struct {
	match *regexp.Regexp
	fam   Family
}{
	{regexp.MustCompile(`^aws-bedrock`), Family{"AWS Bedrock",
		"Revoke the API key in the Bedrock console (API keys) or delete the backing IAM user's service-specific credential; review CloudTrail for its use.",
		"Call Bedrock with an IAM role (SigV4) instead of API keys: EKS Pod Identity/IRSA in-cluster, an OIDC-federated role in CI, or route traffic through your LLM gateway.",
		"AWS_BEARER_TOKEN_BEDROCK", true}},
	{regexp.MustCompile(`^aws-`), Family{"AWS",
		"Deactivate then delete the access key (IAM > Users > Security credentials), check CloudTrail for activity, and issue nothing new if a role can be used.",
		"Use IAM roles, not keys: EKS Pod Identity or IRSA on EKS, instance profiles on EC2, OIDC-federated roles for GitHub Actions/Azure DevOps, and `aws sso login` (IAM Identity Center) for people. The AWS SDK default credential chain picks these up with no code.",
		"AWS_ACCESS_KEY_ID", true}},
	{regexp.MustCompile(`^azure-ad-client-secret`), Family{"Microsoft Entra ID",
		"Delete the client secret (Entra ID > App registrations > Certificates & secrets) and review the service principal's sign-in logs.",
		"Replace client secrets with managed identities (Azure-hosted) or workload identity federation (AKS workload identity, GitHub/Azure DevOps federated credentials). Use DefaultAzureCredential in code.",
		"AZURE_CLIENT_SECRET", true}},
	{regexp.MustCompile(`^azure-storage|^azure-sas`), Family{"Azure Storage",
		"Regenerate the exposed account key (key1/key2) or revoke the SAS by rotating its signing key or stored access policy.",
		"Use Entra ID RBAC (Storage Blob Data roles) with managed/workload identity and DefaultAzureCredential, disable shared-key access on the account, and issue short-lived user-delegation SAS only when a SAS is unavoidable.",
		"AZURE_STORAGE_CONNECTION_STRING", true}},
	{regexp.MustCompile(`^azure-devops`), Family{"Azure DevOps",
		"Revoke the PAT (User settings > Personal access tokens, or an org admin via the PAT admin API) and check the org audit log.",
		"In pipelines use $(System.AccessToken) or service connections with workload identity federation; for automation use a service principal/managed identity with Entra tokens instead of PATs. If a PAT is unavoidable: minimal scope, short expiry, stored in Key Vault via a variable group.",
		"AZURE_DEVOPS_EXT_PAT", false}},
	{regexp.MustCompile(`^azure-openai`), Family{"Azure OpenAI",
		"Regenerate the key (resource > Keys and Endpoint) and switch traffic to the other key during rotation.",
		"Use Entra ID auth (Cognitive Services OpenAI User role) with DefaultAzureCredential and disable local (key) auth, or route through your LLM gateway.",
		"AZURE_OPENAI_API_KEY", false}},
	{regexp.MustCompile(`^azure-apim`), Family{"Azure API Management",
		"Regenerate the subscription key in APIM > Subscriptions.", "Prefer OAuth/managed identity validation in APIM policies over subscription keys.",
		"APIM_SUBSCRIPTION_KEY", false}},
	{regexp.MustCompile(`^(teams|power-automate)-webhook`), Family{"Microsoft Teams / Power Automate",
		"Delete and recreate the webhook/workflow so the old URL stops working.", "Keep webhook URLs in Key Vault; treat the URL itself as the secret.",
		"TEAMS_WEBHOOK_URL", false}},
	{regexp.MustCompile(`^(gcp|firebase)-`), Family{"Google Cloud",
		"Delete the key (IAM > Service accounts > Keys, or APIs & Services > Credentials) and review Cloud Audit Logs.",
		"Use attached service accounts / GKE Workload Identity in GCP and Workload Identity Federation from other clouds and CI; API keys should be restricted by API and referrer/IP.",
		"GOOGLE_APPLICATION_CREDENTIALS", true}},
	{regexp.MustCompile(`^github-`), Family{"GitHub",
		"Revoke the token (Settings > Developer settings > Tokens; org owners can revoke fine-grained tokens) and review the org audit log.",
		"In Actions use the built-in GITHUB_TOKEN with least-privilege `permissions:`, and OIDC for cloud access. For services use a GitHub App (short-lived installation tokens) instead of a PAT.",
		"GITHUB_TOKEN", false}},
	{regexp.MustCompile(`^gitlab-`), Family{"GitLab",
		"Revoke the token (User/Project/Group settings > Access tokens; reset runner tokens in runner settings).",
		"In CI use CI_JOB_TOKEN and ID tokens (OIDC); otherwise project/group access tokens with expiry and minimal scopes.",
		"GITLAB_TOKEN", false}},
	{regexp.MustCompile(`^jfrog-`), Family{"JFrog Artifactory",
		"Revoke the token (Administration > User Management > Access Tokens) and review Artifactory access logs.",
		"Use JFrog OIDC integration from GitHub Actions/Azure DevOps to mint short-lived access tokens per job; never reuse personal API keys.",
		"JFROG_ACCESS_TOKEN", false}},
	{regexp.MustCompile(`^vault-`), Family{"HashiCorp Vault",
		"Revoke it (`vault token revoke -accessor <accessor>`) and audit the token's policies in the audit log.",
		"Authenticate workloads with an auth method (Kubernetes, AppRole, JWT/OIDC, AWS/Azure) through Vault Agent or the Secrets Store CSI driver; tokens should be short-lived and never committed.",
		"VAULT_TOKEN", false}},
	{regexp.MustCompile(`^(terraform-cloud|pulumi)`), Family{"IaC platform",
		"Revoke the token in the platform's user/team token settings.",
		"Use dynamic provider credentials / OIDC between the runner and the cloud, and team tokens scoped to one workspace.",
		"TF_TOKEN_app_terraform_io", false}},
	{regexp.MustCompile(`^(npm|npmrc|pypi|nuget|rubygems|docker|hex)-`), Family{"Package registry",
		"Revoke the token in the registry's account settings and check for unexpected package versions.",
		"Use trusted publishing (OIDC) from CI (PyPI, npm and others support it) or short-lived CI-scoped tokens; keep any remaining token in the CI secret store.",
		"NPM_TOKEN", false}},
	{regexp.MustCompile(`^(openai|anthropic|groq|xai|perplexity|replicate|langsmith|cohere|mistral|deepseek|pinecone|huggingface)-`), Family{"AI provider",
		"Revoke the key in the provider console and check usage/billing for abuse.",
		"Don't ship provider keys to apps: route calls through your LLM gateway (e.g. LiteLLM) with per-app virtual keys, budgets and logging; the provider key lives only in the gateway's secret store.",
		"", false}},
	{regexp.MustCompile(`^litellm`), Family{"LiteLLM gateway",
		"Rotate the master/virtual key on the proxy and update the proxy's secret store; revoke leaked virtual keys via the key management API.",
		"Keep the master key only in the gateway's secret store; give each app its own virtual key with budget, rate limits and model allowlist.",
		"LITELLM_API_KEY", false}},
	{regexp.MustCompile(`^(slack|discord|telegram)-`), Family{"Chat platform",
		"Regenerate the token (or delete the webhook) in the app/bot settings.", "Keep tokens and webhook URLs in your secret store; use per-environment apps.",
		"", false}},
	{regexp.MustCompile(`^(stripe|square|paypal|shopify)-`), Family{"Payments",
		"Roll the key in the provider dashboard (most support an overlap window) and review recent API activity.",
		"Use restricted keys with only the needed permissions, kept in your secret store; never in front-end code.",
		"", false}},
	{regexp.MustCompile(`^(url-credentials|jdbc-password|connection-string-password|snowflake-credentials)`), Family{"Database / service password",
		"Change the account's password and check for logins from unknown hosts.",
		"Use passwordless auth where the platform supports it (RDS/Aurora IAM auth, Entra ID auth for Azure SQL/PostgreSQL with managed identity), or Vault dynamic database credentials with short TTLs.",
		"DATABASE_URL", false}},
	{regexp.MustCompile(`^(private-key|putty-private-key|age-secret-key|kubeconfig-client-key)`), Family{"Private key",
		"Treat the key pair as compromised: replace it, remove the public key everywhere it's trusted (authorized_keys, deploy keys, cert issuers) and revoke any certificate.",
		"Keep signing keys in KMS/HSM (AWS KMS, Azure Key Vault keys) so they never leave it; use short-lived SSH certificates (e.g. Vault SSH CA) and exec-based kubeconfig auth (aws eks get-token, kubelogin).",
		"", false}},
	{regexp.MustCompile(`^jwt$`), Family{"JWT",
		"If the token is long-lived, revoke the session or rotate the signing key; short-lived tokens just expire.",
		"Don't commit tokens; obtain them at runtime from the identity provider.",
		"AUTH_TOKEN", false}},
	{regexp.MustCompile(`^sensitive-file$`), Family{"Sensitive file",
		"Remove the file, purge it from history (git filter-repo) and rotate whatever it contains.",
		"Keep keystores and credential files in a secret store or mount them at runtime; add the pattern to .gitignore.",
		"", false}},
}

var genericFamily = Family{"Unknown issuer",
	"Find the owner, rotate the credential at its issuer, and check for misuse.",
	"Load it at runtime from your secret store (or platform-injected env/file) instead of source.",
	"", false}

// envNames gives conventional variable names for specific rules.
var envNames = map[string]string{
	"aws-secret-access-key": "AWS_SECRET_ACCESS_KEY", "aws-session-token": "AWS_SESSION_TOKEN",
	"azure-storage-account-key": "AZURE_STORAGE_KEY", "azure-sas-token": "AZURE_STORAGE_SAS_TOKEN",
	"gcp-api-key": "GOOGLE_API_KEY", "gcp-oauth-client-secret": "GOOGLE_CLIENT_SECRET",
	"gitlab-runner-token": "CI_RUNNER_TOKEN", "pypi-upload-token": "PYPI_TOKEN", "nuget-api-key": "NUGET_API_KEY",
	"docker-hub-pat": "DOCKERHUB_TOKEN", "openai-api-key": "OPENAI_API_KEY", "anthropic-api-key": "ANTHROPIC_API_KEY",
	"groq-api-key": "GROQ_API_KEY", "xai-api-key": "XAI_API_KEY", "huggingface-token": "HF_TOKEN",
	"mistral-api-key": "MISTRAL_API_KEY", "cohere-api-key": "COHERE_API_KEY", "pinecone-api-key": "PINECONE_API_KEY",
	"slack-bot-token": "SLACK_BOT_TOKEN", "slack-webhook-url": "SLACK_WEBHOOK_URL", "stripe-key": "STRIPE_SECRET_KEY",
	"stripe-webhook-secret": "STRIPE_WEBHOOK_SECRET", "sendgrid-api-key": "SENDGRID_API_KEY",
	"twilio-auth-token": "TWILIO_AUTH_TOKEN", "datadog-key": "DD_API_KEY", "sentry-token": "SENTRY_AUTH_TOKEN",
	"databricks-token": "DATABRICKS_TOKEN", "digitalocean-token": "DIGITALOCEAN_TOKEN", "linear-api-key": "LINEAR_API_KEY",
	"vault-token-legacy": "VAULT_TOKEN", "terraform-cloud-token": "TF_TOKEN_app_terraform_io", "pulumi-access-token": "PULUMI_ACCESS_TOKEN",
	"grafana-cloud-api-token": "GRAFANA_CLOUD_TOKEN", "grafana-service-account-token": "GRAFANA_SA_TOKEN",
}

// FamilyFor returns the issuer family for a rule ID.
func FamilyFor(ruleID string) Family {
	for _, f := range families {
		if f.match.MatchString(ruleID) {
			return f.fam
		}
	}
	return genericFamily
}

// Input is what guidance needs about a finding.
type Input struct {
	RuleID, File, Line, Secret, Verification string
	Store, Runbook                           string // org defaults from config/flags
}

// For builds guidance for one finding.
func For(in Input) Guidance {
	fam := FamilyFor(in.RuleID)
	lang := LanguageFor(in.File)
	g := Guidance{Family: fam.Name, Rotate: fam.Rotate, Eliminate: fam.Eliminate, Language: lang,
		Store: storeOrDefault(in.Store), Runbook: in.Runbook}
	switch in.Verification {
	case "verified":
		g.Urgency = "revoke-now"
	case "invalid":
		g.Urgency = "review" // already dead: still remove it from code
	default:
		g.Urgency = "rotate"
	}
	g.EnvVar = EnvName(in.RuleID, in.Line, in.Secret, fam)
	if fam.SDKChain {
		g.Replace = sdkChainNote(fam.Name, lang)
	} else if expr := EnvExpr(lang, g.EnvVar); expr != "" {
		g.Replace = expr
	}
	g.Steps = steps(g, fam)
	return g
}

func steps(g Guidance, fam Family) []string {
	var s []string
	if g.Urgency == "revoke-now" {
		s = append(s, "LIVE credential: revoke it now, before anything else. "+fam.Rotate)
	} else {
		s = append(s, "Rotate: "+fam.Rotate)
	}
	if fam.Eliminate != "" {
		s = append(s, "Remove the need for it: "+fam.Eliminate)
	}
	if fam.SDKChain {
		s = append(s, "Delete the literal; the "+fam.Name+" SDK default credential chain will find the workload identity.")
	} else if g.Replace != "" {
		s = append(s, "Replace the literal with "+g.Replace+" and inject "+g.EnvVar+" from "+storeLabel(g.Store)+".")
	} else {
		s = append(s, "Move the value to "+storeLabel(g.Store)+" and reference it as "+g.EnvVar+".")
	}
	s = append(s, "Removing it from the latest commit is not enough: it stays in git history. Rotation is the fix.")
	if g.Runbook != "" {
		s = append(s, "Follow your team's runbook: "+g.Runbook)
	}
	return s
}

// Stores supported by snippets.
var Stores = []string{"env", "vault", "aws", "azure", "gcp"}

func storeOrDefault(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	for _, k := range Stores {
		if s == k {
			return s
		}
	}
	return "env"
}

func storeLabel(s string) string {
	switch s {
	case "vault":
		return "HashiCorp Vault (via Vault Agent/CSI or the SDK)"
	case "aws":
		return "AWS Secrets Manager"
	case "azure":
		return "Azure Key Vault"
	case "gcp":
		return "GCP Secret Manager"
	}
	return "your secret store / CI secret variables"
}

var identRe = regexp.MustCompile(`([A-Za-z_][A-Za-z0-9_.-]*)["'\x60]?\s*(?::=|=>|=|:)\s*["'\x60]?[^"'\x60\s]*$`)

// EnvName picks a variable name: the conventional one for the rule, else the
// identifier the literal was assigned to, else one derived from the rule.
func EnvName(ruleID, line, secret string, fam Family) string {
	if n, ok := envNames[ruleID]; ok {
		return n
	}
	if fam.EnvVar != "" {
		return fam.EnvVar
	}
	if i := strings.Index(line, secret); i > 0 && secret != "" {
		if m := identRe.FindStringSubmatch(line[:i]); m != nil {
			if n := toEnv(m[1]); len(n) >= 3 {
				return n
			}
		}
	}
	return toEnv(strings.TrimSuffix(strings.TrimSuffix(ruleID, "-key"), "-token")) + "_SECRET"
}

var camel = regexp.MustCompile(`([a-z0-9])([A-Z])`)

func toEnv(s string) string {
	if i := strings.LastIndexAny(s, ".:"); i >= 0 && i < len(s)-1 {
		if p := s[i+1:]; len(p) >= 3 {
			s = p // spring.datasource.password -> password
		} else {
			s = strings.NewReplacer(".", "_", ":", "_").Replace(s)
		}
	}
	s = camel.ReplaceAllString(s, "${1}_${2}")
	s = strings.NewReplacer("-", "_", ".", "_", " ", "_").Replace(s)
	return strings.Trim(strings.ToUpper(s), "_")
}

// LanguageFor maps a file name to a snippet language.
func LanguageFor(path string) string {
	base := strings.ToLower(filepath.Base(path))
	switch {
	case strings.Contains(base, "dockerfile") || strings.Contains(base, "containerfile"):
		return "dockerfile"
	case base == ".env" || strings.HasPrefix(base, ".env.") || strings.HasSuffix(base, ".env"):
		return "dotenv"
	case strings.HasSuffix(path, ".github/workflows/"+filepath.Base(path)) || strings.Contains(path, ".github/workflows/"):
		return "github-actions"
	case strings.Contains(base, "azure-pipelines") || strings.Contains(path, ".azuredevops/") || strings.Contains(path, "/pipelines/"):
		return "azure-pipelines"
	}
	switch filepath.Ext(base) {
	case ".py":
		return "python"
	case ".go":
		return "go"
	case ".js", ".mjs", ".cjs", ".jsx":
		return "javascript"
	case ".ts", ".tsx", ".mts":
		return "typescript"
	case ".java", ".kt", ".kts", ".scala":
		return "java"
	case ".cs":
		return "csharp"
	case ".rb":
		return "ruby"
	case ".php":
		return "php"
	case ".sh", ".bash", ".zsh":
		return "shell"
	case ".ps1":
		return "powershell"
	case ".tf", ".tfvars", ".hcl":
		return "terraform"
	case ".yaml", ".yml":
		return "kubernetes"
	case ".properties":
		return "spring"
	case ".config", ".xml":
		return "dotnet-config"
	case ".json":
		return "json-config"
	}
	return ""
}

// EnvExpr is a drop-in expression reading an env var in the language.
func EnvExpr(lang, env string) string {
	switch lang {
	case "python":
		return `os.environ["` + env + `"]`
	case "go":
		return `os.Getenv("` + env + `")`
	case "javascript", "typescript":
		return `process.env.` + env
	case "java":
		return `System.getenv("` + env + `")`
	case "csharp":
		return `Environment.GetEnvironmentVariable("` + env + `")`
	case "ruby":
		return `ENV.fetch("` + env + `")`
	case "php":
		return `getenv('` + env + `')`
	case "shell":
		return `"${` + env + `:?not set}"`
	case "powershell":
		return `$env:` + env
	case "terraform":
		return `var.` + strings.ToLower(env) + ` (sensitive = true; set via TF_VAR_` + strings.ToLower(env) + `)`
	case "kubernetes":
		return `valueFrom.secretKeyRef (Secret synced by External Secrets Operator or the CSI driver)`
	case "spring":
		return `${` + env + `}`
	case "dotenv":
		return `(keep .env out of git; commit .env.example with ` + env + `= empty)`
	case "dockerfile":
		return `RUN --mount=type=secret,id=` + strings.ToLower(env) + ` (build) / runtime env, never ENV/ARG`
	case "github-actions":
		return `${{ secrets.` + env + ` }}`
	case "azure-pipelines":
		return `$(` + env + `) from a Key Vault-linked variable group`
	case "dotnet-config":
		return `Azure Key Vault configuration provider / app setting reference (@Microsoft.KeyVault(...))`
	}
	return ""
}

func sdkChainNote(fam, lang string) string {
	switch fam {
	case "AWS", "AWS Bedrock":
		return "no code: delete the literal and let the AWS SDK default credential chain use the workload role"
	case "Microsoft Entra ID", "Azure Storage":
		if lang == "python" || lang == "csharp" || lang == "java" || lang == "javascript" || lang == "typescript" || lang == "go" {
			return "DefaultAzureCredential() with a managed/workload identity, no secret"
		}
		return "managed / workload identity, no secret"
	case "Google Cloud":
		return "no code: Application Default Credentials from the attached service account / workload identity federation"
	}
	return ""
}
