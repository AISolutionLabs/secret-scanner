// SPDX-License-Identifier: Apache-2.0

package config

import "strings"

// tok wraps a prefixed token: word boundary before, and no further token
// characters after, so longer strings that merely contain the shape are skipped.
// Base64 punctuation (+ /) is excluded on both sides so tokens are not
// "found" in the middle of encoded blobs.
func tok(secret string) string {
	return TokPrefix + secret + TokSuffix
}

// Token-rule wrapper and semi-generic marker, recognized by the compiler.
const (
	TokPrefix  = `(?:^|[^0-9A-Za-z_+/-])(`
	TokSuffix  = `)(?:[^0-9A-Za-z_+/-]|$)`
	SemiMarker = `[\w.-]{0,50}?(?i:`
)

// IsTokenChar reports whether c can continue a token (for boundary checks).
func IsTokenChar(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c == '_' || c == '+' || c == '/' || c == '-'
}

// semi builds a "keyword near an assignment" regex (same idea as gitleaks'
// semi-generic rules): identifier, optional suffix, an operator, optional
// quote, then the secret in group 1.
func semi(ids []string, secret string, caseInsensitiveSecret bool) string {
	p := `[\w.-]{0,50}?(?i:` + strings.Join(ids, "|") + `)(?:[ \t\w.-]{0,20})[\s'"]{0,3}` +
		`(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}(` + secret + `)(?:[\x60'"\s;,)\]}]|\\[nrt]|$)`
	if caseInsensitiveSecret {
		return `(?i)` + p
	}
	return p
}

const uuid = `[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}`

func r(id, desc, sev, regex string, keywords []string, tags ...string) Rule {
	return Rule{ID: id, Description: desc, Severity: sev, Regex: regex, Keywords: keywords, Tags: tags}
}

func withEntropy(rule Rule, e float64) Rule { rule.Entropy = e; return rule }

// DefaultRules is the built-in rule pack.
func DefaultRules() []Rule {
	rules := []Rule{
		// --- Cloud: AWS ---------------------------------------------------
		withEntropy(r("aws-access-key-id", "AWS access key ID", "critical",
			tok(`(?:A3T[A-Z0-9]|AKIA|ASIA|ABIA|ACCA)[A-Z2-7]{16}`),
			[]string{"akia", "asia", "abia", "acca", "a3t"}, "aws", "cloud"), 3.0),
		// SigV4 credential scope (Authorization headers, logs, presigned URLs):
		// the key ID is followed by "/<date>/", which the token boundary rejects.
		withEntropy(r("aws-access-key-id-sigv4", "AWS access key ID in a SigV4 credential scope", "critical",
			`(?i:credential)=((?:AKIA|ASIA)[A-Z2-7]{16})(?:/|%2F)\d{8}(?:/|%2F)`,
			[]string{"credential="}, "aws", "cloud"), 3.0),
		withEntropy(r("aws-secret-access-key", "AWS secret access key", "critical",
			semi([]string{`aws_?(?:secret_?(?:access_?)?key|sk)`, `secretaccesskey`}, `[A-Za-z0-9/+]{40}`, false),
			[]string{"aws", "secretaccesskey"}, "aws", "cloud"), 4.0),
		withEntropy(r("aws-session-token", "AWS session token", "high",
			semi([]string{`aws_?session_?token`, `sessiontoken`}, `[A-Za-z0-9/+=]{100,1000}`, false),
			[]string{"session"}, "aws", "cloud"), 4.0),
		r("aws-bedrock-api-key", "AWS Bedrock API key", "critical",
			tok(`ABSKQmVkcm9ja0FQSUtleS[A-Za-z0-9+/=]{40,300}|bedrock-api-key-[A-Za-z0-9+/=]{60,1000}`),
			[]string{"absk", "bedrock-api-key-"}, "aws", "ai"),

		// --- Cloud: Azure -------------------------------------------------
		r("azure-ad-client-secret", "Azure AD / Entra ID client secret", "critical",
			`(?:^|[\\'"\x60\s>=:(,)])([a-zA-Z0-9_~.]{3}\dQ~[a-zA-Z0-9_~.-]{31,34})(?:$|[\\'"\x60\s<),])`,
			[]string{"q~"}, "azure", "cloud"),
		r("azure-storage-connection-string", "Azure Storage / Cosmos DB account key in connection string", "critical",
			`(?i)AccountKey=([A-Za-z0-9+/]{86}==)`, []string{"accountkey"}, "azure", "cloud"),
		withEntropy(r("azure-storage-account-key", "Azure Storage account key", "critical",
			semi([]string{`account_?key`, `storage_?(?:account_?)?key`, `azure_?storage_?key`, `primary_?key`}, `[A-Za-z0-9+/]{86}==`, false),
			[]string{"accountkey", "account_key", "storagekey", "storage_key", "storageaccountkey", "storage_account_key", "azure_storage_key", "primarykey", "primary_key"}, "azure", "cloud"), 4.0),
		r("azure-sas-token", "Azure shared access signature", "high",
			`(?i)[?&]sig=([A-Za-z0-9%+/]{40,}(?:%3D){0,2}=?)`, []string{"sig="}, "azure", "cloud"),
		r("azure-devops-pat", "Azure DevOps personal access token", "critical",
			tok(`[A-Za-z0-9]{76}AZDO[A-Za-z0-9]{4}`), []string{"azdo"}, "azure", "vcs"),
		withEntropy(r("azure-devops-pat-legacy", "Azure DevOps personal access token (legacy format)", "critical",
			semi([]string{`ado`, `azure_?devops`, `azdo`, `devops`, `system_?accesstoken`, `\w*_pat`, `pat_\w*`}, `[a-z2-7]{52}`, false),
			[]string{"ado", "devops", "azdo", "accesstoken", "_pat", "pat_"}, "azure", "vcs"), 3.5),
		r("azure-openai-key", "Azure OpenAI API key", "high",
			semi([]string{`azure_?openai(?:_?api)?_?key`, `aoai_?key`}, `[a-fA-F0-9]{32}|[A-Za-z0-9]{84}`, false),
			[]string{"openai", "aoai"}, "azure", "ai"),
		r("azure-apim-subscription-key", "Azure API Management subscription key", "medium",
			semi([]string{`ocp-apim-subscription-key`, `apim_?(?:subscription_?)?key`}, `[a-fA-F0-9]{32}`, false),
			[]string{"apim"}, "azure", "cloud"),
		r("teams-webhook", "Microsoft Teams incoming webhook", "medium",
			`(?i)(https://[a-z0-9-]+\.webhook\.office\.com/webhookb2/[a-z0-9-]+@[a-z0-9-]+/IncomingWebhook/[a-z0-9]+/[a-z0-9-]+)`,
			[]string{"webhook.office.com"}, "webhook", "chat"),
		r("power-automate-webhook", "Power Automate / Teams workflow webhook URL", "medium",
			`(?i)(https://[a-z0-9.-]+\.logic\.azure\.com(?::443)?/workflows/[a-f0-9]+/triggers/[^\s"']+?sig=[\w-]{20,})`,
			[]string{"logic.azure.com"}, "webhook", "azure"),

		// --- Cloud: GCP / Google -----------------------------------------
		r("gcp-api-key", "Google Cloud / Firebase API key", "high",
			tok(`AIza[\w-]{35}`), []string{"aiza"}, "gcp", "cloud"),
		r("gcp-service-account-key", "GCP service account private key ID", "critical",
			`"private_key_id"\s*:\s*"([a-f0-9]{40})"`, []string{"private_key_id"}, "gcp", "cloud"),
		r("gcp-oauth-client-secret", "Google OAuth client secret", "high",
			tok(`GOCSPX-[\w-]{28}`), []string{"gocspx-"}, "gcp"),
		r("gcp-oauth-access-token", "Google OAuth access token", "medium",
			tok(`ya29\.[\w-]{30,}`), []string{"ya29."}, "gcp"),
		r("firebase-fcm-server-key", "Firebase Cloud Messaging server key", "high",
			tok(`AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}`), []string{"aaaa"}, "gcp"),

		// --- Other clouds / PaaS -----------------------------------------
		r("digitalocean-token", "DigitalOcean token", "critical",
			tok(`do[por]_v1_[a-f0-9]{64}`), []string{"dop_v1_", "doo_v1_", "dor_v1_"}, "cloud"),
		r("heroku-api-key", "Heroku API key", "high",
			tok(`HRKU-AA[0-9A-Za-z_-]{58}`), []string{"hrku-"}, "cloud"),
		r("heroku-api-key-legacy", "Heroku API key (legacy)", "high",
			semi([]string{`heroku`}, uuid, false), []string{"heroku"}, "cloud"),
		r("cloudflare-api-token", "Cloudflare API token or global key", "high",
			semi([]string{`cloudflare`, `cf_?api`, `cf_?token`}, `[A-Za-z0-9_-]{40}|[a-f0-9]{37}`, false),
			[]string{"cloudflare", "cf_api", "cfapi", "cf_token", "cftoken"}, "cloud"),
		r("alibaba-access-key-id", "Alibaba Cloud access key ID", "high",
			tok(`LTAI[a-zA-Z0-9]{20}`), []string{"ltai"}, "cloud"),
		r("ibm-cloud-api-key", "IBM Cloud API key", "high",
			semi([]string{`ibm(?:_?cloud)?_?api_?key`}, `[A-Za-z0-9_-]{44}`, false), []string{"ibm"}, "cloud"),
		r("oracle-oci-key-fingerprint", "OCI API signing key fingerprint with key file", "low",
			semi([]string{`oci_?(?:cli_?)?fingerprint`}, `(?:[0-9a-f]{2}:){15}[0-9a-f]{2}`, false), []string{"fingerprint"}, "cloud"),

		// --- Source control / CI -----------------------------------------
		r("github-pat", "GitHub personal access token", "critical", tok(`ghp_[0-9a-zA-Z]{36}`), []string{"ghp_"}, "github", "vcs"),
		r("github-fine-grained-pat", "GitHub fine-grained personal access token", "critical",
			tok(`github_pat_[0-9a-zA-Z_]{82}`), []string{"github_pat_"}, "github", "vcs"),
		r("github-oauth", "GitHub OAuth access token", "critical", tok(`gho_[0-9a-zA-Z]{36}`), []string{"gho_"}, "github", "vcs"),
		r("github-app-token", "GitHub App user/installation token", "critical",
			tok(`(?:ghu|ghs)_[0-9a-zA-Z]{36}`), []string{"ghu_", "ghs_"}, "github", "vcs"),
		r("github-refresh-token", "GitHub refresh token", "critical", tok(`ghr_[0-9a-zA-Z]{36}`), []string{"ghr_"}, "github", "vcs"),
		r("gitlab-pat", "GitLab personal access token", "critical",
			tok(`glpat-[\w-]{20,}(?:\.[0-9a-z]{2}\.[0-9a-z]{9})?`), []string{"glpat-"}, "gitlab", "vcs"),
		r("gitlab-pipeline-trigger-token", "GitLab pipeline trigger token", "high",
			tok(`glptt-[0-9a-f]{40}`), []string{"glptt-"}, "gitlab", "vcs"),
		r("gitlab-runner-registration-token", "GitLab runner registration token", "high",
			tok(`GR1348941[\w-]{20}`), []string{"gr1348941"}, "gitlab", "vcs"),
		r("gitlab-runner-token", "GitLab runner authentication token", "high",
			tok(`glrt-[\w-]{20,}`), []string{"glrt-"}, "gitlab", "vcs"),
		r("gitlab-deploy-token", "GitLab deploy token", "high", tok(`gldt-[\w-]{20,}`), []string{"gldt-"}, "gitlab", "vcs"),
		r("gitlab-oauth-app-secret", "GitLab OAuth application secret", "high",
			tok(`gloas-[\w-]{64}`), []string{"gloas-"}, "gitlab", "vcs"),
		r("bitbucket-app-password", "Bitbucket app password", "high",
			tok(`ATBB[A-Za-z0-9_=.-]{28,}`), []string{"atbb"}, "vcs"),
		r("atlassian-api-token", "Atlassian (Jira/Confluence) API token", "high",
			tok(`ATATT3[A-Za-z0-9_=-]{186}`), []string{"atatt3"}, "atlassian"),
		withEntropy(r("atlassian-api-token-legacy", "Atlassian API token (legacy)", "medium",
			semi([]string{`atlassian`, `confluence`, `jira`}, `[A-Za-z0-9]{24}`, false),
			[]string{"atlassian", "confluence", "jira"}, "atlassian"), 3.5),
		r("circleci-token", "CircleCI API token", "high",
			semi([]string{`circle(?:ci)?_?(?:api_?)?token`}, `CCIPAT_[A-Za-z0-9]{22}_[a-f0-9]{40}|[a-f0-9]{40}`, false),
			[]string{"circle"}, "ci"),
		r("sonarqube-token", "SonarQube / SonarCloud token", "high",
			tok(`sq[uap]_[a-f0-9]{40}`), []string{"squ_", "sqa_", "sqp_"}, "ci"),
		r("snyk-token", "Snyk API token", "high", semi([]string{`snyk`}, uuid, false), []string{"snyk"}, "ci"),
		r("terraform-cloud-token", "Terraform Cloud / Enterprise API token", "critical",
			`(?i)\b([a-z0-9]{14}\.atlasv1\.[a-z0-9_=-]{60,70})(?:[^0-9A-Za-z_=-]|$)`, []string{"atlasv1"}, "iac"),
		r("pulumi-access-token", "Pulumi access token", "high", tok(`pul-[a-f0-9]{40}`), []string{"pul-"}, "iac"),
		r("doppler-token", "Doppler token", "high", `(?i)\b(dp\.(?:pt|st|sa|ct|scim)\.[a-z0-9]{40,44})`, []string{"dp."}, "secrets-manager"),
		r("vault-token", "HashiCorp Vault service/batch token", "critical",
			tok(`hv[sb]\.[\w-]{90,400}`), []string{"hvs.", "hvb."}, "vault", "secrets-manager"),
		withEntropy(r("vault-token-legacy", "HashiCorp Vault token (legacy)", "high",
			semi([]string{`vault_?token`, `vault`}, `s\.[A-Za-z0-9]{24}`, false), []string{"vault"}, "vault"), 3.5),
		r("octopus-deploy-api-key", "Octopus Deploy API key", "high", tok(`API-[A-Z0-9]{26}`), []string{"api-"}, "ci"),

		// --- Package registries / artifacts ------------------------------
		r("npm-access-token", "npm access token", "critical", tok(`npm_[A-Za-z0-9]{36}`), []string{"npm_"}, "registry"),
		r("npmrc-auth", "Credential in .npmrc / .yarnrc", "high",
			`(?i)(?:^|\s|:)_(?:authToken|auth|password)\s*=\s*["']?([^\s"'$]{12,})`, []string{"_auth", "_password"}, "registry"),
		r("pypi-upload-token", "PyPI upload token", "critical", tok(`pypi-AgEIcHlwaS5vcmc[\w-]{50,1000}`), []string{"pypi-ageichlwas5vcmc"}, "registry"),
		r("nuget-api-key", "NuGet API key", "high", tok(`oy2[a-z0-9]{43}`), []string{"oy2"}, "registry"),
		r("rubygems-api-key", "RubyGems API key", "high", tok(`rubygems_[a-f0-9]{48}`), []string{"rubygems_"}, "registry"),
		r("docker-hub-pat", "Docker Hub personal access token", "high", tok(`dckr_pat_[A-Za-z0-9_-]{27}`), []string{"dckr_pat_"}, "registry"),
		{ID: "docker-config-auth", Description: "Registry credential in Docker config.json", Severity: "high",
			Regex: `"auth"\s*:\s*"([A-Za-z0-9+/]{16,}={0,2})"`, Keywords: []string{`"auth"`},
			Path: `(?i)(?:^|/)(?:\.docker/config\.json|config\.json|\.dockercfg|dockerconfigjson)$`, Tags: []string{"registry"}},
		r("jfrog-api-key", "JFrog Artifactory API key", "critical", tok(`AKCp[A-Za-z0-9]{69}`), []string{"akcp"}, "jfrog", "registry"),
		r("jfrog-identity-token", "JFrog identity / reference token", "critical", tok(`cmVmd[A-Za-z0-9]{59}`), []string{"cmvmd"}, "jfrog", "registry"),
		r("hex-api-key", "Hex.pm API key", "medium", semi([]string{`hex_?api_?key`}, `[a-f0-9]{32}`, false), []string{"hex"}, "registry"),

		// --- AI providers / gateways --------------------------------------
		r("openai-api-key", "OpenAI API key", "critical",
			tok(`sk-(?:(?:proj|svcacct|admin)-[A-Za-z0-9_-]{20,200}|[A-Za-z0-9]{20})T3BlbkFJ[A-Za-z0-9_-]{20,200}`),
			[]string{"t3blbkfj"}, "ai"),
		r("anthropic-api-key", "Anthropic API key", "critical",
			tok(`sk-ant-(?:api03|admin01)-[A-Za-z0-9_-]{80,100}AA`), []string{"sk-ant-"}, "ai"),
		withEntropy(r("litellm-key", "LiteLLM master or virtual key", "critical",
			semi([]string{`litellm(?:_?(?:master|api|virtual|proxy))?_?key`, `master_?key`}, `sk-[A-Za-z0-9_-]{16,128}`, false),
			[]string{"litellm", "master"}, "ai", "gateway"), 3.0),
		r("huggingface-token", "Hugging Face access token", "high",
			tok(`(?:hf_|api_org_)[A-Za-z]{34}`), []string{"hf_", "api_org_"}, "ai"),
		r("groq-api-key", "Groq API key", "high", tok(`gsk_[A-Za-z0-9]{52}`), []string{"gsk_"}, "ai"),
		r("xai-api-key", "xAI API key", "high", tok(`xai-[A-Za-z0-9]{80}`), []string{"xai-"}, "ai"),
		r("perplexity-api-key", "Perplexity API key", "high", tok(`pplx-[A-Za-z0-9]{48}`), []string{"pplx-"}, "ai"),
		r("replicate-api-token", "Replicate API token", "high", tok(`r8_[A-Za-z0-9]{37}`), []string{"r8_"}, "ai"),
		r("langsmith-api-key", "LangSmith / LangChain API key", "high",
			tok(`lsv2_(?:pt|sk)_[a-f0-9]{32}_[a-f0-9]{10}`), []string{"lsv2_"}, "ai"),
		withEntropy(r("cohere-api-key", "Cohere API key", "high",
			semi([]string{`cohere(?:_?api)?_?key`, `co_?api_?key`}, `[A-Za-z0-9]{40}`, false), []string{"cohere", "co_api", "coapi"}, "ai"), 3.5),
		withEntropy(r("mistral-api-key", "Mistral API key", "high",
			semi([]string{`mistral(?:_?api)?_?key`}, `[A-Za-z0-9]{32}`, false), []string{"mistral"}, "ai"), 3.5),
		withEntropy(r("deepseek-api-key", "DeepSeek API key", "high",
			semi([]string{`deepseek(?:_?api)?_?key`}, `sk-[a-f0-9]{32}`, false), []string{"deepseek"}, "ai"), 3.0),
		r("pinecone-api-key", "Pinecone API key", "high",
			semi([]string{`pinecone(?:_?api)?_?key`}, `pcsk_[A-Za-z0-9_]{50,120}|`+uuid, false), []string{"pinecone"}, "ai"),

		// --- Data / analytics / observability -----------------------------
		r("databricks-token", "Databricks personal access token", "critical", tok(`dapi[a-f0-9]{32}(?:-\d)?`), []string{"dapi"}, "data"),
		r("snowflake-credentials", "Snowflake password in connection URL", "high",
			`(?i)snowflake://[^:/\s]+:([^@/\s]{6,})@`, []string{"snowflake://"}, "data"),
		withEntropy(r("datadog-key", "Datadog API or application key", "high",
			semi([]string{`datadog(?:_?(?:api|app(?:lication)?))?_?key`, `dd_?(?:api|app)_?key`}, `[a-f0-9]{32}|[a-f0-9]{40}`, false),
			[]string{"datadog", "dd_api", "dd_app", "ddapi", "ddapp"}, "observability"), 3.0),
		r("grafana-cloud-api-token", "Grafana Cloud API token", "high", tok(`glc_[A-Za-z0-9+/]{32,400}={0,2}`), []string{"glc_"}, "observability"),
		r("grafana-service-account-token", "Grafana service account token", "high",
			tok(`glsa_[A-Za-z0-9]{32}_[A-Fa-f0-9]{8}`), []string{"glsa_"}, "observability"),
		r("grafana-api-key", "Grafana API key (legacy)", "high", tok(`eyJrIjoi[A-Za-z0-9]{70,400}={0,2}`), []string{"eyjrijoi"}, "observability"),
		r("new-relic-key", "New Relic user/ingest key", "high",
			`(?i)\b(NR(?:AK|II|JS)-[A-Z0-9_-]{27,32})(?:[^0-9A-Za-z_-]|$)`, []string{"nrak-", "nrii-", "nrjs-"}, "observability"),
		r("sentry-token", "Sentry auth token", "high", tok(`sntry[su]_[A-Za-z0-9+/=_]{40,}`), []string{"sntrys_", "sntryu_"}, "observability"),
		r("splunk-hec-token", "Splunk HTTP Event Collector token", "medium",
			semi([]string{`splunk(?:_?hec)?_?token`, `hec_?token`}, uuid, false), []string{"splunk", "hec_token", "hectoken"}, "observability"),
		r("pagerduty-token", "PagerDuty API token", "medium",
			semi([]string{`pagerduty(?:_?api)?_?(?:token|key)`, `pd_?token`}, `[A-Za-z0-9_+-]{20}`, false), []string{"pagerduty", "pd_token", "pdtoken"}, "observability"),
		r("honeycomb-api-key", "Honeycomb API key", "medium",
			semi([]string{`honeycomb(?:_?api)?_?key`, `x-honeycomb-team`}, `hc[a-z]{2}_[a-z0-9]{58}|[A-Za-z0-9]{22,32}`, false), []string{"honeycomb"}, "observability"),

		// --- Messaging / collaboration -----------------------------------
		r("slack-bot-token", "Slack bot token", "high", tok(`xoxb-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*`), []string{"xoxb-"}, "slack", "chat"),
		r("slack-user-token", "Slack user token", "high",
			tok(`xox[pe](?:-[0-9]{10,13}){3}-[a-zA-Z0-9-]{28,34}`), []string{"xoxp-", "xoxe-"}, "slack", "chat"),
		r("slack-app-token", "Slack app-level token", "high", `(?i)\b(xapp-\d-[A-Z0-9]+-\d+-[a-z0-9]+)`, []string{"xapp-"}, "slack", "chat"),
		r("slack-config-token", "Slack configuration or refresh token", "high",
			tok(`xoxe\.xox[bp]-\d-[A-Z0-9]{163,166}|xoxe-\d-[A-Z0-9]{146}`), []string{"xoxe"}, "slack", "chat"),
		r("slack-legacy-token", "Slack legacy token", "high", tok(`xox[os]-\d+-\d+-\d+-[a-fA-F\d]+`), []string{"xoxo-", "xoxs-"}, "slack", "chat"),
		r("slack-webhook-url", "Slack webhook URL", "medium",
			`((?:https?://)?hooks\.slack\.com/(?:services|workflows|triggers)/[A-Za-z0-9+/]{43,56})`, []string{"hooks.slack.com"}, "slack", "webhook"),
		r("discord-webhook-url", "Discord webhook URL", "medium",
			`(https://(?:ptb\.|canary\.)?discord(?:app)?\.com/api/webhooks/\d+/[\w-]{60,})`, []string{"discord"}, "webhook", "chat"),
		r("discord-bot-token", "Discord bot token", "high",
			semi([]string{`discord(?:_?bot)?_?token`}, `[MN][A-Za-z\d]{23,25}\.[\w-]{6}\.[\w-]{27,38}`, false), []string{"discord"}, "chat"),
		r("telegram-bot-token", "Telegram bot token", "high", tok(`\d{8,10}:AA[0-9A-Za-z_-]{33}`), []string{":aa"}, "chat"),
		withEntropy(r("twilio-api-key", "Twilio API key SID", "high", tok(`SK[0-9a-fA-F]{32}`), []string{"sk"}, "comms"), 3.0),
		r("twilio-auth-token", "Twilio auth token", "high", semi([]string{`twilio(?:_?auth)?_?token`}, `[a-f0-9]{32}`, false), []string{"twilio"}, "comms"),
		r("sendgrid-api-key", "SendGrid API key", "high", tok(`SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}`), []string{"sg."}, "comms"),
		r("mailgun-api-key", "Mailgun API key", "high", semi([]string{`mailgun(?:_?api)?_?key`}, `(?:key-)?[a-f0-9]{32}|[a-f0-9]{32}-[a-f0-9]{8}-[a-f0-9]{8}`, false), []string{"mailgun"}, "comms"),
		r("mailchimp-api-key", "Mailchimp API key", "high", tok(`[0-9a-f]{32}-us\d{1,2}`), []string{"-us"}, "comms"),
		r("postmark-server-token", "Postmark server token", "medium", semi([]string{`postmark(?:_?(?:server|api))?_?token`}, uuid, false), []string{"postmark"}, "comms"),
		r("linear-api-key", "Linear API key", "high", tok(`lin_api_[A-Za-z0-9]{40}`), []string{"lin_api_"}, "productivity"),
		r("notion-token", "Notion integration token", "high", tok(`ntn_[0-9]{11}[A-Za-z0-9]{35}`), []string{"ntn_"}, "productivity"),
		r("postman-api-key", "Postman API key", "high", `(?i)\b(PMAK-[a-f0-9]{24}-[a-f0-9]{34})(?:[^0-9A-Za-z_-]|$)`, []string{"pmak-"}, "productivity"),
		r("okta-api-token", "Okta API token", "high", semi([]string{`okta(?:_?api)?_?token`, `okta`}, `00[\w=-]{40}`, false), []string{"okta"}, "identity"),

		// --- Payments / commerce ------------------------------------------
		r("stripe-key", "Stripe secret or restricted key", "critical", tok(`(?:sk|rk)_(?:test|live|prod)_[a-zA-Z0-9]{10,99}`), []string{"sk_", "rk_"}, "payments"),
		r("stripe-webhook-secret", "Stripe webhook signing secret", "high", tok(`whsec_[a-zA-Z0-9]{32,}`), []string{"whsec_"}, "payments"),
		r("square-token", "Square access token or OAuth secret", "high", tok(`(?:EAAA|sq0atp-|sq0csp-)[0-9A-Za-z_-]{22,60}`), []string{"eaaa", "sq0atp-", "sq0csp-"}, "payments"),
		r("paypal-braintree-token", "PayPal Braintree access token", "critical",
			tok(`access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}`), []string{"access_token$production$"}, "payments"),
		r("shopify-token", "Shopify access token / shared secret", "high", tok(`shp(?:at|ss|ca|pa)_[a-fA-F0-9]{32}`), []string{"shpat_", "shpss_", "shpca_", "shppa_"}, "commerce"),
		r("facebook-access-token", "Facebook / Meta access token", "medium", tok(`EAA[MC][A-Za-z0-9]{100,}`), []string{"eaam", "eaac"}, "social"),
		r("mapbox-secret-token", "Mapbox secret token", "high", tok(`sk\.eyJ[A-Za-z0-9_-]{50,}\.[A-Za-z0-9_-]{20,}`), []string{"sk.eyj"}, "maps"),
		r("algolia-admin-key", "Algolia admin API key", "high", semi([]string{`algolia(?:_?admin)?(?:_?api)?_?key`}, `[a-f0-9]{32}`, false), []string{"algolia"}, "search"),

		// --- Keys, certificates, tokens -----------------------------------
		r("private-key", "Private key (PEM / PGP / OpenSSH)", "critical",
			`(?i)(-----BEGIN[ A-Z0-9_-]{0,100}PRIVATE KEY(?: BLOCK)?-----[\s\S-]{64,}?-----END[ A-Z0-9_-]{0,100}PRIVATE KEY(?: BLOCK)?-----)`,
			[]string{"-----begin"}, "key"),
		r("putty-private-key", "PuTTY private key", "critical", `(PuTTY-User-Key-File-[23]: [\w-]+)`, []string{"putty-user-key-file"}, "key"),
		r("age-secret-key", "age encryption secret key", "critical",
			`(AGE-SECRET-KEY-1[QPZRY9X8GF2TVDW0S3JN54KHCE6MUA7L]{58})`, []string{"age-secret-key-1"}, "key"),
		r("kubeconfig-client-key", "Client private key embedded in kubeconfig", "critical",
			`client-key-data:\s*["']?([A-Za-z0-9+/=]{40,})`, []string{"client-key-data"}, "kubernetes", "key"),
		// HTTP authorization schemes (Authorization / Proxy-Authorization
		// headers, header maps, recorded requests). Basic must decode to
		// printable user:password; Bearer must be token-shaped (see
		// detect/validate.go). Both yield to provider rules on the same span.
		{ID: "http-basic-auth", Description: "HTTP Basic credentials (base64 user:password)", Severity: "high",
			Regex:    `(?i)\bbasic[ \t]+([A-Za-z0-9+/]{4,1000}={0,2})(?:[^A-Za-z0-9+/=_.$%{}<>-]|$)`,
			Keywords: []string{"basic"}, Tags: []string{"credentials", "http-auth"}, Validate: "basic-auth"},
		{ID: "http-bearer-token", Description: "HTTP Bearer token in an authorization header", Severity: "medium",
			Regex:    `(?i)\bbearer[ \t]+([A-Za-z0-9_.~+/-]{16,1000}={0,2})(?:[^A-Za-z0-9_.~+/=$%{}<>-]|$)`,
			Keywords: []string{"bearer"}, Tags: []string{"token", "http-auth"}, Validate: "opaque-token",
			Allowlists: []Allowlist{placeholderValues}},
		r("jwt", "JSON Web Token", "medium", tok(`eyJ[A-Za-z0-9_-]{15,}\.eyJ[A-Za-z0-9_-]{15,}\.[A-Za-z0-9_-]{10,}={0,2}`), []string{"eyj"}, "token"),

		// --- Credentials in URLs / connection strings ---------------------
		{ID: "url-credentials", Description: "Password embedded in a URL (DB, broker, git, HTTP)", Severity: "high",
			Regex:    `\b[a-zA-Z][a-zA-Z0-9+.-]{1,20}://[^:/?#@\s'"\x60]{1,64}:([^@/?#\s'"\x60]{3,128})@[a-zA-Z0-9.-]+`,
			Keywords: []string{"://"}, Tags: []string{"credentials", "url"},
			Allowlists: []Allowlist{
				placeholderValues,
				// Documentation hosts only. Local hosts (localhost, 127.0.0.1, *.local,
				// compose services) are reported, classified as Context "local".
				{Description: "documentation hosts", RegexTarget: "match", Regexes: []string{`(?i)@(?:(?:[\w-]+\.)*(?:example\.(?:com|org|net)|faketld|test|invalid)|host|hostname|myhost|some_?dsn|your[\w.-]*)(?:[:/]|$)`}},
			}},
		r("jdbc-password", "Password in JDBC URL", "high",
			`(?i)jdbc:[a-z0-9]+:[^\s"']*?[;?&]password=([^;&\s"']{4,})`, []string{"jdbc:"}, "credentials"),
		{ID: "connection-string-password", Description: "Password in a key=value connection string", Severity: "medium",
			// Needs connection-string context (server/host/data source/...) on
			// the same line, so code like password = url.password; is ignored.
			Regex:    `(?i)(?:(?:server|data source|host|address|addr|endpoint|hostname|uid|user id|database|initial catalog)\s*=[^\n]{0,200}?(?:^|[;"'\s])(?:password|pwd)\s*=\s*([^;"'\s{}$()]{4,})\s*(?:;|$|["'])|(?:^|[;"'\s])(?:password|pwd)\s*=\s*([^;"'\s{}$()]{4,})\s*;[^\n]{0,200}?(?:server|data source|host|address|database|uid|user id)\s*=)`,
			Keywords: []string{"password", "pwd"}, Tags: []string{"credentials"},
			Allowlists: []Allowlist{placeholderValues}},

		// --- File-name rules (no regex) ------------------------------------
		{ID: "sensitive-file", Description: "File that usually holds credentials or keys", Severity: "medium",
			Path: `(?i)(?:^|/)(?:id_(?:rsa|dsa|ecdsa|ed25519)|\.htpasswd|\.pgpass|\.git-credentials|\.netrc|_netrc|credentials\.(?:json|xml)|shadow|proftpdpasswd|.*\.(?:p12|pfx|jks|keystore|kdbx|ovpn|tfstate|tfstate\.backup|ppk|asc\.key))$|(?:^|/)config/(?:master|credentials/[\w-]+)\.key$|(?:^|/)\.mozilla/firefox/(?:[^/]+/)?(?:logins\.json|key[34]\.db)$`,
			Tags: []string{"file"}},

		// --- Generic (lowest priority, yields to specific rules) ----------
		{ID: "generic-api-key", Description: "Generic API key, token or secret", Severity: "medium", Entropy: 3.5,
			Regex: semi([]string{`access`, `auth`, `(?-i:[Aa]pi|API)`, `credential`, `creds`, `key`, `passw(?:or)?d`, `secret`, `token`},
				`[\w.=!@#%^&*+~?$-]{10,150}|[a-z0-9][a-z0-9+/]{11,}={0,3}`, true),
			Keywords: []string{"access", "api", "auth", "key", "credential", "creds", "passwd", "password", "secret", "token"},
			Tags:     []string{"generic"},
			Allowlists: []Allowlist{{Description: "signature algorithm and auth scheme names", Regexes: []string{`(?i)^(?:AWS4-HMAC-SHA256|GOOG4-RSA-SHA256|HMAC-SHA(?:1|224|256|384|512)|RSA-SHA(?:1|256|512)|ECDSA-SHA256|Bearer|Basic|Digest|Negotiate)$`}},
				{Description: "non-secret shapes", Regexes: []string{
					`^[a-zA-Z_]+(?:\.[a-zA-Z_]+)+$`,   // dotted identifiers
					`^[a-z]+(?:[_-][a-z]+)+$`,         // snake/kebab words
					`^[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+$`, // ENV_VAR_NAMES (must contain _)
					`^(?i:true|false|null|none|nil|undefined)$`,
					`^[0-9.]+$`,
					`^v?\d+\.\d+\.\d+(?:[-+][\w.-]+)?$`, // semver / Go pseudo-versions
					`^\.[A-Za-z][\w.-]*$`,               // dotfile names
					`(?i)^[\w-]+\.(?:json|ya?ml|toml|txt|md|go|py|js|ts|sh|env|ini|conf|cfg|xml|html|lock|log)$`, // file names
				}},
				nameAllowlist, hashedValues,

				{Description: "pagination tokens in docs and API examples", RegexTarget: "line", Regexes: []string{
					`(?i)\b(?:next|previous|prev|continuation)[ _-]?(?:page[ _-]?)?(?:token|marker|cursor)\b["']?\s*[:=]`,
				}},
				{Description: "value read from env/secret store", RegexTarget: "line", Regexes: []string{
					`(?i)(?:getenv|environ\[|process\.env|secretKeyRef|valueFrom|keyvault|\$\(\w+\)|\{\{\s*secrets\.)`,
				}},
			}},
		{ID: "xml-config-secret", Description: "Secret in XML config (<add key=... value=...>, <password>...</password>)", Severity: "medium", Entropy: 3.0,
			// .NET web.config/app.config appSettings, Maven settings.xml, Spring XML.
			Regex:       `(?i)(?:<add\s+(?:key|name)\s*=\s*"[^"]*(?:passw(?:or)?d|pwd|[._-]pass|secret|token|api[_.-]?key|access[_.-]?key|master[_.-]?key|credential|client[_.-]?secret)[^"]*"\s+value\s*=\s*"([^"\s]{8,200})"|<[\w:.-]*(?:passw(?:or)?d|secret|token|apikey|api_key|credential)[\w:.-]*>([^<\s]{8,200})</)`,
			SecretGroup: 0, Keywords: []string{"<add", "password>", "secret>", "token>", "apikey>", "api_key>", "credential>", "credentials>", "passwd>"},
			Tags: []string{"generic", "credentials", "xml"},
			Allowlists: []Allowlist{nameAllowlist, placeholderValues, hashedValues,
				{Description: "placeholders", Regexes: []string{`^\$\(`, `^\$\{`, `^#\{`, `^@`, `^\[\w+\]$`}}}},
		{ID: "password-in-config", Description: "Unquoted password in an env, INI, properties or YAML config", Severity: "low",
			// KEY=value / key: value lines where values are commonly unquoted.
			Regex:    `(?im)^[ \t]*(?:export[ \t]+)?[\w.-]{0,40}?(?:passw(?:or)?d|pwd|passphrase|_pass|\bpass)(?:[_.-]?(?:\d{1,2}|prod|production|dev|stage|staging|test|local))?[ \t]*[=:][ \t]*([^\s'"#;$<{%][^\s'"#;]{3,63})[ \t]*(?:#.*)?$`,
			Keywords: []string{"passw", "pwd", "passphrase", "pass"},
			Path:     `(?i)(?:(?:^|/)\.env(?:\.[\w-]+)?|\.(?:env|ini|cfg|conf|properties|ya?ml|toml)|(?:^|/)(?:\.?[\w-]*rc|config))$`,
			Tags:     []string{"generic", "credentials"},
			Allowlists: []Allowlist{placeholderValues, hashedValues, {Description: "placeholder values", Regexes: []string{
				`(?i)^(?:password|passw0rd|pass|changeme|changeit|secret|example|sample|dummy|test(?:ing)?|default|null|none|nil|undefined|required|optional|true|false|yes|no|on|off|redacted|x{4,}|\*{4,}|\.{4,})$`,
				`^\d+$`, `^[a-zA-Z][a-zA-Z0-9+.-]*://`, `^[./~]`,
			}}}},
		{ID: "php-define-secret", Description: "Secret in a PHP define() (WordPress keys and salts, DB passwords)", Severity: "high",
			Regex:       `(?i)define\(\s*['"]([A-Z0-9_]*(?:PASSWORD|PASS|SECRET|_KEY|SALT|TOKEN)[A-Z0-9_]*)['"]\s*,\s*'([^']{4,200})'\s*\)`,
			SecretGroup: 2, Keywords: []string{"define"}, Tags: []string{"credentials"},
			Allowlists: []Allowlist{placeholderValues, {Description: "WordPress placeholder", Regexes: []string{`(?i)^put your unique phrase here$`, `(?i)^(?:password_here|username_here|database_name_here)$`}}}},
		{ID: "django-secret-key", Description: "Django SECRET_KEY", Severity: "high",
			Regex:    `(?:^|[^\w])SECRET_KEY\s*=\s*['"]([^'"\n]{30,100})['"]`,
			Keywords: []string{"secret_key"}, Tags: []string{"credentials"},
			Allowlists: []Allowlist{placeholderValues, {Description: "insecure dev keys", Regexes: []string{`^django-insecure-`, `(?i)change|dummy|example|placeholder|not-?secret`}}}},
		r("laravel-app-key", "Laravel APP_KEY", "high", `(?:^|\s)APP_KEY\s*=\s*["']?base64:([A-Za-z0-9+/]{40,}={0,2})`, []string{"app_key"}),
		{ID: "xml-password-attribute", Description: "Password in an XML attribute or element (IDE, FTP and DB client configs)", Severity: "medium",
			Regex:    `(?i)(?:\b(?:password|passwd|pwd|pass)\s*=\s*"([^"\s]{4,200})"|<(?:pass|password|passwd)(?:\s[^>]*)?>([^<\s]{4,200})</(?:pass|password|passwd)>)`,
			Keywords: []string{"pass", "pwd"}, Path: `(?i)\.(?:xml|config|conf|xaml|jnlp|plist)$`,
			Tags:       []string{"credentials"},
			Allowlists: []Allowlist{placeholderValues, hashedValues, {Description: "variables", Regexes: []string{`^\$\{`, `^\$\(`, `^#\{`, `^@`, `^\[\w+\]$`, `^%[\w]+%$`}}}},
		{ID: "netrc-password", Description: "Password in a .netrc file", Severity: "high",
			Regex: `(?:^|\s)password\s+(\S{3,})`, Keywords: []string{"password"},
			Path: `(?:^|/)[._]netrc$`, Tags: []string{"credentials"}, Allowlists: []Allowlist{placeholderValues}},
		{ID: "password-assignment", Description: "Hard-coded password literal", Severity: "low",
			// Also: indexers (["password"] = ...), comparisons (== / ===), a
			// literal wrapped in Some(...)/StringValue(...), and passphrases with
			// up to two inner spaces (see weakPasswordNoise).
			Regex: `(?i)[\w.-]{0,30}?(?:passw(?:or)?d|pwd|passphrase|\bpass\b|(?-i:Pass)\b)(?:[ \t\w.-]{0,10})[\s'"]{0,3}\]?\s*(?:={1,3}|:|:=|=>)\s*` +
				`(?:(?:new\s+)?(?:Some|String|StringValue|types\.StringValue|StringCredentialValue|SecretStr|SecureString|Optional\.of)\(\s*)?` +
				`(?:"([^"\s$<{%]{4,64}|[!#&-;=?-z|}~][ !#&-;=?-z|}~]{4,62}[!#&-;=?-z|}~])"|'([^'\s$<{%]{4,64}|[!-#&(-;=?-z|}~][ !-#&(-;=?-z|}~]{4,62}[!-#&(-;=?-z|}~])')`,
			Keywords: []string{"passw", "pwd", "passphrase", "pass"},
			Tags:     []string{"generic", "credentials"},
			Allowlists: []Allowlist{{Description: "placeholder values", Regexes: []string{
				// Exact placeholder words only. "pass123" / "password123" are reported
				// (low confidence) rather than dropped: weak real passwords look the same.
				`(?i)^(?:password|passw0rd|pass|changeme|changeit|secret|example|sample|dummy|test(?:ing)?|default|null|none|undefined|required|optional|redacted|x{4,}|\*{4,}|\.{4,})$`,
				`(?i)^(?:enter|your|my|new|old|confirm)[_ -]?pass`,
				`^[a-zA-Z][a-zA-Z0-9+.-]*://`, // URLs (url-credentials covers passwords in URLs)
				`^[./~]`,                      // file paths
			}}, passwordSettings}},

		// --- Passwords in statements, commands and calls -------------------
		// The surrounding syntax says the value is a password, so word-shaped
		// values are not dropped here; templates and placeholders are.
		{ID: "sql-password", Description: "Password in a SQL user/role statement", Severity: "high",
			Regex: `(?i)\b(?:` +
				`(?:create|alter)\s+(?:user|role|login)\b[^;\n]{0,160}?\bidentified\s+(?:with\s+\S+\s+)?(?:by|as)(?:\s+password)?\s*` + sqlValue +
				`|(?:create|alter)\s+(?:user|role|login)\b[^;\n]{0,160}?\bpassword\s*=?\s*` + sqlQuoted +
				`|grant\b[^;\n]{0,160}?\bto\b[^;\n]{0,80}?\bidentified\s+by(?:\s+password)?\s*` + sqlQuoted +
				`|set\s+password\s*(?:for\s+[^=;\n]{1,80})?=\s*(?:password\s*\(\s*)?` + sqlQuoted + `)`,
			Keywords: []string{"create user", "alter user", "create role", "alter role", "create login", "alter login", "identified", "set password"},
			Tags:     []string{"credentials"},
			Allowlists: []Allowlist{placeholderValues, interpolatedValues, {Description: "SQL keywords and bind parameters", Regexes: []string{
				`(?i)^(?:null|none|values|password|expire|encrypted|unencrypted|by|as|with|login|nologin|valid|default)$`,
			}}}},
		{ID: "env-password-assignment", Description: "Password in an environment assignment (docker -e, compose, ENV, inline env)", Severity: "medium",
			// NAME_PASSWORD=value where NAME is an environment-style identifier:
			// compose list items, docker -e / --env flags, Dockerfile ENV,
			// "PGPASSWORD=... psql" prefixes, .env-like files of any name.
			Regex:       `(?:^|[\s'"(;&|])(?:export\s+|ENV\s+|-e\s*|--env[\s=]|--build-arg[\s=])?["']?(?:(?:[A-Z][A-Z0-9]*_)*[A-Z]{0,6}(?:PASSWORD|PASSWD|PASSPHRASE)|(?:[A-Z][A-Z0-9]*_)+(?:PASS|PWD))(?:_[A-Z0-9]+)*=(?:"([^"\s$<{}()\[\];|&,\x60\\]{3,128})"|'([^'\s$<{}()\[\];|&,\x60\\]{3,128})'|([^\s"'$<{}()\[\];|&,\x60\\#]{3,128}))(?:["'\s;&|]|\\[nr]|$)`,
			SecretGroup: 0, Keywords: []string{"pass", "pwd"},
			Tags:       []string{"generic", "credentials", "password"},
			Allowlists: []Allowlist{nameAllowlist, placeholderValues, hashedValues, placeholderPasswordWords, passwordSettings}},
		{ID: "cli-password-argument", Description: "Password on a command line (curl -u, openssl pass:, sshpass, mysql -p, form posts)", Severity: "high",
			Regex: `(?i)(?:` +
				`\b(?:curl|wget)\b[^\n]{0,300}?\s(?:-u|--user|--proxy-user)(?:\s+|=)["']?[^\s:"'$<{]{1,64}:([^\s"'$<{]{3,128}?)["']?(?:\s|$)` +
				`|\s-(?:pass(?:in|out)?|password|passphrase)\s+["']?pass:([^\s"'$<{]{3,128})` +
				`|\bsshpass\s+-p\s*["']?([^\s"'$<{-][^\s"']{2,127})` +
				`|\bmysql(?:dump|admin)?\b[^\n]{0,100}?\s-p([^\s"'$<{-][^\s"']{2,63})` +
				`|(?:\s-[dF]\s*["']?|--data(?:-\w+)?[=\s]["']?|[?&])(?:\w*_)?(?:password|passwd|pwd|pass)=([^&\s"'$<{}%#()]{3,128})(?:[&\s"']|$))`,
			Keywords: []string{"curl", "wget", "pass:", "sshpass", "mysql", "password=", "passwd=", "pwd=", "pass="},
			Tags:     []string{"credentials", "password"},
			Allowlists: []Allowlist{placeholderValues, hashedValues, placeholderPasswordWords,
				{Description: "env and shell substitutions", Regexes: []string{`^env:`, `^file:`, `^stdin$`, `^fd:`}}}},
		{ID: "password-call", Description: "Password passed to a setter or credential constructor", Severity: "medium",
			// setPassword("..."), SetBasicAuth("user", "..."), new NetworkCredential("user", "..."),
			// HTTPBasicAuth('user', '...'), auth=("user", "...").
			Regex: `(?i)(?:` +
				`\b(?:set|with)_?(?:key_?|store_?|trust_?store_?|key_?store_?|db_?|database_?|proxy_?|admin_?|user_?)?(?:password|passwd|passphrase)\s*\(\s*(?:new\s+String\(\s*)?["'\x60]([^"'\x60\s$<{%]{4,128})["'\x60]\s*\)` +
				`|\b(?:\w*basic_?auth|networkcredential|gitcredential|usernamepassword\w*|passwordauthentication|passwordcredential|auth)\s*=?\s*[\(\[]\s*["'][^"'\n]{1,64}["']\s*,\s*["']([^"'\s$<{%]{3,128})["'])`,
			Keywords:   []string{"password", "passwd", "passphrase", "auth", "credential"},
			Tags:       []string{"credentials", "password"},
			Allowlists: []Allowlist{placeholderValues, hashedValues, placeholderPasswordWords}},
		{ID: "token-setter", Description: "Token or API key passed to a setter (SetAuthToken, withToken, setApiKey)", Severity: "medium",
			Regex:    `(?i)\b(?:set|with|use)_?(?:auth_?|bearer_?|access_?|api_?|oauth_?|client_?|refresh_?|private_?)?(?:token|secret|api_?key|access_?key)\s*\(\s*["'\x60]([A-Za-z0-9_.~+/=-]{16,512})["'\x60]\s*[,)]`,
			Keywords: []string{"token", "secret", "apikey", "api_key", "accesskey", "access_key"},
			Tags:     []string{"token", "http-auth"}, Validate: "opaque-token",
			Allowlists: []Allowlist{placeholderValues}},
	}
	return rules
}

// sqlValue is a SQL password literal: quoted (optionally backslash-escaped
// inside a shell string) or a bare Oracle-style word. Bind parameters and
// variables (:pw, ?, $1, @pw) never qualify. A bare Oracle password follows
// identifier rules and starts with a letter (unquoted IDENTIFIED BY 12345 is
// a template value in generated SQL, not a usable password).
const (
	sqlQuoted = `(?:\\?'([^'\\\n]{3,128})\\?'|\\?"([^"\\\n]{3,128})\\?")`
	sqlValue  = `(?:` + sqlQuoted + `|([A-Za-z][^\s'";\\,)]{2,63}))`
)

// interpolatedValues are values spliced in at runtime: string concatenation
// ('` + pw + `'), PHP/Ruby/template interpolation, %%TOKENS%%.
var interpolatedValues = Allowlist{Description: "interpolated values", Regexes: []string{
	"\x60", `^\s*\+|\+\s*$`, `^%%\w+%%$`, `^\{\$[\w>-]+\}$`, `^\$\w+$`, `^#\{`, `^\{\{`,
}}

// passwordSettings drops values of keys that configure passwords rather
// than hold one (password_charset = 'UTF-8', PASSWORD_SCHEME=SHA512-CRYPT).
var passwordSettings = Allowlist{Description: "password settings, not passwords", RegexTarget: "prefix", Regexes: []string{
	`(?i)(?:passw(?:or)?d|pass|pwd|passphrase)[_.-]?(?:scheme|charset|encoding|algorithm|algo|hash\w*|type|mode|policy|length|min\w*|max\w*|file|path|env|var|rounds)\w*["'\x60\]\s]*(?:={1,3}|:|:=|=>)\s*["']?$`,
}}

// placeholderPasswordWords are config words and placeholders that are not
// passwords when they appear as one (yes, none, changeme, ****).
var placeholderPasswordWords = Allowlist{Description: "placeholder values", Regexes: []string{
	`(?i)^(?:password|passw0rd|pass|changeme|changeit|secret|example|sample|dummy|test(?:ing)?|default|null|none|nil|undefined|required|optional|true|false|yes|no|on|off|redacted|x{4,}|\*{4,}|\.{4,})$`,
	`^\d{1,3}$`, `^[a-zA-Z][a-zA-Z0-9+.-]*://`, `^[./~]`,
}}

// GenericStopwords are substrings of common non-secret values. The detector
// applies them only to word-like values (see detect.genericNoise), so a
// random token that happens to contain "secret" or "token" is kept.
var GenericStopwords = genericStopwords

var genericStopwords = []string{
	"abcdef", "123456", "000000", "password", "passw0rd", "secret", "token", "apikey", "api_key", "bearer",
	"changeit", "default", "localhost", "function", "return", "string", "public", "private", "config",
	"variable", "example", "sample", "dummy", "placeholder", "test1234", "testtest", "hunter2", "lorem",
	"foobar", "redacted", "masked", "notset", "unset", "required", "optional", "enabled", "disabled",
	"keyword", "keyring", "keychain", "keystore", "keyvault", "keypair", "keyboard", "author", "accessor",
	"authority", "authorize", "credential", "tokenizer", "_field", "_name", "_type", "_path", "_url", "_file",
	"aaaaaa", "xxxxxx", "******",
}

// DefaultAllowlists are global allowlists shipped with the default pack.
func DefaultAllowlists() []Allowlist {
	// Suppressions are deliberately narrow:
	//   - only content we cannot meaningfully scan (binaries, media, vendored
	//     third-party trees) is skipped for every rule;
	//   - lockfiles, scanner configs and placeholder-looking values are only
	//     exempt from noisy generic rules, so a structured provider token or a
	//     credential in a registry URL inside them is still reported.
	return []Allowlist{
		{Description: "binary and media files, vendored third-party trees", Paths: []string{
			`(?i)\.(?:png|jpe?g|gif|bmp|ico|webp|tiff?|svg|woff2?|ttf|otf|eot|pdf|zip|gz|tgz|bz2|xz|7z|rar|jar|war|ear|class|exe|dll|so|dylib|a|o|bin|dat|mp[34]|mov|avi|wav|flac|ogg|pyc|whl|egg|wasm|DS_Store)$`,
			`(?:^|/)(?:node_modules|\.git|\.venv|__pycache__|\.terraform/providers)/`,
			`(?:^|/)(?:gradlew|mvnw)(?:\.bat|\.cmd)?$`,
		}},
		{Description: "lockfiles and package metadata (generic rules only)", TargetTags: []string{"generic"}, Paths: []string{
			`(?:^|/)(?:go\.sum|go\.work\.sum|package-lock\.json|npm-shrinkwrap\.json|yarn\.lock|pnpm-lock\.yaml|bun\.lockb|poetry\.lock|Pipfile\.lock|uv\.lock|Cargo\.lock|composer\.lock|Gemfile\.lock|gradle\.lockfile|packages\.lock\.json|MODULE\.bazel\.lock)$`,
			`(?:^|/)[\w.+-]+\.dist-info/(?:RECORD|METADATA|WHEEL)$`,
			`(?:^|/)vendor/modules\.txt$`,
		}},
		{Description: "scanner config and ignore files (generic and custom-rule self-tests only)", TargetTags: []string{"generic", "custom"}, Paths: []string{
			`(?:^|/)(?:\.?secretscan\.toml|\.gitleaks\.toml|gitleaks\.toml|\.secretscanignore|\.gitleaksignore|\.secrets\.baseline)$`,
		}},
		{Description: "placeholders and templated values (generic and credential rules only)", TargetTags: []string{"generic", "credentials"}, Regexes: []string{
			`^\$\{[^}]*\}$`, `^\$\([^)]*\)$`, `^\{\{.*\}\}$`, `^<[^>]+>$`, `^%[A-Za-z_]+%$`, `^\$[A-Z_][A-Z0-9_]*$`,
			`^\{[A-Za-z_][\w.]*\}$`, `^%\(\w+\)s$`, `^@[A-Za-z_]\w*@$`, `^#\{[^}]+\}$`,
			`^[*xX#•.]+$`,
			`(?i)^(?:your|my|insert|replace|enter|put)[_-]?(?:own[_-]?|real[_-]?|actual[_-]?)?(?:api[_-]?|access[_-]?|secret[_-]?)?(?:key|token|secret|password|pass|value|here)`,
			`(?i)(?:example|sample|dummy|placeholder|changeme|redacted|notreal|not_a_real|fake_?(?:key|token|secret))`,
		}},
	}
}

// Default returns the built-in config.
func Default() *Config {
	return &Config{Title: "secretscan default rules", Rules: DefaultRules(), Allowlists: DefaultAllowlists()}
}

// nameAllowlist drops values whose identifier says they aren't secrets
// (ids, names, URLs, pagination/verification tokens, hashes, ...). It is
// evaluated against the match text before the secret ("prefix").
var nameAllowlist = Allowlist{Description: "names that hold identifiers, not secrets", RegexTarget: "prefix", Regexes: []string{
	`(?i)(?:name|ids?|arn|ur[il]|path|type|mode|version|region|endpoint|header|label|format|prefix|suffix|count|length|size|marker|class|kind|enabled|required|field)["'\x60]?\s*(?:=|:|=>|,|\?=)?\s*["'\x60]?$`,
	`(?i)(?:next|previous|prev|continuation|pagination|page|sync|resume|cursor|verification|idempotency|request|client)[ _.-]?(?:page[ _.-]?)?(?:token|marker|key|cursor)`,
	`(?i)(?:^|[^a-z])(?:pub(?:lic)?|primary|foreign|sort|partition|cache|idempotency|dedup(?:e|lication)?|bucket|object|sequence|natural|schema)[_.-]?keys?(?:[^a-z]|$)`,
	`(?i)(?:^|[^a-z])keys?[_.-]?(?:ids?|name|alias|path|file|size|length|type|usage|pair|ring|code|board|word|frame|spec|hash|version|format|prefix|count|fingerprint|vault[_.-]?(?:id|name|uri|url))(?:[^a-z]|$)`,
	`(?i)(?:^|[^a-z])tokens?[_.-]?(?:url|uri|endpoint|type|ttl|expir\w*|count|limit|file|path|name|header|prefix|kind|usage)(?:[^a-z]|$)`,
	`(?i)(?:^|[^a-z])(?:secret|password|passwd)[_.-]?(?:name|ref|keyref|path|file|length|policy|hint|field|label|prompt|reset\w*|min\w*|max\w*|regex|pattern|rules?|strength|expir\w*)(?:[^a-z]|$)`,
	`(?i)(?:^|[^a-z])(?:auth(?:or(?:ity|ization)?)?|access)[_.-]?(?:url|uri|type|method|mode|header|provider|domain|scheme|level|log|control|pattern|rights?|policy|scope|group)(?:[^a-z]|$)`,
	`(?i)(?:^|[^a-z])api[_.-]?(?:version|url|uri|base|host|path|name|group|id|endpoint|spec|docs?)(?:[^a-z]|$)`,
	`(?i)(?:(?:vault|kv|ssm|parameter|keyvault)[_.-]?(?:key|path|name|ref|id)|secret[_.-]?(?:path|name|ref|id|arn))["'\x60]?\s*(?:=|:|=>|,)?\s*["'\x60]?$`, // references to stored secrets
	`(?i)(?:^|[^a-z])(?:sha(?:1|224|256|384|512)|md5|checksum|digest|integrity|etag|nonce|salt|iv)(?:[^a-z]|$)`,
}}

// placeholderValues are documentation/template values for password-like fields.
var placeholderValues = Allowlist{Description: "placeholder and documentation passwords", Regexes: []string{
	`(?i)^(?:pass(?:word)?|passwd|pwd|secret|pw|test|admin|user(?:name)?|guest|root|xxx+|\*+|token|apikey|my%20pass|tiger|scott|hunter2|changeme|example|sample|dummy|foobar|foo|bar|pass%\w+|whatever|mypassword|yourpassword)$`,
	`^\{[A-Za-z_][\w.]*\}$`, `^%\(\w+\)s$`, `^\$\{?[A-Za-z_]\w*\}?$`, `^<[^>]+>$`, `^\(.*\)$`, `^\[[^\]]+\]$`,
}}

// hashedValues are password hashes (bcrypt, sha-crypt, argon2, pbkdf2), not plaintext secrets.
var hashedValues = Allowlist{Description: "password hashes", Regexes: []string{
	`^\$(?:2[abxy]?|5|6|y|7|argon2(?:id|i|d)?|pbkdf2[\w-]*|scrypt|sha1|md5)\$`,
	`^(?:pbkdf2_sha256|bcrypt_sha256|argon2)\$`,
}}
