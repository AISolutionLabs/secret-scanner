// SPDX-License-Identifier: Apache-2.0

package detect_test

import (
	"encoding/base64"
	"fmt"
	"math/rand"
	"strings"
	"testing"

	"github.com/AISolutionLabs/secret-scanner/internal/config"
	"github.com/AISolutionLabs/secret-scanner/internal/detect"
)

// Samples are generated at runtime so this repository never contains
// realistic-looking tokens (which would trip push protection elsewhere).
var rng = rand.New(rand.NewSource(42))

const (
	alnum   = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
	upAlnum = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	lowAln  = "abcdefghijklmnopqrstuvwxyz0123456789"
	hexs    = "0123456789abcdef"
	b32u    = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
	b32l    = "abcdefghijklmnopqrstuvwxyz234567"
	letters = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
	digits  = "0123456789"
	bech32  = "QPZRY9X8GF2TVDW0S3JN54KHCE6MUA7L"
)

func g(cs string, n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = cs[rng.Intn(len(cs))]
	}
	return string(b)
}

// rng2 feeds samples and tests added after the statistical tests were
// calibrated, so adding a rule does not reshuffle the values those tests
// draw from rng (their thresholds are per-sample, not per-seed).
var rng2 = rand.New(rand.NewSource(4242))

func g2(cs string, n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = cs[rng2.Intn(len(cs))]
	}
	return string(b)
}

func uuid() string {
	return g(hexs, 8) + "-" + g(hexs, 4) + "-" + g(hexs, 4) + "-" + g(hexs, 4) + "-" + g(hexs, 12)
}

type sample struct {
	text string
	path string
}

func samples() map[string]sample {
	s := func(t string) sample { return sample{text: t} }
	pemBody := ""
	for i := 0; i < 4; i++ {
		pemBody += g(alnum, 64) + "\n"
	}
	return map[string]sample{
		"aws-access-key-id":                {text: "aws_key = AKIA" + g(b32u, 16)},
		"aws-access-key-id-sigv4":          s("Authorization: AWS4-HMAC-SHA256 Credential=AKIA" + g(b32u, 16) + "/20260101/us-east-1/s3/aws4_request"),
		"aws-secret-access-key":            s("AWS_SECRET_ACCESS_KEY=" + g(alnum+"/+", 40)),
		"aws-session-token":                s("aws_session_token = " + g(alnum+"/+", 120)),
		"aws-bedrock-api-key":              s("key: ABSKQmVkcm9ja0FQSUtleS" + g(alnum, 60)),
		"azure-ad-client-secret":           s(`client_secret = "abc8Q~` + g(alnum, 32) + `"`),
		"azure-storage-connection-string":  s("DefaultEndpointsProtocol=https;AccountName=acct;AccountKey=" + g(alnum, 86) + "==;EndpointSuffix=core.windows.net"),
		"azure-storage-account-key":        s(`storage_account_key = "` + g(alnum, 86) + `=="`),
		"azure-sas-token":                  s("https://acct.blob.core.windows.net/c?sv=2022-11-02&ss=b&sig=" + g(alnum, 44) + "%3D"),
		"azure-devops-pat":                 s("PAT=" + g(alnum, 76) + "AZDO" + g(alnum, 4)),
		"azure-devops-pat-legacy":          s("AZURE_DEVOPS_PAT=" + g(b32l, 52)),
		"azure-openai-key":                 s("AZURE_OPENAI_API_KEY=" + g(hexs, 32)),
		"azure-apim-subscription-key":      s("Ocp-Apim-Subscription-Key: " + g(hexs, 32)),
		"teams-webhook":                    s("https://contoso.webhook.office.com/webhookb2/" + uuid() + "@" + uuid() + "/IncomingWebhook/" + g(hexs, 32) + "/" + uuid()),
		"power-automate-webhook":           s("https://prod-12.westeurope.logic.azure.com:443/workflows/" + g(hexs, 32) + "/triggers/manual/paths/invoke?api-version=2016-06-01&sv=1.0&sig=" + g(alnum, 43)),
		"gcp-api-key":                      s("key=AIza" + g(alnum, 35)),
		"gcp-service-account-key":          s(`"private_key_id": "` + g(hexs, 40) + `"`),
		"gcp-oauth-client-secret":          s("GOCSPX-" + g(alnum, 28)),
		"gcp-oauth-access-token":           s("Authorization: Bearer ya29." + g(alnum, 60)),
		"firebase-fcm-server-key":          s("AAAA" + g(alnum, 7) + ":" + g(alnum, 140)),
		"digitalocean-token":               s("dop_v1_" + g(hexs, 64)),
		"heroku-api-key":                   s("HRKU-AA" + g(alnum, 58)),
		"heroku-api-key-legacy":            s("HEROKU_API_KEY=" + uuid()),
		"cloudflare-api-token":             s("CLOUDFLARE_API_TOKEN=" + g(alnum, 40)),
		"alibaba-access-key-id":            s("LTAI" + g(alnum, 20)),
		"ibm-cloud-api-key":                s("IBM_CLOUD_API_KEY=" + g(alnum, 44)),
		"oracle-oci-key-fingerprint":       s("oci_cli_fingerprint = " + strings.TrimSuffix(strings.Repeat(g(hexs, 2)+":", 16), ":")),
		"github-pat":                       s("token: ghp_" + g(alnum, 36)),
		"github-fine-grained-pat":          s("github_pat_" + g(alnum, 82)),
		"github-oauth":                     s("gho_" + g(alnum, 36)),
		"github-app-token":                 s("ghs_" + g(alnum, 36)),
		"github-refresh-token":             s("ghr_" + g(alnum, 36)),
		"gitlab-pat":                       s("glpat-" + g(alnum, 20)),
		"gitlab-pipeline-trigger-token":    s("glptt-" + g(hexs, 40)),
		"gitlab-runner-registration-token": s("GR1348941" + g(alnum, 20)),
		"gitlab-runner-token":              s("glrt-" + g(alnum, 20)),
		"gitlab-deploy-token":              s("gldt-" + g(alnum, 20)),
		"gitlab-oauth-app-secret":          s("gloas-" + g(alnum, 64)),
		"bitbucket-app-password":           s("ATBB" + g(alnum, 32)),
		"atlassian-api-token":              s("ATATT3" + g(alnum, 186)),
		"atlassian-api-token-legacy":       s("JIRA_API_TOKEN=" + g(alnum, 24)),
		"circleci-token":                   s("CIRCLECI_TOKEN=" + g(hexs, 40)),
		"sonarqube-token":                  s("squ_" + g(hexs, 40)),
		"snyk-token":                       s("SNYK_TOKEN=" + uuid()),
		"terraform-cloud-token":            s(g(lowAln, 14) + ".atlasv1." + g(lowAln, 64)),
		"pulumi-access-token":              s("pul-" + g(hexs, 40)),
		"doppler-token":                    s("dp.pt." + g(lowAln, 43)),
		"vault-token":                      s("hvs." + g(alnum, 95)),
		"vault-token-legacy":               s("VAULT_TOKEN=s." + g(alnum, 24)),
		"octopus-deploy-api-key":           s("API-" + g(upAlnum, 26)),
		"npm-access-token":                 s("npm_" + g(alnum, 36)),
		"npmrc-auth":                       s("//registry.npmjs.org/:_authToken=" + g(alnum, 36)),
		"pypi-upload-token":                s("pypi-AgEIcHlwaS5vcmc" + g(alnum, 60)),
		"nuget-api-key":                    s("oy2" + g(lowAln, 43)),
		"rubygems-api-key":                 s("rubygems_" + g(hexs, 48)),
		"docker-hub-pat":                   s("dckr_pat_" + g(alnum, 27)),
		"docker-config-auth":               {text: `{"auths":{"r.example.io":{"auth":"` + base64.StdEncoding.EncodeToString([]byte("deploy:"+g(alnum, 20))) + `"}}}`, path: "home/.docker/config.json"},
		"jfrog-api-key":                    s("AKCp" + g(alnum, 69)),
		"jfrog-identity-token":             s("cmVmd" + g(alnum, 59)),
		"hex-api-key":                      s("HEX_API_KEY=" + g(hexs, 32)),
		"openai-api-key":                   s("OPENAI_API_KEY=sk-proj-" + g(alnum, 40) + "T3BlbkFJ" + g(alnum, 40)),
		"anthropic-api-key":                s("sk-ant-api03-" + g(alnum, 93) + "AA"),
		"litellm-key":                      s("LITELLM_MASTER_KEY=sk-" + g(alnum, 24)),
		"huggingface-token":                s("hf_" + g(letters, 34)),
		"groq-api-key":                     s("gsk_" + g(alnum, 52)),
		"xai-api-key":                      s("xai-" + g(alnum, 80)),
		"perplexity-api-key":               s("pplx-" + g(alnum, 48)),
		"replicate-api-token":              s("r8_" + g(alnum, 37)),
		"langsmith-api-key":                s("lsv2_pt_" + g(hexs, 32) + "_" + g(hexs, 10)),
		"cohere-api-key":                   s("COHERE_API_KEY=" + g(alnum, 40)),
		"mistral-api-key":                  s("MISTRAL_API_KEY=" + g(alnum, 32)),
		"deepseek-api-key":                 s("DEEPSEEK_API_KEY=sk-" + g(hexs, 32)),
		"pinecone-api-key":                 s("PINECONE_API_KEY=pcsk_" + g(alnum, 60)),
		"databricks-token":                 s("dapi" + g(hexs, 32)),
		"snowflake-credentials":            s("snowflake://svc_user:" + g(alnum, 16) + "@acct/db"),
		"datadog-key":                      s("DD_API_KEY=" + g(hexs, 32)),
		"grafana-cloud-api-token":          s("glc_" + g(alnum, 60)),
		"grafana-service-account-token":    s("glsa_" + g(alnum, 32) + "_" + g(hexs, 8)),
		"grafana-api-key":                  s("eyJrIjoi" + g(alnum, 80)),
		"new-relic-key":                    s("NRAK-" + g(upAlnum, 27)),
		"sentry-token":                     s("sntrys_" + g(alnum, 60)),
		"splunk-hec-token":                 s("SPLUNK_HEC_TOKEN=" + uuid()),
		"pagerduty-token":                  s("PAGERDUTY_API_TOKEN=" + g(alnum, 20)),
		"honeycomb-api-key":                s("HONEYCOMB_API_KEY=" + g(alnum, 32)),
		"slack-bot-token":                  s("xoxb-" + g(digits, 12) + "-" + g(digits, 12) + "-" + g(alnum, 24)),
		"slack-user-token":                 s("xoxp-" + g(digits, 12) + "-" + g(digits, 12) + "-" + g(digits, 12) + "-" + g(hexs, 32)),
		"slack-app-token":                  s("xapp-1-A" + g(upAlnum, 10) + "-" + g(digits, 12) + "-" + g(hexs, 64)),
		"slack-config-token":               s("xoxe.xoxp-1-" + g(upAlnum, 164)),
		"slack-legacy-token":               s("xoxs-1234-5678-9012-" + g(hexs, 20)),
		"slack-webhook-url":                s("https://hooks.slack.com/services/T" + g(upAlnum, 8) + "/B" + g(upAlnum, 8) + "/" + g(alnum, 24)),
		"discord-webhook-url":              s("https://discord.com/api/webhooks/" + g(digits, 18) + "/" + g(alnum, 68)),
		"discord-bot-token":                s("DISCORD_BOT_TOKEN=M" + g(alnum, 24) + "." + g(alnum, 6) + "." + g(alnum, 30)),
		"telegram-bot-token":               s("bot " + g(digits, 10) + ":AA" + g(alnum, 33)),
		"twilio-api-key":                   s("SK" + g(hexs, 32)),
		"twilio-auth-token":                s("TWILIO_AUTH_TOKEN=" + g(hexs, 32)),
		"sendgrid-api-key":                 s("SG." + g(alnum, 22) + "." + g(alnum, 43)),
		"mailgun-api-key":                  s("MAILGUN_API_KEY=key-" + g(hexs, 32)),
		"mailchimp-api-key":                s(g(hexs, 32) + "-us12"),
		"postmark-server-token":            s("POSTMARK_SERVER_TOKEN=" + uuid()),
		"linear-api-key":                   s("lin_api_" + g(alnum, 40)),
		"notion-token":                     s("ntn_" + g(digits, 11) + g(alnum, 35)),
		"postman-api-key":                  s("PMAK-" + g(hexs, 24) + "-" + g(hexs, 34)),
		"okta-api-token":                   s("OKTA_API_TOKEN=00" + g(alnum, 40)),
		"stripe-key":                       s("sk_live_" + g(alnum, 24)),
		"stripe-webhook-secret":            s("whsec_" + g(alnum, 32)),
		"square-token":                     s("sq0atp-" + g(alnum, 22)),
		"paypal-braintree-token":           s("access_token$production$" + g(lowAln, 16) + "$" + g(hexs, 32)),
		"shopify-token":                    s("shpat_" + g(hexs, 32)),
		"facebook-access-token":            s("EAAC" + g(alnum, 120)),
		"mapbox-secret-token":              s("sk.eyJ" + g(alnum, 60) + "." + g(alnum, 22)),
		"algolia-admin-key":                s("ALGOLIA_ADMIN_API_KEY=" + g(hexs, 32)),
		"private-key":                      s("-----BEGIN RSA PRIVATE KEY-----\n" + pemBody + "-----END RSA PRIVATE KEY-----\n"),
		"putty-private-key":                s("PuTTY-User-Key-" + "File-3: ssh-ed25519"),
		"age-secret-key":                   s("AGE-SECRET-KEY-1" + g(bech32, 58)),
		"kubeconfig-client-key":            s("    client-key-data: " + g(alnum, 80)),
		"jwt":                              s("Authorization: Bearer eyJ" + g(alnum, 20) + ".eyJ" + g(alnum, 30) + "." + g(alnum, 30)),
		"http-basic-auth":                  s(`req.Header.Set("Authorization", "Basic ` + base64.StdEncoding.EncodeToString([]byte("svc_"+g2(lowAln, 6)+":"+g2(alnum, 14))) + `")`),
		"http-bearer-token":                s(`curl -H "Authorization: Bearer ` + g2(alnum, 40) + `" https://api.internal/v1`),
		"sql-password":                     s(`CREATE USER 'app'@'%' IDENTIFIED BY '` + g2(alnum, 14) + `';`),
		"env-password-assignment":          s(`docker run -e MYSQL_ROOT_PASSWORD=` + g2(alnum, 14) + ` -d mysql:8`),
		"cli-password-argument":            s(`curl -u deploy:` + g2(alnum, 16) + ` https://ci.internal/api`),
		"password-call":                    s(`req.SetBasicAuth("deploy", "` + g2(alnum, 14) + `")`),
		"token-setter":                     s(`client.SetAuthToken("` + g2(alnum, 40) + `")`),
		"url-credentials":                  s("DATABASE_URL=postgres://admin:" + g(alnum, 16) + "@db.internal:5432/app"),
		"jdbc-password":                    s("jdbc:sqlserver://h:1433;databaseName=x;user=sa;password=" + g(alnum, 14)),
		"connection-string-password":       s("Server=tcp:h,1433;User ID=sa;Password=" + g(alnum, 14) + ";Encrypt=True;"),
		"sensitive-file":                   {text: "anything", path: "keys/id_rsa"},
		"generic-api-key":                  s(`api_secret = "` + g(alnum, 32) + `"`),
		"xml-config-secret":                s(`<add key="StorageToken" value="` + g(alnum, 24) + `" />`),
		"password-assignment":              s(`db_password = "` + "Tr0ub4dor&3" + `"`),
		"password-in-config":               {text: "DB_PASSWORD=" + g(alnum, 14), path: "deploy/.env.production"},
		"php-define-secret":                {text: "define('AUTH_KEY', '" + g(alnum+"!@#%^&*()-_[]{}<>~+=,.;:/?|", 64) + "');", path: "wp-config.php"},
		"django-secret-key":                {text: "SECRET_KEY = '" + g(alnum+"!@#%^&*(-_=+)", 50) + "'", path: "mysite/settings.py"},
		"laravel-app-key":                  {text: "APP_KEY=base64:" + g(alnum+"+/", 43) + "=", path: ".env"},
		"xml-password-attribute":           {text: `<Server Host="ftp.example.org" User="deploy" Password="` + g(alnum, 16) + `"/>`, path: "conf/servers.xml"},
		"netrc-password":                   {text: "machine api.example.org login deploy password " + g(alnum, 20), path: "home/.netrc"},
	}
}

func defaultDetector(t testing.TB, depth int) *detect.Detector {
	t.Helper()
	cfg, _, err := config.Resolve(config.Options{})
	if err != nil {
		t.Fatal(err)
	}
	rs, err := config.Compile(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return detect.New(rs, detect.Options{MaxDecodeDepth: depth})
}

func ids(fs []detect.Finding) []string {
	var out []string
	for _, f := range fs {
		out = append(out, f.RuleID)
	}
	return out
}

func has(fs []detect.Finding, id string) bool {
	for _, f := range fs {
		if f.RuleID == id {
			return true
		}
	}
	return false
}

// Every default rule must have a sample, and every sample must fire its rule.
func TestEveryDefaultRuleDetects(t *testing.T) {
	d := defaultDetector(t, 0)
	smp := samples()
	for _, r := range config.DefaultRules() {
		sm, ok := smp[r.ID]
		if !ok {
			t.Errorf("rule %s has no test sample", r.ID)
			continue
		}
		path := sm.path
		if path == "" {
			path = "src/app.env"
		}
		fs := d.Detect(detect.Fragment{Raw: sm.text, FilePath: path, StartLine: 1})
		if !has(fs, r.ID) {
			t.Errorf("rule %s did not fire on its sample %q; got %v", r.ID, sm.text, ids(fs))
		}
	}
	for id := range smp {
		found := false
		for _, r := range config.DefaultRules() {
			found = found || r.ID == id
		}
		if !found {
			t.Errorf("sample for unknown rule %s", id)
		}
	}
}

func TestNegatives(t *testing.T) {
	d := defaultDetector(t, 2)
	cases := map[string]string{
		"aws docs example":       "aws_access_key_id = AKIAIOSFODNN7EXAMPLE",
		"env reference":          `password = "${DB_PASSWORD}"`,
		"getenv":                 `api_key = os.getenv("API_KEY_FROM_ENVIRONMENT")`,
		"placeholder":            `api_key = "your_api_key_here_1234"`,
		"angle placeholder":      `token: "<GITHUB_TOKEN>"`,
		"masked":                 `secret: "****************"`,
		"helm template":          `password: "{{ .Values.db.password }}"`,
		"k8s secret ref":         `token: {valueFrom: {secretKeyRef: {name: s, key: tok3nValue12345}}}`,
		"dotted identifier":      `auth_provider = "com.company.auth.provider"`,
		"env var name":           `token_env = "GITHUB_TOKEN_FOR_CI"`,
		"url without password":   "https://user@github.com/org/repo.git",
		"url env password":       "postgres://admin:$PGPASSWORD@db/app",
		"plain prose":            "The secret to good code is keeping functions small and tested.",
		"public certificate":     "-----BEGIN CERTIFICATE-----\nMIIBszCCAVmgAwIBAgIUQ\n-----END CERTIFICATE-----",
		"longer than github pat": "ghp_" + strings.Repeat("a1B2", 12),
	}
	for name, text := range cases {
		if fs := d.Detect(detect.Fragment{Raw: text, FilePath: "src/main.go", StartLine: 1}); len(fs) > 0 {
			t.Errorf("%s: unexpected findings %v (%q)", name, ids(fs), fs[0].Secret)
		}
	}
}

func TestInlineIgnoreMarkers(t *testing.T) {
	d := defaultDetector(t, 0)
	pat := "ghp_" + g(alnum, 36)
	for _, text := range []string{
		"token = '" + pat + "' # secretscan:allow",
		"token = '" + pat + "' // gitleaks:allow",
		"token = '" + pat + "'  # pragma: allowlist secret",
		"# secretscan:allow-next-line\ntoken = '" + pat + "'",
	} {
		if fs := d.Detect(detect.Fragment{Raw: text, FilePath: "a.py", StartLine: 1}); len(fs) > 0 {
			t.Errorf("expected inline ignore for %q, got %v", text, ids(fs))
		}
	}
	// Audit mode: markers disabled.
	cfg, _, _ := config.Resolve(config.Options{})
	rs, _ := config.Compile(cfg)
	audit := detect.New(rs, detect.Options{IgnoreMarkers: []string{}})
	if fs := audit.Detect(detect.Fragment{Raw: "t='" + pat + "' # secretscan:allow", FilePath: "a.py"}); !has(fs, "github-pat") {
		t.Error("audit mode should ignore inline markers")
	}
}

func TestPositionsAndFingerprint(t *testing.T) {
	d := defaultDetector(t, 0)
	pat := "ghp_" + g(alnum, 36)
	text := "line1\nline2\n  export GH=" + pat + "\n"
	fs := d.Detect(detect.Fragment{Raw: text, FilePath: "dir/x.sh", StartLine: 10, Commit: "abc123"})
	if len(fs) != 1 {
		t.Fatalf("want 1 finding, got %v", ids(fs))
	}
	f := fs[0]
	if f.StartLine != 12 || f.StartColumn != 13 || f.EndLine != 12 {
		t.Errorf("bad position %d:%d-%d:%d", f.StartLine, f.StartColumn, f.EndLine, f.EndColumn)
	}
	if f.Fingerprint != "abc123:dir/x.sh:github-pat:12" {
		t.Errorf("bad fingerprint %s", f.Fingerprint)
	}
	if f.Secret != pat || len(f.SecretHash) != 64 {
		t.Errorf("bad secret/hash")
	}
}

func TestGenericYieldsToSpecific(t *testing.T) {
	d := defaultDetector(t, 0)
	text := `api_key = "ghp_` + g(alnum, 36) + `"`
	fs := d.Detect(detect.Fragment{Raw: text, FilePath: "a.py"})
	if len(fs) != 1 || fs[0].RuleID != "github-pat" {
		t.Errorf("want only github-pat, got %v", ids(fs))
	}
}

func TestDecoding(t *testing.T) {
	pat := "ghp_" + g(alnum, 36)
	inner := base64.StdEncoding.EncodeToString([]byte("GITHUB_TOKEN=" + pat + "\n"))
	double := base64.StdEncoding.EncodeToString([]byte("config: " + inner))
	hexed := fmt.Sprintf("%x", "token="+pat)

	d := defaultDetector(t, 2)
	for name, text := range map[string]string{
		"base64": "data:\n  creds: " + inner + "\n",
		"double": "blob = " + double,
		"hex":    "payload " + hexed,
	} {
		fs := d.Detect(detect.Fragment{Raw: text, FilePath: "k8s/secret.yaml", StartLine: 1})
		if !has(fs, "github-pat") {
			t.Errorf("%s: expected decoded github-pat, got %v", name, ids(fs))
			continue
		}
		for _, f := range fs {
			if f.RuleID == "github-pat" && (f.Decoded == "" || f.Secret != pat) {
				t.Errorf("%s: decoded=%q secret=%q", name, f.Decoded, f.Secret)
			}
		}
	}
	off := defaultDetector(t, 0)
	if fs := off.Detect(detect.Fragment{Raw: "creds: " + inner, FilePath: "a"}); has(fs, "github-pat") {
		t.Error("decoding should be off at depth 0")
	}
}

func TestEntropyGate(t *testing.T) {
	d := defaultDetector(t, 0)
	if fs := d.Detect(detect.Fragment{Raw: `api_secret = "aaaaaaaaaaaaaaaabbbbbbbb"`, FilePath: "a"}); has(fs, "generic-api-key") {
		t.Error("low-entropy value should not trigger generic rule")
	}
}

func TestRedact(t *testing.T) {
	f := detect.Finding{Secret: "ghp_abcdefghij", Match: "token=ghp_abcdefghij", Line: "x token=ghp_abcdefghij"}
	detect.Redact(&f, 100)
	if strings.Contains(f.Line, "abcdef") || f.Secret != "REDACTED" {
		t.Errorf("full redact failed: %+v", f)
	}
	g := detect.Finding{Secret: "ABCDEFGHIJ"}
	detect.Redact(&g, 70)
	if g.Secret != "ABCREDACTED" {
		t.Errorf("partial redact: %s", g.Secret)
	}
}

func TestIgnoreSetAndBaseline(t *testing.T) {
	f := detect.Finding{RuleID: "github-pat", File: "a.go", StartLine: 3, Fingerprint: "a.go:github-pat:3", SecretHash: "deadbeef"}
	for _, entry := range []string{"a.go:github-pat:3", "sha256:DEADBEEF", "rule:github-pat", "rule:github-pat:a.go"} {
		s := detect.NewIgnoreSet()
		s.Add(entry)
		if !s.Ignored(f) {
			t.Errorf("entry %q should ignore finding", entry)
		}
	}
	s := detect.NewIgnoreSet()
	s.Add("rule:github-pat:b.go")
	if s.Ignored(f) {
		t.Error("rule:file entry must be file-specific")
	}
}

func BenchmarkDetect(b *testing.B) {
	d := defaultDetector(b, 2)
	var sb strings.Builder
	for i := 0; i < 2000; i++ {
		fmt.Fprintf(&sb, "func handler%d(w http.ResponseWriter, r *http.Request) { log.Printf(\"request %%s\", r.URL.Path) }\n", i)
	}
	text := sb.String()
	b.SetBytes(int64(len(text)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		d.Detect(detect.Fragment{Raw: text, FilePath: "big.go", StartLine: 1})
	}
}

func TestLooksLikeIdentifierViaGeneric(t *testing.T) {
	d := defaultDetector(t, 0)
	for _, line := range []string{
		"s, err := SignPSS(rand.Reader, key, crypto.SHA256, hashed[:], nil)",
		"KeyUsage: KeyUsageCRLSign,",
		"return cryptRSA(priv.withKey, C.GO_RSA_PKCS1_OAEP_PADDING, h)",
		"{hexKey: hexPKCS1TestPKCS8Key, errorContains: \"x\"},",
		"k8s.io/apiserver,v0.0.0-20191031110436-8cb875160ee0,h1:x",
	} {
		if fs := d.Detect(detect.Fragment{Raw: line, FilePath: "a.go"}); len(fs) > 0 {
			t.Errorf("false positive on %q: %v %q", line, ids(fs), fs[0].Secret)
		}
	}
	// Random unquoted env values are still caught.
	if fs := d.Detect(detect.Fragment{Raw: "API_SECRET=" + g(alnum, 32), FilePath: ".env"}); !has(fs, "generic-api-key") {
		t.Error("unquoted random secret missed")
	}
	// Tokens embedded in base64 blobs are not reported.
	if fs := d.Detect(detect.Fragment{Raw: "Dx+EAAAAAABIhdsPhK0EAAAPtnMIQPbGBA+FjgQAAEiJnCSIAAAASImEJIAAAABIiUwkaEiLUEhI", FilePath: "a.b64"}); has(fs, "square-token") {
		t.Error("square token inside base64 blob")
	}
}

func TestQuotedIdentifiersAndWeakPasswords(t *testing.T) {
	d := defaultDetector(t, 0)
	if fs := d.Detect(detect.Fragment{Raw: `"EncapsulationKeySize768": "EncapsulationKeySize1024",`, FilePath: "a.go"}); len(fs) > 0 {
		t.Errorf("quoted identifier flagged: %v", ids(fs))
	}
	// Word-like hard-coded passwords are still caught by password-assignment.
	if fs := d.Detect(detect.Fragment{Raw: `db_password = "` + "SuperSecret" + "Password2024" + `"`, FilePath: "a.py"}); !has(fs, "password-assignment") {
		t.Errorf("weak password missed: %v", ids(fs))
	}
}

func TestProseAndURLValuesNotFlagged(t *testing.T) {
	d := defaultDetector(t, 0)
	for _, line := range []string{
		`fs.Var(&x, "ignore-file", "fingerprints (default: .secretscanignore, .gitleaksignore)")`,
		`"url without password":   "https://user@github.com/org/repo.git",`,
		`password_file: "./config/db-credentials.txt"`,
	} {
		if fs := d.Detect(detect.Fragment{Raw: line, FilePath: "a.go"}); len(fs) > 0 {
			t.Errorf("false positive on %q: %v", line, ids(fs))
		}
	}
}

func TestV3NoiseFilters(t *testing.T) {
	d := defaultDetector(t, 2)
	for _, line := range []string{
		`      "result_key": "DBSubnetGroups"`,
		` *   KeyMarker: "nextkeyfrompreviousresponse",`,
		`OAUTH_API_BETA_HEADER = "oauth-2025-04-20"`,
		"\tSIOCGLIFTOKEN                 = -0x3f879678",
		`    readonly INVALID_PASSWORD: "invalid-password";`,
		`              "PasswordLastUsed": "2016-09-08T21:47:36Z",`,
		`CPK_KEY_VALUE = "MDEyMzQ1NjcwMTIzNDU2NzAxMjM0NTY3MDEyMzQ1Njc="`,
		`  "PurchaseToken": "eyJ2IjoiMSIsInMiOjEsImMiOi...",`,
		`engine = create_engine("mssql+pyodbc://scott:tiger@some_dsn")`,
		`f"http://{ENCODED_USER}:{ENCODED_PASSWORD}@request.com/url.html"`,
		`DEVSTORE = "DefaultEndpointsProtocol=http;AccountName=devstoreaccount1;AccountKey=` +
			"Eby8vdM02xNOcqFlqUwJPLlmEtlCDXJ1OUzFT50uSRZ6IFsuFq2UVErCz4I6tq/K1SZFPTOtr/" + `KBHBeksoGMGw==;"`,
		`api_key = "abcdefghijklmnop1234"`,
	} {
		if fs := d.Detect(detect.Fragment{Raw: line, FilePath: "x.py"}); len(fs) > 0 {
			t.Errorf("noise not filtered: %q -> %v %q", line, ids(fs), fs[0].Secret)
		}
	}
	// Still caught: leet passwords, symbol passwords in env files, short-alphabet hex.
	for line, rule := range map[string]string{
		`db_password = "s00pers3cret"`:               "password-assignment", // secretscan:allow (test fixture)
		`ENV ADMIN_PASSWORD=Wuy8vDv-a*+Q7Xtzp8+`:     "generic-api-key",
		`token = "db9ed2a829b6e9e3a60e5a0eb0e1526c"`: "generic-api-key", // secretscan:allow (test fixture)
		`  password: 5ydbL_XwX4E9`:                   "generic-api-key", // secretscan:allow (test fixture)
		`const credentials = 'Et69DS8GOzI_Ck1!UL';`:  "generic-api-key", // secretscan:allow (test fixture)
	} {
		path := "app.py"
		if strings.HasPrefix(line, "ENV") {
			path = "Dockerfile"
		} else if strings.HasPrefix(line, "  password") {
			path = "values.yaml"
		}
		if fs := d.Detect(detect.Fragment{Raw: line, FilePath: path}); !has(fs, rule) {
			t.Errorf("missed %q (%s): %v", line, rule, ids(fs))
		}
	}
}

func TestV4NoiseFiltersAndRecall(t *testing.T) {
	d := defaultDetector(t, 2)
	for _, line := range []string{
		`    "NextToken": "JqBdtVdGsvMjUysyEgwy/jVBCGAjj9G4/ivkfsXHt9A=",`,
		`               "AccessPointName": "myaccesspoint--abcd-ab1--xa-s3",`,
		`            "clientSecret": "YSBzZWNyZXQ=",`,
		`        token = 'eyJmb28iOiAiYmFyIn0='`,
		`            'ContinuationToken': "%C3%A7%C3%B6s%25%20asd%08+c",`,
		`    const password = parsedURL.password;`,
		`        "PWD=(whatever);"`,
		`        "token": "mF_9.B5f-4.1JqM",`,
	} {
		if fs := d.Detect(detect.Fragment{Raw: line, FilePath: "x.py"}); len(fs) > 0 {
			t.Errorf("noise not filtered: %q -> %v %q", line, ids(fs), fs[0].Secret)
		}
	}
	for line, path := range map[string]string{
		`  jwt_secret: "ZcoN0HMupgdPhqEjT+GJh5vq6PACZZ1KNOlktT9iV0g="`:                    "values.yml", // secretscan:allow (test fixture)
		`ENV SESSION_SECRET=Sj6l!buX3C-E%@WC`:                                             "0176-app-Dockerfile",
		`Data Source=sql1;Initial Catalog=app;User ID=svc;Password=` + g(alnum, 14) + `;`: "app.config",
	} {
		if fs := d.Detect(detect.Fragment{Raw: line, FilePath: path}); len(fs) == 0 {
			t.Errorf("missed %q", line)
		}
	}
}

func TestXMLConfigAndSymbolPasswords(t *testing.T) {
	d := defaultDetector(t, 0)
	hits := map[string]string{
		`    <add key="LITELLM_MASTER_KEY" value="sk-sIJpLWZVcdAbmaJTc5dg1u" />`: "web.config", // secretscan:allow (test fixture)
		`    <add key="admin.pass" value="3FKq&nVJRzf#oL0" />`:                   "web.config", // secretscan:allow (test fixture)
		`<server><id>nexus</id><password>Zq8!vR2#pLm9xT</password></server>`:     "settings.xml",
		`password = puJeBew?Cq$3cdm$JvmR24`:                                      "settings.ini",
		"export const redisPassword = `vO?!E#sKameh2`;":                          "env.ts", // secretscan:allow (test fixture)
	}
	for line, path := range hits {
		if fs := d.Detect(detect.Fragment{Raw: line, FilePath: path}); len(fs) == 0 {
			t.Errorf("missed %q", line)
		} else if strings.Contains(fs[0].Secret, "<") || strings.Contains(fs[0].Secret, "key=") {
			t.Errorf("bad secret span %q", fs[0].Secret)
		}
	}
	for _, line := range []string{
		`    <add key="TokenEndpoint" value="https://login.example.com/token" />`,
		`    <add key="ClientSecret" value="$(ClientSecret)" />`,
		`<password>${env.NEXUS_PASSWORD}</password>`,
		`    <add key="PasswordMinLength" value="12" />`,
	} {
		if fs := d.Detect(detect.Fragment{Raw: line, FilePath: "web.config"}); len(fs) > 0 {
			t.Errorf("noise: %q -> %v %q", line, ids(fs), fs[0].Secret)
		}
	}
}
