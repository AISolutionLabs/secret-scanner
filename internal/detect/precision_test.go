// SPDX-License-Identifier: Apache-2.0

package detect_test

import (
	"strings"
	"testing"

	"github.com/AISolutionLabs/secret-scanner/internal/config"
	"github.com/AISolutionLabs/secret-scanner/internal/detect"
)

func findingFor(fs []detect.Finding, id string) *detect.Finding {
	for i := range fs {
		if fs[i].RuleID == id {
			return &fs[i]
		}
	}
	return nil
}

// Suppressions must be narrow: a filter or allowlist that removes a false
// positive must never hide a valid secret next to it.
func TestSuppressionsDoNotHideNearbySecrets(t *testing.T) {
	d := defaultDetector(t, 2)
	pat := "ghp_" + g(alnum, 36)
	cases := []struct {
		name, path, text, rule string
	}{
		{"same line as word-like generic value", "app.py",
			`auth_provider = "isOnDemandRevalidate"; token = "` + pat + `"`, "github-pat"},
		{"next line after a filtered UUID", "app.py",
			"request_token = \"" + uuid() + "\"\ngh = \"" + pat + "\"", "github-pat"},
		{"token containing a placeholder word", "app.py",
			`gh = "ghp_Example` + g(alnum, 29) + `"`, "github-pat"},
		{"provider token on a name-allowlisted key", "app.py",
			`public_key_id = "` + pat + `"`, "github-pat"},
		{"registry credential in a lockfile", "package-lock.json",
			`"resolved": "https://ci-bot:` + g(alnum, 20) + `@artifactory.acme-corp.io/api/npm/x/-/x-1.0.0.tgz",`, "url-credentials"},
		{"provider token in a lockfile", "yarn.lock",
			`  resolved "https://npm.pkg.github.com/x?token=` + pat + `"`, "github-pat"},
		{"provider token pasted into scanner config", ".gitleaks.toml",
			`regexes = ['''` + pat + `''']`, "github-pat"},
		{"next to the AWS documentation example key", "deploy.env",
			"AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\nGITHUB_TOKEN=" + pat, "github-pat"},
		{"inline ignore applies to its own line only", "app.py",
			"x = \"ghp_" + g(alnum, 36) + "\"  # secretscan:allow\ny = \"" + pat + "\"", "github-pat"},
		{"real token next to a docker digest", "values.yaml",
			"image: reg.io/app@sha256:" + g(hexs, 64) + "\ntoken: " + pat, "github-pat"},
	}
	for _, c := range cases {
		fs := d.Detect(detect.Fragment{Raw: c.text, FilePath: c.path, StartLine: 1})
		f := findingFor(fs, c.rule)
		if f == nil {
			t.Errorf("%s: %s hidden (got %v)", c.name, c.rule, ids(fs))
			continue
		}
		if strings.Contains(c.name, "inline") && f.StartLine != 2 {
			t.Errorf("%s: wrong line %d", c.name, f.StartLine)
		}
	}
}

// Provider-format findings are high confidence wherever they appear;
// test/example locations only withhold a supporting signal from contextual rules.
func TestConfidenceNeverDowngradedByLocation(t *testing.T) {
	d := defaultDetector(t, 0)
	pat := "ghp_" + g(alnum, 36)
	for _, path := range []string{"src/app.py", "tests/test_app.py", "examples/demo.go", "docs/setup.md", "app.spec.ts"} {
		f := findingFor(d.Detect(detect.Fragment{Raw: `t = "` + pat + `"`, FilePath: path}), "github-pat")
		if f == nil || f.Confidence != detect.High {
			t.Errorf("%s: github-pat confidence %v", path, f)
		}
	}
}

// Entropy alone never produces a high-confidence finding.
func TestEntropyAloneIsNotEnough(t *testing.T) {
	d := defaultDetector(t, 0)
	secret := g(alnum, 32)
	// Strong: credential key + random + long + literal + outside tests.
	strong := findingFor(d.Detect(detect.Fragment{Raw: `api_secret = "` + secret + `"`, FilePath: "src/app.py"}), "generic-api-key")
	if strong == nil || strong.Confidence != detect.High || len(strong.Evidence) < 4 {
		t.Fatalf("strong generic: %+v", strong)
	}
	// Same random value in a test file, unquoted short value: fewer signals.
	weak := findingFor(d.Detect(detect.Fragment{Raw: "client_secret: " + g(alnum, 12), FilePath: "tests/fixture.txt"}), "generic-api-key")
	if weak != nil && weak.Confidence == detect.High {
		t.Errorf("weak generic should not be high: %+v", weak)
	}
}

func TestLedgerExplainsEverySuppression(t *testing.T) {
	cfg, _, _ := config.Resolve(config.Options{})
	rs, _ := config.Compile(cfg)
	d := detect.New(rs, detect.Options{RecordSuppressed: true})
	res := d.Scan(detect.Fragment{Raw: "auth_provider = \"isOnDemandRevalidate\"\n" +
		"request_token = \"" + uuid() + "\"\n" +
		"token = \"ghp_" + g(alnum, 36) + "\" # secretscan:allow\n" +
		"db_password = \"Winter2026!\"\n", FilePath: "app.py", StartLine: 1})
	reasons := map[string]int{}
	for _, s := range res.Suppressed {
		reasons[s.Reason] = s.StartLine
		if s.SecretHash == "" || s.File != "app.py" {
			t.Errorf("incomplete ledger entry %+v", s)
		}
	}
	for reason, line := range map[string]int{"word-like": 1, "uuid": 2, "inline-ignore": 3} {
		if reasons[reason] != line {
			t.Errorf("ledger missing %s on line %d: %v", reason, line, reasons)
		}
	}
	// Reported by password-assignment, so not listed as suppressed.
	for _, s := range res.Suppressed {
		if s.StartLine == 4 {
			t.Errorf("value reported by another rule listed as suppressed: %+v", s)
		}
	}
	total := 0
	for _, n := range res.Counts {
		total += n
	}
	if total != len(res.Suppressed) {
		t.Errorf("counts %v disagree with ledger (%d)", res.Counts, len(res.Suppressed))
	}
}

// False-positive patterns reported in public issue trackers.
func TestPubliclyReportedFalsePositives(t *testing.T) {
	d := defaultDetector(t, 2)
	cases := map[string]string{
		// gitleaks#1468: square-access-token on a Docker image digest
		"base-images.yaml": "image: my-super.registry.docker/aws-cli@sha256:eaaa7b11777babe28e6133a8b19ff71cea687e0d7f05158dee95a71f76ce3d00",
		// gitleaks#1775: generic-api-key on BitBake SRCREV and patch checksums
		"docker-moby.bb": `SRCREV_moby = "43fc912ef59a83054ea7f6706df4d53a7dea4d80"`,
		"vendor.patch":   `-{"files":{"Cargo.toml":"32a7c9ac508dc33ad03b44010f7cd1bb3592fd069e9e0b9caffd909ff2795184",`,
		// gitleaks#1321: Vault key name in a Jenkins pipeline
		"Jenkinsfile": `    [envVar: 'TF_VAR_APPROLESECRETID', vaultKey: 'inf-vsqt-01-secret-id']]]]) {`,
		// gitleaks#1832: hashicorp-tf-password on policy names and annotations
		"vault.tf": "  \"vault.hashicorp.com/agent-inject-secret-ingest.json\" : \"kv/ops/ingest\"\n  password_policy = \"excellent\"",
		// trufflehog#4364: commit SHA in a GitHub zipball URL
		"composer.json": `"url": "https://api.github.com/repos/symfony/monolog-bridge/zipball/9d14621e59f22c2b6d030d92d37ffe5ae1e60452",`,
		// trufflehog#3578: documentation connection string
		"appsettings.json": `"ConnectionString": "Server=myServerAddress;Database=myDataBase;User Id=myUsername;Password=myPassword;"`,
	}
	for path, text := range cases {
		if fs := d.Detect(detect.Fragment{Raw: text, FilePath: path}); len(fs) > 0 {
			t.Errorf("%s: false positive %v %q", path, ids(fs), fs[0].Secret)
		}
	}
}

func TestCorpusDerivedNoise(t *testing.T) {
	d := defaultDetector(t, 0)
	for path, text := range map[string]string{
		"v1_volume_projection.py": `        "downward_api": "V1DownwardAPIProjection",`,
		"packages-bundle.js":      `key-for","es6.symbol"`,
		"httptester.py":           `KRB5_PASSWORD_ENV = 'KRB5_PASSWORD'`,
		"page_iterator.py":        `    Next page token: eav1OzQB0OM8rLdGXOEsyQWSG`,
	} {
		if fs := d.Detect(detect.Fragment{Raw: text, FilePath: path}); len(fs) > 0 {
			t.Errorf("%s: %v %q", path, ids(fs), fs[0].Secret)
		}
	}
	// Unstructured random values in fixtures are capped at medium; provider formats are not.
	f := findingFor(d.Detect(detect.Fragment{Raw: `encryption_key = "` + g(hexs, 32) + `"`, FilePath: "tests/unit/test_blob.py"}), "generic-api-key")
	if f == nil || f.Confidence != detect.Medium {
		t.Errorf("fixture generic should be medium: %+v", f)
	}
	for _, p := range []string{"examples-1.json", "login-provider-test-cases.json", "fake_credentials.py"} {
		if !detect.IsTestPath("data/" + p) {
			t.Errorf("%s should be a test/example path", p)
		}
	}
	if detect.IsTestPath("src/contest.py") || detect.IsTestPath("src/latest_release.go") {
		t.Error("test path regex too broad")
	}
}

// Identifier filters must essentially never fire on random tokens.
// Noise filters must essentially never remove a random secret. (Values
// below the rule's entropy threshold never qualify and are reported apart.)
func TestNoiseFiltersSpareRandomSecrets(t *testing.T) {
	cfg, _, _ := config.Resolve(config.Options{})
	rs, _ := config.Compile(cfg)
	d := detect.New(rs, detect.Options{RecordSuppressed: true})
	filtered, belowEntropy := map[string]int{}, 0
	if testing.Short() || raceEnabled {
		t.Skip("statistical: needs the full sample; CI runs it in a separate non-race step")
	}
	n := 20000
	for i := 0; i < n; i++ {
		v := g(alnum, 16+i%30)
		res := d.Scan(detect.Fragment{Raw: `api_secret = "` + v + `"`, FilePath: "src/app.py"})
		if has(res.Findings, "generic-api-key") {
			continue
		}
		if len(res.Suppressed) == 0 {
			belowEntropy++
		}
		for _, s := range res.Suppressed {
			filtered[s.Reason]++
		}
	}
	total := 0
	for _, c := range filtered {
		total += c
	}
	t.Logf("random secrets lost: %d to filters %v, %d below the entropy threshold (of %d)", total, filtered, belowEntropy, n)
	if total > 2 { // <= 0.01%
		t.Errorf("noise filters removed %d/%d random secrets: %v", total, n, filtered)
	}
	if belowEntropy > n/1000 { // <= 0.1%
		t.Errorf("%d/%d random secrets below the entropy threshold", belowEntropy, n)
	}
}
