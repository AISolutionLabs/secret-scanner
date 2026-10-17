// SPDX-License-Identifier: Apache-2.0

package detect_test

import (
	"math/rand"
	"strings"
	"testing"

	"github.com/AISolutionLabs/secret-scanner/internal/detect"
)

// Regressions from an adversarial recall review: real credentials written
// the way developers write them, which filters or contexts used to drop or
// downgrade. Values are generated at runtime from a dedicated source so the
// calibrated statistical tests keep their samples.

var rng3 = rand.New(rand.NewSource(31337))

func g3(cs string, n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = cs[rng3.Intn(len(cs))]
	}
	return string(b)
}

func scanOne(d *detect.Detector, line, path string) []detect.Finding {
	return d.Detect(detect.Fragment{Raw: line + "\n", FilePath: path, StartLine: 1})
}

// One-word default passwords plus digits are real weak passwords as often
// as placeholders. Outside test, example and doc files they are reported at
// low confidence (strict blocks, balanced lists them for review); in those
// files they are dropped with a ledger reason.
func TestDefaultPasswordsReportedLow(t *testing.T) {
	d := defaultDetector(t, 0)
	for _, c := range []struct{ line, path string }{
		{"DB_PASSWORD=admin@123", "config/prod.env"},
		{`  password: "Welcome@2024"`, "deploy/values-prod.yaml"},
		{`DATABASES = {'default': {'PASSWORD': 'P@ssw0rd2023'}}`, "app/settings.py"},
		{`master_password = "Password1"`, "main.tf"},
		{"MYSQL_ROOT_PASSWORD: root123", "values.yaml"},
		{`password = "qwerty123!"`, "src/db.py"},
		{"ADMIN_PASSWORD=Admin@2025", ".env"},
	} {
		fs := scanOne(d, c.line, c.path)
		if len(fs) == 0 {
			t.Errorf("%s %q: not reported", c.path, c.line)
			continue
		}
		for _, f := range fs {
			if f.Confidence != detect.Low || !strings.Contains(strings.Join(f.Evidence, "\n"), detect.DefaultPasswordEvidence) {
				t.Errorf("%s %q (%s): confidence %s, evidence %v", c.path, c.line, f.RuleID, f.Confidence, f.Evidence)
			}
			if detect.BlocksFinding("balanced", "block", f) || !detect.BlocksFinding("strict", "block", f) {
				t.Errorf("%s %q: low finding must be review under balanced and block under strict", c.path, c.line)
			}
		}
	}
	// In test and documentation files they stay placeholders.
	for _, c := range []struct{ line, path string }{
		{"DB_PASSWORD=admin123", "tests/fixtures/.env"},
		{`password: "Password1"`, "docs/setup.yaml"},
		{"    password: admin123", "README.md"},
		{`login("admin", "root@123")`, "e2e/login.spec.ts"},
	} {
		if fs := scanOne(d, c.line, c.path); len(fs) > 0 {
			t.Errorf("%s %q: reported %v", c.path, c.line, ids(fs))
		}
	}
	// Values that say they are fake are still dropped everywhere.
	for _, line := range []string{"DB_PASSWORD=changeme123", "DB_PASSWORD=Test@1234", `password = "dummy1"`} {
		if fs := scanOne(d, line, "config/prod.env"); len(fs) > 0 {
			t.Errorf("%q: reported %v", line, ids(fs))
		}
	}
}

// Production hosts that merely look local, and files that hold real local
// secrets, are not capped at low.
func TestProductionLookingLocalContext(t *testing.T) {
	d := defaultDetector(t, 0)
	pw := g3(alnum, 18)
	notLocal := []struct{ line, path string }{
		{"database_url: postgres://app:" + pw + "@postgres.prod.svc.cluster.local:5432/app", "k8s/app.yaml"}, // Kubernetes service DNS
		{"database_url: postgres://app:" + pw + "@pg.default.svc.cluster.local/app", "config/app.yaml"},
		{`DB = "mysql://app:` + pw + `@sql01.corp.local/app"`, "src/settings.py"}, // Active Directory domain
		{"ConnectionString=Server=sql01.corp.local;Database=app;User Id=app;Password=" + pw + ";", "conf/app.cfg"},
		{"PAYMENTS_API_KEY=" + g3(alnum, 32), ".env.local"}, // Next.js / Vite: real keys live here
		{"PAYMENTS_API_KEY=" + g3(alnum, 32), "apps/web/.env.development.local"},
		{"      - DB_PASSWORD=" + pw, "docker-compose.prod.yml"},
		{"      - DB_PASSWORD=" + pw, "deploy/production/docker-compose.yml"},
		{"          value: postgres://app:" + pw + "@127.0.0.1:5432/app", "k8s/prod/deploy.yaml"}, // cloud-sql-proxy sidecar
		{`url = "postgres://app:` + pw + `@10.20.4.17/app"`, "config/prod/settings.py"},
	}
	for _, c := range notLocal {
		fs := scanOne(d, c.line, c.path)
		if len(fs) == 0 {
			t.Errorf("%s %q: not reported", c.path, c.line)
			continue
		}
		for _, f := range fs {
			if f.Context != "" || !detect.BlocksFinding("balanced", "block", f) {
				t.Errorf("%s %q (%s): context %q confidence %s blocking=%v", c.path, c.line, f.RuleID, f.Context, f.Confidence,
					detect.BlocksFinding("balanced", "block", f))
			}
		}
	}
	// Still local: loopback, single-label mDNS names, compose files and env
	// files for tests outside production paths.
	for _, c := range []struct{ line, path string }{
		{`url = "postgres://app:` + pw + `@localhost:5432/app"`, "src/settings.py"},
		{`url = "postgres://app:` + pw + `@devbox.local:5432/app"`, "src/settings.py"},
		{"      - DB_PASSWORD=" + pw, "docker-compose.yml"},
		{"DB_PASSWORD=" + pw, ".env.test"},
	} {
		fs := scanOne(d, c.line, c.path)
		if len(fs) == 0 || fs[0].Context != detect.ContextLocal {
			t.Errorf("%s %q: want local context, got %+v", c.path, c.line, fs)
		}
	}
}

// redis://:password@host has an empty user name; it is Redis's own URL form.
func TestURLCredentialWithEmptyUser(t *testing.T) {
	d := defaultDetector(t, 0)
	pw := g3(alnum, 24)
	for _, line := range []string{
		"redis_url: redis://:" + pw + "@redis-master.prod.acme-corp.net:6379/0",
		`REDIS_URL = "rediss://:` + pw + `@cache.internal:6380"`,
	} {
		if f := findingFor(scanOne(d, line, "config/app.yaml"), "url-credentials"); f == nil || f.Secret != pw {
			t.Errorf("%q: not reported by url-credentials", line)
		}
	}
	for _, line := range []string{"redis_url: redis://:password@localhost:6379", "url: redis://:${REDIS_PASSWORD}@redis:6379"} {
		if fs := scanOne(d, line, "config/app.yaml"); has(fs, "url-credentials") {
			t.Errorf("%q: placeholder reported", line)
		}
	}
}

// A placeholder phrase must be the whole value: "mysecretkey_" or
// "yourkey_" followed by random characters is a real key's name.
func TestPlaceholderPrefixNeedsWholeValue(t *testing.T) {
	d := defaultDetector(t, 0)
	for _, v := range []string{"mysecretkey_" + g3(lowAln, 6), "mytoken" + g3(alnum, 12), "yourkey_" + g3(alnum, 16)} {
		if fs := scanOne(d, `JWT_SECRET = "`+v+`"`, "src/config.py"); len(fs) == 0 {
			t.Errorf("%q: not reported", v)
		}
	}
	for _, v := range []string{"your_api_key_here", "YOUR_ACCESS_TOKEN_HERE", "my-secret-key", "your_api_key_here_1234", "yourpasswordhere",
		"your_token_goes_here", "insert_your_key_here", "my_secret_xxxxxxxx"} {
		if fs := scanOne(d, `JWT_SECRET = "`+v+`"`, "src/config.py"); len(fs) > 0 {
			t.Errorf("%q: placeholder reported %v", v, ids(fs))
		}
	}
}

// Authorization: <uuid> carries the credential (APIs that take a raw key in
// the header); kept at low like other UUIDs under credential keys.
func TestAuthorizationHeaderUUID(t *testing.T) {
	d := defaultDetector(t, 0)
	fs := scanOne(d, "Authorization: "+uuid(), "http/requests.http")
	if len(fs) == 0 || fs[0].Confidence != detect.Low {
		t.Errorf("Authorization UUID: %+v", fs)
	}
	if !detect.CredentialKey.MatchString("Authorization: ") || !detect.CredentialKey.MatchString("Proxy-Authorization: ") {
		t.Error("CredentialKey must match Authorization headers")
	}
}

// Bearer tokens without a digit (letters-only alphabets, or a random draw
// that happens to have none) are tokens too; placeholders are still not.
func TestDigitFreeBearerTokens(t *testing.T) {
	d := defaultDetector(t, 0)
	missed := 0
	for i := 0; i < 200; i++ {
		tok := g3(letters, 32)
		if !has(scanOne(d, `curl -H "Authorization: Bearer `+tok+`" https://api.acme.io/v1`, "scripts/call.sh"), "http-bearer-token") {
			missed++
		}
	}
	if missed > 2 {
		t.Errorf("%d/200 digit-free 32-character Bearer tokens missed", missed)
	}
	for _, p := range []string{"YOUR_ACCESS_TOKEN", "someAccessTokenValue", "ReplaceWithYourOwnTokenHere", "accessTokenFromLoginResponse",
		"PersonalAccessTokenHere", "ThisIsNotARealTokenJustExample", "abcdefghijklmnopqrstuvwxyz"} {
		if has(scanOne(d, "Authorization: Bearer "+p, "src/client.js"), "http-bearer-token") {
			t.Errorf("Bearer placeholder %q reported", p)
		}
	}
}

// Unquoted values in env-style text files (.env.production.local, .envrc,
// Makefiles, notes) are literals, not code: random base64 there used to be
// dropped as "operator-in-code" for its + and / about 40% of the time, and
// base64 starting with / or + never matched.
func TestUnquotedRandomValuesInTextFiles(t *testing.T) {
	d := defaultDetector(t, 0)
	for _, path := range []string{"notes/creds.txt", ".env.production.local", ".envrc", "Makefile", "deploy/app.env.j2", "app.service"} {
		for _, cs := range []string{alnum, alnum + "+/"} {
			missed := 0
			for i := 0; i < 300; i++ {
				if len(scanOne(d, "API_SECRET="+g3(cs, 32), path)) == 0 {
					missed++
				}
			}
			if missed > 3 {
				t.Errorf("%s: %d/300 random values missed (alphabet of %d)", path, missed, len(cs))
			}
		}
	}
	// Expressions in code are still not secrets.
	for _, line := range []string{"api_key = base+offset*2", "auth = a/b+c", "token = prefix+suffix"} {
		if fs := scanOne(d, line, "src/app.py"); len(fs) > 0 {
			t.Errorf("%q: reported %v", line, ids(fs))
		}
	}
}
