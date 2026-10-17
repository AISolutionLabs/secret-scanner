// SPDX-License-Identifier: Apache-2.0

package detect_test

import (
	"encoding/base64"
	"fmt"
	"sort"
	"strings"
	"testing"

	"github.com/AISolutionLabs/secret-scanner/internal/config"
	"github.com/AISolutionLabs/secret-scanner/internal/detect"
)

// Every noise filter gets three kinds of cases:
//
//	keep        real-looking secrets the filter must NOT remove
//	reject      harmless values it exists to remove
//	borderline  known trade-offs, pinned so a change in behaviour is a
//	            deliberate, reviewed decision (documented in docs/precision.md)
type filterCase struct {
	line, path string
	want       bool // reported?
}

func reported(d *detect.Detector, c filterCase) bool {
	path := c.path
	if path == "" {
		path = "src/settings.py"
	}
	return len(d.Detect(detect.Fragment{Raw: c.line, FilePath: path})) > 0
}

func TestFilterAdversarialCases(t *testing.T) {
	d := defaultDetector(t, 2)
	filters := map[string]struct{ keep, reject, borderline []filterCase }{
		"word-like": {
			keep: []filterCase{
				{line: `api_secret = "xK9mPasswordQ7zL2vN8wR"`},      // dictionary word inside a random token
				{line: `client_secret = "Q2hpY2tlbkRpbm5lcjk4Nzc="`}, // base64 of words: still opaque
				{line: `token = "aSecretTokenValue9x7Kq2LmN4"`},      // words + random tail
			},
			reject: []filterCase{
				{line: `auth_provider = "SecurityProfiles"`},
				{line: `token_name = "accessTokenProvider"`},
			},
			borderline: []filterCase{
				// Passphrase-style secrets made only of words are filtered by the
				// generic rule. Known gap: use a password-named key (below) or a custom rule.
				{line: `api_secret = "CorrectHorseBatteryStaple"`, want: false},
				{line: `db_password = "CorrectHorseBatteryStaple9"`, want: true},
			},
		},
		"camel-case-identifier": {
			keep:   []filterCase{{line: `api_secret = "AbqzXyvwKjhpTrmn9Q"`}},
			reject: []filterCase{{line: `"downward_api": "V1DownwardAPIProjection",`}},
		},
		"identifier": {
			keep: []filterCase{
				{line: `api_secret = "MIVWdsoNuhGuoNge7Kx"`}, // splits into 3+ letter runs, but random
				// Unquoted hex is data, not an identifier. Fixed values (random
				// stand-ins from CredData) that the letter-run split once misread.
				{line: "SharedSecret=e86f3aba843e0de15cacbe173d6eaea830eed88eac4a8d2d", path: "test/vectors.txt"}, // secretscan:allow (fixture)
				{line: "Key = acc993b3319ddf05b296bacd8b6e16f4", path: "test/kdf.txt"},                            // secretscan:allow (fixture)
			},
			reject: []filterCase{{line: `key := crypto.SHA256`, path: "main.go"}, {line: `KeyUsage: KeyUsageCRLSign,`, path: "x509.go"}},
		},
		"uuid": {
			keep:       []filterCase{{line: `HEROKU_API_KEY=01234567-89ab-4cde-8f01-23456789abcd`, path: ".env"}}, // provider rule keeps it
			reject:     []filterCase{{line: `request_token = "0b8a6c3e-1f2d-4e5a-9b7c-6d5e4f3a2b1c"`}},
			borderline: []filterCase{{line: `api_secret = "0b8a6c3e-1f2d-4e5a-9b7c-6d5e4f3a2b1c"`, want: false}}, // UUID secrets without a provider rule
		},
		"number-or-date": {
			keep:   []filterCase{{line: `api_secret = "20240101aBcD9xYzQ7"`}},
			reject: []filterCase{{line: `token_expiry = "2024-01-01T00:00:00Z"`}, {line: `api_key_id = "12345678901234"`}},
		},
		"word-segments": {
			keep:   []filterCase{{line: `license_key = "x7k2-9fj3-qq81-z0pa"`}, {line: `api_key = "QX7V2-3OFV9-VV1UB-NKT0I"`}},
			reject: []filterCase{{line: `OAUTH_API_BETA_HEADER = "oauth-2025-04-20"`}, {line: `api_version = "v2-beta-release"`}},
		},
		"word-tokens": {
			keep: []filterCase{
				{line: `api_secret = "KeyQx7mVaultZp2Lw9TokenRb"`}, // words broken up by random runs
				{line: `client_secret = "dataTq8ZmXkWv2PbNs4c"`},
				{line: `db_password = "CorrectHorseBatteryStaple9"`}, // password rules never use word filters
			},
			reject: []filterCase{
				{line: `"webhookKey": "my_webhookKey",`, path: "v1.d.ts"},
				{line: `cacheKey: "headersToExcludeInCacheKey"`, path: "dedupe.js"},
				{line: `key","TSNeverKeyword","TSNullKeyword"`, path: "bundle.js"},
				{line: `auth: "0011_update_proxy_permissions"`, path: "migrations/0012.py"},
				{line: `token_url_name = "base64url-decode-v2"`},
				{line: `secret_arn = "arn-MyTestDatabaseSecret1-d4e5f6"`},
			},
		},
		"echoes-key-name": {
			keep:   []filterCase{{line: `"webhookKey": "my_Kq9Zx7mVwP2bN4"`, path: "v1.d.ts"}},
			reject: []filterCase{{line: `"vmIdToken": "my_vmIdToken",`, path: "v1.d.ts"}, {line: `"b64MacKey": "my_b64MacKey"`, path: "v1.d.ts"}},
		},
		"scheme-names": {
			keep:   []filterCase{{line: `Authorization: AWS4-HMAC-SHA256 Credential=AKIA` + g("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567", 16) + `/20260101/us-east-1/s3/aws4_request`, path: "req.txt"}},
			reject: []filterCase{{line: `Authorization: AWS4-HMAC-SHA256`, path: "get-vanilla.sreq"}},
		},
		"string-concatenation": {
			keep:   []filterCase{{line: `api_secret = "+Kq9Zx7mVwP2bN4+Lx"`}},
			reject: []filterCase{{line: `html += ' key="'+value1.key+'"'`, path: "runtime.dev.js"}},
		},
		"email-address": {
			keep:   []filterCase{{line: `password = "Kq9@Zx7mN2pQ.v"`}},
			reject: []filterCase{{line: `__author_email__ = "me@kennethreitz.org"`, path: "__version__.py"}},
		},
		"dotted-namespace": {
			keep:       []filterCase{{line: `api_secret = "Ab3.Kq9.Zx7mN2pQ"`}},
			reject:     []filterCase{{line: `key-for","es6.symbol"`, path: "bundle.js"}},
			borderline: []filterCase{{line: `api_secret = "kqz.vwp.mtr.xyl"`, want: false}}, // lowercase dotted, no digits
		},
		"single-case-letters": {
			reject: []filterCase{{line: ` *   KeyMarker: "nextkeyfrompreviousresponse",`}},
			keep:   []filterCase{{line: `api_secret = "qzvxkwplmrtbnhgdfsyc7"`}, {line: `api_secret = "qzvxkwplmrtbnhgdfsyc"`}}, // digit-free single-case random is kept
		},
		"operator-in-code": {
			keep:   []filterCase{{line: `password = "Wuy8vDv-a*+Q7Xtzp8+"`}, {line: `ADMIN_PASSWORD=Wuy8vDv-a*+Q7Xtzp8+`, path: ".env"}},
			reject: []filterCase{{line: `auth_score = weight*factor+bias_offset9`, path: "model.py"}},
		},
		"key=value-pair": {
			keep:   []filterCase{{line: `client_secret = "d8ZJUhe2xp+U3TnFoLuTW2k+L74Brz8Hy==" `}},
			reject: []filterCase{{line: `endpoint_auth: "Region=eu-west-1"`}},
		},
		"placeholder-password": {
			keep:       []filterCase{{line: `db_password = "s00pers3cret"`}, {line: `password: "Winter2026!"`}},
			reject:     []filterCase{{line: `password = "changeme"`}, {line: `readonly INVALID_PASSWORD: "invalid-password";`, path: "e.ts"}},
			borderline: []filterCase{{line: `password = "password"`, want: false}}, // literal placeholder word, even if real
		},
		"known-public-example": {
			keep:   []filterCase{{line: `aws_access_key_id = AKIA` + g("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567", 16), path: "c.env"}},
			reject: []filterCase{{line: `aws_access_key_id = AKIAIOSFODNN7EXAMPLE`, path: "c.env"}},
		},
	}
	names := make([]string, 0, len(filters))
	for n := range filters {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, name := range names {
		f := filters[name]
		for _, c := range f.keep {
			if !reported(d, c) {
				t.Errorf("%s must KEEP %q", name, c.line)
			}
		}
		for _, c := range f.reject {
			if reported(d, c) {
				t.Errorf("%s must REJECT %q", name, c.line)
			}
		}
		for _, c := range f.borderline {
			if got := reported(d, c); got != c.want {
				t.Errorf("%s borderline changed for %q: reported=%v (was %v); update docs/precision.md if intended", name, c.line, got, c.want)
			}
		}
	}
}

// Loss of random secrets per alphabet, split into "removed by a noise
// filter" (must stay ~0) and "below the rule's entropy threshold" (a rule
// design limit, reported). Run with -v to print the table.
func TestFalseNegativesPerAlphabet(t *testing.T) {
	cfg, _, _ := config.Resolve(config.Options{})
	rs, _ := config.Compile(cfg)
	d := detect.New(rs, detect.Options{RecordSuppressed: true})
	b64 := func(n int) string { return base64.StdEncoding.EncodeToString([]byte(g(alnum+"!@#$%^&*", n))) }
	b64url := func(n int) string {
		return strings.TrimRight(base64.URLEncoding.EncodeToString([]byte(g(alnum, n))), "=")
	}
	alphabets := []struct {
		name     string
		gen      func(i int) string
		maxEnt   float64 // max acceptable below-entropy loss (fraction)
		maxNoise float64 // max acceptable filter loss (fraction)
	}{
		{"alnum 16-45", func(i int) string { return g(alnum, 16+i%30) }, 0.001, 0.0002},
		{"hex 32/40/64", func(i int) string { return g(hexs, []int{32, 40, 64}[i%3]) }, 0.001, 0.0002},
		{"HEX upper 32", func(i int) string { return strings.ToUpper(g(hexs, 32)) }, 0.001, 0.0002},
		{"base64 std", func(i int) string { return b64(18 + i%30) }, 0.001, 0.0002},
		{"base64url", func(i int) string { return b64url(18 + i%30) }, 0.001, 0.0002},
		{"base32 lower 52", func(i int) string { return g("abcdefghijklmnopqrstuvwxyz234567", 52) }, 0.001, 0.0002},
		{"base32 upper 32", func(i int) string { return g("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567", 32) }, 0.001, 0.0002},
		{"password 12-24", func(i int) string { return g(alnum+"!@#$%^&*-_+?", 12+i%13) }, 0.003, 0.0005},
		{"lower+digits 20-40", func(i int) string { return g("abcdefghijklmnopqrstuvwxyz0123456789", 20+i%21) }, 0.005, 0.0002},
		// Random tokens around one placeholder-vocabulary word. The placeholder
		// filters must never fire on them (checked below for every alphabet);
		// the older word filters (word-like, digit-free-name-or-path) lose
		// ~0.3% of these, a known limit pinned here so it cannot grow.
		{"placeholder-vocabulary-adjacent", func(i int) string {
			w := []string{"password", "Admin", "test", "passwd", "root", "token", "local", "postgres", "Master"}[i%9]
			return g(alnum, 6+i%8) + []string{"", "-", "_"}[i%3] + w + g(alnum, 6+(i/3)%8)
		}, 0.001, 0.005},
	}
	if testing.Short() || raceEnabled {
		t.Skip("statistical: needs the full sample; CI runs it in a separate non-race step")
	}
	n := 20000.0 // a 1-in-10,000 leak must show up, not hide in sampling noise
	var rows []string
	for _, a := range alphabets {
		lostFilter, lostEntropy := 0, 0
		reasons := map[string]int{}
		for i := 0; i < int(n); i++ {
			v := a.gen(i)
			res := d.Scan(detect.Fragment{Raw: `api_secret = "` + v + `"`, FilePath: "src/app.py"})
			if has(res.Findings, "generic-api-key") {
				continue
			}
			if len(res.Suppressed) == 0 {
				lostEntropy++
			} else {
				lostFilter++
				reasons[res.Suppressed[0].Reason]++
			}
		}
		rows = append(rows, fmt.Sprintf("| %-20s | %5.3f%% | %5.3f%% | %v |", a.name, 100*float64(lostFilter)/n, 100*float64(lostEntropy)/n, reasons))
		for _, r := range []string{"placeholder-vocabulary", "echoes-key-name", "user-equals-password", "test-vector-name", "patterned-hex",
			"hash-of-credential", "public-key-token", "ui-text", "localized-text", "algorithm-name", "oid-bytes-or-version"} {
			if reasons[r] > 0 {
				t.Errorf("%s: placeholder/key filter %s removed %d random secrets", a.name, r, reasons[r])
			}
		}
		if float64(lostFilter)/n > a.maxNoise {
			t.Errorf("%s: noise filters removed %d/%.0f (%v)", a.name, lostFilter, n, reasons)
		}
		if float64(lostEntropy)/n > a.maxEnt {
			t.Errorf("%s: %d/%.0f below the entropy threshold", a.name, lostEntropy, n)
		}
	}
	t.Logf("\n| Alphabet | Removed by filters | Below entropy threshold | Filter reasons |\n|---|---|---|---|\n%s", strings.Join(rows, "\n"))
}

func TestCredentialNameSegments(t *testing.T) {
	d := defaultDetector(t, 0)
	for _, keep := range []string{`api_secret = "x8-Kq2_9Q!z7vB-mP"`, `password = "pass-word-9Zq!"`} {
		if !reported(d, filterCase{line: keep}) {
			t.Errorf("must keep %q", keep)
		}
	}
	for _, reject := range []string{`    [envVar: 'TF_VAR_X', vaultKey: 'inf-vsqt-01-secret-id']`, `secret_ref = "prod/my-app/db-password"`, `api_key_name = "team-a_api-key-v2"`} {
		if reported(d, filterCase{line: reject}) {
			t.Errorf("must reject %q", reject)
		}
	}
}

// Rules added after the independent leaky-repo run: each must catch its
// format and leave the common harmless shapes alone.
func TestConfigFormatRules(t *testing.T) {
	d := defaultDetector(t, 0)
	cases := []struct {
		rule, line, path string
		want             bool
	}{
		{"password-in-config", "REDIS_PASSWORD=RedisPass1!", ".env", true},
		{"password-in-config", "export ADMIN_PASS=hunter22", "deploy/env.sh.env", true},
		{"password-in-config", "db.password: kq9Vz2mXw", "config/app.yml", true},
		{"password-in-config", "DB_PASSWORD=", ".env", false},
		{"password-in-config", "DB_PASSWORD=${DB_PASSWORD}", ".env", false},
		{"password-in-config", "DB_PASSWORD=changeme", ".env", false},
		{"password-in-config", "password_min_length: 12", "config/app.yml", false},
		{"password-in-config", "password_file: /run/secrets/db", "config/app.yml", false},
		{"password-in-config", "use_password: true", "config/app.yml", false},
		{"password-in-config", "DB_PASSWORD=RedisPass1!", "src/app.py", false}, // path-scoped
		{"php-define-secret", "define('DB_PASSWORD', 'AdminPassword123');", "wp-config.php", true},
		{"php-define-secret", "define('AUTH_KEY', 'put your unique phrase here');", "wp-config.php", false},
		{"php-define-secret", "define('WP_DEBUG', 'enabled');", "wp-config.php", false},
		{"django-secret-key", "SECRET_KEY = 'django-insecure-" + g(alnum, 40) + "'", "settings.py", false},
		{"django-secret-key", "SECRET_KEY = os.environ['SECRET_KEY']", "settings.py", false},
		{"laravel-app-key", "APP_KEY=", ".env.example", false},
		{"xml-password-attribute", `<Pass encoding="base64">` + g(alnum, 16) + `</Pass>`, "sitemanager.xml", true},
		{"xml-password-attribute", `<property name="password" value="${db.password}"/>`, "pom.xml", false},
		{"xml-password-attribute", `<input type="password" name="pwd"/>`, "form.xml", false},
		{"netrc-password", "machine example.org login me password " + g(alnum, 12), ".netrc", true},
	}
	for _, c := range cases {
		got := has(d.Detect(detect.Fragment{Raw: c.line, FilePath: c.path}), c.rule)
		if got != c.want {
			t.Errorf("%s on %q (%s): reported=%v, want %v", c.rule, c.line, c.path, got, c.want)
		}
	}
	// Weak dictionary passwords are reported, but not as high confidence.
	// (Was admin123: canonical one-word defaults like admin123 / root123 are
	// now dropped as placeholders, with a ledger entry; see TestDummyValues.)
	fs := d.Detect(detect.Fragment{Raw: "ADMIN_PASSWORD=adminXq7", FilePath: ".env"})
	if len(fs) == 0 || fs[0].Confidence == detect.High {
		t.Errorf("weak password should be reported below high confidence: %+v", fs)
	}
}

func TestSecretReferenceNamesVsSecretKeys(t *testing.T) {
	d := defaultDetector(t, 0)
	for _, keep := range []filterCase{
		{line: "ENV SECRET_KEY=" + g(alnum, 22), path: "Dockerfile"},
		{line: `secret_key = "` + g(alnum, 24) + `"`},
	} {
		if !reported(d, keep) {
			t.Errorf("must keep %q", keep.line)
		}
	}
	for _, reject := range []filterCase{
		{line: `secret_name = "prod-db-credentials-v2"`},
		{line: `vault_key = "kv/data/team9/payments"`},
		{line: "    passwordPolicy: strong", path: "values.yaml"},
		{line: "password_reset_ttl: 3600s", path: "config/app.yml"},
	} {
		if reported(d, reject) {
			t.Errorf("must reject %q", reject.line)
		}
	}
}
