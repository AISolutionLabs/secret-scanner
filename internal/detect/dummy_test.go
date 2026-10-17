// SPDX-License-Identifier: Apache-2.0

package detect_test

import (
	"sort"
	"strings"
	"testing"

	"github.com/AISolutionLabs/secret-scanner/internal/config"
	"github.com/AISolutionLabs/secret-scanner/internal/detect"
)

// Placeholder, key-name and test-vector filters, in the keep / reject /
// borderline style of TestFilterAdversarialCases. Random parts are generated
// at runtime; the literal values are vocabulary placeholders or obvious fakes.
func TestDummyAndKeyFilterAdversarialCases(t *testing.T) {
	d := defaultDetector(t, 0)
	rnd := func(n int) string { return g(alnum, n) }
	low := func(n int) string { return g("abcdefghijklmnopqrstuvwxyz", n) }
	filters := map[string]struct{ keep, reject, borderline []filterCase }{
		"placeholder-vocabulary": {
			keep: []filterCase{
				// word-like passwords and passphrases outside the vocabulary
				{line: `db_password = "CorrectHorseBatteryStaple9"`},
				{line: `password: "Winter2026!"`},
				{line: `db_password = "Tr0ub4dor&3"`},
				{line: `db_password = "s00pers3cret"`},
				// low entropy but random-looking (CredData's stand-ins look like this)
				{line: `password = "` + low(7) + `"`},
				{line: `password = "` + low(6) + "9" + `"`},
				// UUID-shaped password
				{line: `db_password = "` + uuid() + `"`},
				// one vocabulary word inside random characters
				{line: `db_password = "` + rnd(4) + "password" + rnd(4) + `"`},
				{line: `api_secret = "` + rnd(6) + "admin" + rnd(8) + `"`},
				{line: `db_password = "admin_` + rnd(10) + `"`},
				{line: `db_password = "s3cret` + rnd(5) + `"`},
				{line: `ADMIN_PASSWORD=` + rnd(5) + `test`, path: ".env"},
				// weak real-looking passwords: several words plus a number
				{line: `db_password = "SuperSecretPassword2024"`},
				{line: "REDIS_PASSWORD=RedisPass1!", path: ".env"},
				{line: "export ADMIN_PASS=hunter22", path: "deploy/env.sh.env"},
			},
			reject: []filterCase{
				{line: `"password": "s3krit-password",`, path: "config.json"},
				{line: `password: some_password`, path: "values.yaml"},
				{line: `joomla_database_password: top_secret`, path: "vars.yml"},
				{line: `password: x-pack-test-password`, path: "elastic.yml"},
				{line: `GOCOMMERCE_MAILER_PASS=super-secret-password`, path: ".env"},
				// one-word defaults plus digits in test and doc files (elsewhere
				// they are reported at low: TestDefaultPasswordsReportedLow)
				{line: `password: 'admin123'`, path: "test/e2e.js"},
				{line: `final String password = "pass123";`, path: "src/test/java/A.java"},
				{line: `MYSQL_ROOT_PASSWORD: root123`, path: "README.md"},
				{line: `SentinelPassword: "abc123",`, path: "a_test.go"},
				{line: `password: 'testpwd1',`, path: "spec.js"},
				{line: `token := "my-s3cr3t-t0ken" // fake`, path: "a.go"},
				{line: `password = "SuperSecretPassw0rd"`},
				{line: `target_pass: SECRET_ACCESS_KEY`, path: "conf.yml"},
				{line: `const pw = "p@ssw0rd!";`, path: "a.js"},
			},
			borderline: []filterCase{
				// Known remaining false positives: words that are not placeholder
				// vocabulary on their own.
				{line: `const string expectedAccessToken2 = "LET_ME_IN-2";`, path: "a.cs", want: true},
				{line: `POSTGRES_PASSWORD: grafanatest`, path: "values.yaml", want: true},
				// Canonical default passwords are reported (low) in a real .env file.
				{line: "ADMIN_PASSWORD=admin123", path: ".env", want: true},
			},
		},
		"echoes-key-name": {
			keep:   []filterCase{{line: `basicAuthPassword: ` + low(4) + `_` + low(5), path: "values.yaml"}},
			reject: []filterCase{{line: `basicAuthPassword: basic_auth_password`, path: "values.yaml"}},
		},
		"url-placeholders": {
			keep: []filterCase{
				{line: `DATABASE_URL=postgres://app:` + rnd(16) + `@db.internal.corp:5432/app`, path: "deploy.sh"},
				{line: `url = "postgres://postgres:` + rnd(12) + `@localhost:5432/app"`},
			},
			reject: []filterCase{
				{line: `url = "postgres://postgres:postgres@postgres:5432/app_test"`},
				{line: `NewClient(SetURL("http://no-such-user:invalid-password@127.0.0.1:9210"))`, path: "a.go"},
				{line: `u, _ := url.Parse("socks5://hello:world@10.0.0.10:3128")`, path: "a.go"},
				{line: `url = "postgres://user:` + rnd(12) + `@db.example.com/app"`},
			},
		},
		"hash-of-credential": {
			keep: []filterCase{
				{line: `auth_token = "` + g(hexs, 64) + `"`},
				{line: `hash_secret = "` + rnd(32) + `"`}, // a secret used for hashing is still a secret
			},
			reject: []filterCase{
				{line: `"password_hash": "` + g(hexs, 64) + `"`, path: "a.json"},
				{line: `AuthConfigHash: "` + g(hexs, 64) + `",`, path: "a.go"},
				{line: `'_auth_user_hash': '` + g(hexs, 40) + `',`, path: "s.py"},
				{line: `op.reg.apiAccessTokenSHA256=` + g(hexs, 64), path: "a.properties"},
				{line: `SECRET_HASH = "` + rnd(43) + `="`},
			},
		},
		"public-key-token": {
			keep:   []filterCase{{line: `PrivateKeyToken="` + g(hexs, 16) + g(alnum, 8) + `"`, path: "a.config"}},
			reject: []filterCase{{line: `<assembly name="System.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=` + g(hexs, 16) + `" />`, path: "Form1.resx"}},
		},
		"ui-text": {
			keep: []filterCase{
				{line: `"LABEL_PASSWORD": "` + low(5) + "7" + low(3) + `",`, path: "en.json"}, // digits: not a label
				{line: `"ADMIN_PASSWORD": "` + low(9) + `",`, path: "conf.json"},              // not a UI key
			},
			reject: []filterCase{
				{line: `"LABEL_PASSWORD": "Kodeord",`, path: "da.json"},
				{line: `"SHOW_PASSWORD_ADVICE": "Wachtwoordadvies tonen",`, path: "nl.json"},
				{line: `'labelPassword': 'Mot de passe:',`, path: "fr.js"},
			},
		},
		"localized-text": {
			keep:   []filterCase{{line: `password = "` + rnd(10) + `é"`}},
			reject: []filterCase{{line: `"MANDATORY_PASSWORD": "パスワードを入力してください",`, path: "ja.json"}, {line: `"pwd": "Пароль",`, path: "ru.json"}},
		},
		"algorithm-name": {
			reject: []filterCase{{line: `config.Password.Algorithm = "sha512"`, path: "a.go"}, {line: `MAILU_PASSWORD_SCHEME=SHA512-CRYPT`, path: ".env"}},
		},
		"oid-bytes-or-version": {
			keep:   []filterCase{{line: `password = "1.3.` + rnd(8) + `"`}},
			reject: []filterCase{{line: `passwordModifyOID = "1.3.6.1.4.1.4203.1.11.1"`, path: "a.go"}, {line: `OBJ_userPassword="\x55\x04\x23"`, path: "obj.h"}, {line: `"parse-passwd": "^1.0.0"`, path: "package.json"}},
		},
		"test-vector-name": {
			keep: []filterCase{
				{line: "Key = " + g(hexs, 32), path: "test/evpkdf.txt"},
				{line: `license_key = "x7k2-9fj3-qq81-z0pa"`},
				{line: `api_key = "k2f-dsa-9xq-` + rnd(6) + `"`}, // one role word among random groups
			},
			reject: []filterCase{
				{line: "PrivateKey=KAS-ECC-CDH_P-192_C8", path: "evppkey_ecc.txt"},
				{line: "PeerKey=ALICE_cf_sect193r1_PUB", path: "evppkey_ecc.txt"},
				{line: "Key = ED448-1-PUBLIC", path: "evppkey.txt"},
				{line: "PrivateKey=BOB_cf_c2tnb431r1", path: "evppkey_ecc.txt"},
				{line: "PrivateKey=RSA-OAEP-10", path: "evppkey_rsa.txt"},
			},
		},
		"patterned-hex": {
			keep: []filterCase{{line: "Key = " + g(hexs, 64), path: "test/evpciph.txt"}, {line: `secret_key = "` + g(hexs, 32) + `"`}},
			reject: []filterCase{
				{line: "Key = 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", path: "evpmac.txt"},
				{line: "Key = 00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff", path: "evpciph.txt"},
				{line: "Key = 7f7e7d7c7b7a79787776757473727170404142434445464748494a4b4c4d4e4f", path: "evpciph.txt"},
				{line: "Key = ef012345ef012345ef012345ef012345", path: "evpciph.txt"},
			},
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
				t.Errorf("%s must KEEP %q (%s)", name, c.line, c.path)
			}
		}
		for _, c := range f.reject {
			if reported(d, c) {
				t.Errorf("%s must REJECT %q (%s)", name, c.line, c.path)
			}
		}
		for _, c := range f.borderline {
			if got := reported(d, c); got != c.want {
				t.Errorf("%s borderline changed for %q: reported=%v (was %v)", name, c.line, got, c.want)
			}
		}
	}
}

// Dropped placeholders are explained in the ledger, never silently.
func TestDummyValuesInLedger(t *testing.T) {
	cfg, _, _ := config.Resolve(config.Options{})
	rs, _ := config.Compile(cfg)
	d := detect.New(rs, detect.Options{RecordSuppressed: true})
	res := d.Scan(detect.Fragment{Raw: "password: some_password\nADMIN_PASSWORD: admin123\n", FilePath: "test/values.yaml"})
	if len(res.Findings) != 0 {
		t.Fatalf("placeholders reported: %v", ids(res.Findings))
	}
	lines := map[int]string{}
	for _, s := range res.Suppressed {
		lines[s.StartLine] = s.Reason
	}
	if lines[1] != "placeholder-vocabulary" || lines[2] != detect.DefaultPasswordReason {
		t.Errorf("ledger: %+v", res.Suppressed)
	}
}

// Random passwords that happen to contain one vocabulary word (and leet
// digits), and short random lowercase passwords like CredData's stand-ins,
// must never be classified as placeholders.
func TestPlaceholderVocabularySparesRandomPasswords(t *testing.T) {
	if testing.Short() || raceEnabled {
		t.Skip("statistical")
	}
	cfg, _, _ := config.Resolve(config.Options{})
	rs, _ := config.Compile(cfg)
	d := detect.New(rs, detect.Options{RecordSuppressed: true})
	words := []string{"password", "admin", "test", "secret", "root", "dev", "db", "my", "key", "token", "foo", "abc", "local", "postgres"}
	seps := []string{"", "", "-", "_", "@", "1", "3"}
	gens := []struct {
		name string
		gen  func(i int) string
	}{
		{"vocab-adjacent", func(i int) string {
			w := words[i%len(words)]
			if i%3 == 0 {
				w = strings.ToUpper(w[:1]) + w[1:]
			}
			return g(alnum, 3+i%6) + seps[i%len(seps)] + w + seps[(i/7)%len(seps)] + g(alnum+"!#%", 3+(i/3)%6)
		}},
		{"lower 6-10", func(i int) string { return g("abcdefghijklmnopqrstuvwxyz", 6+i%5) }},
		{"lower+digits 6-10", func(i int) string { return g("abcdefghijklmnopqrstuvwxyz", 4+i%5) + g("0123456789", 1+i%3) }},
		{"leet-ish 8-12", func(i int) string { return g("abcdefghijklmnopqrstuvwxyz013457@$", 8+i%5) }},
	}
	n := 50000
	for _, gg := range gens {
		lost := map[string]int{}
		var ex []string
		for i := 0; i < n; i++ {
			v := gg.gen(i)
			res := d.Scan(detect.Fragment{Raw: `db_password = "` + v + `"`, FilePath: "src/app.py"})
			for _, s := range res.Suppressed {
				switch s.Reason {
				case "placeholder-vocabulary", "echoes-key-name", "ui-text", "localized-text":
					lost[s.Reason]++
					if len(ex) < 5 {
						ex = append(ex, v)
					}
				}
			}
		}
		total := 0
		for _, c := range lost {
			total += c
		}
		t.Logf("%s: %d/%d classified as placeholders %v %v", gg.name, total, n, lost, ex)
		if float64(total)/float64(n) > 0.0002 {
			t.Errorf("%s: %d/%d random passwords classified as placeholders %v, e.g. %v", gg.name, total, n, lost, ex)
		}
	}
}

func TestLocalAndExampleContext(t *testing.T) {
	d := defaultDetector(t, 0)
	pw := g(alnum, 14)
	cases := []struct {
		line, path, ctx string
	}{
		{`url = "postgres://app:` + pw + `@localhost:5432/app"`, "src/settings.py", detect.ContextLocal},
		{`url = "postgres://app:` + pw + `@127.0.0.1:5432/app"`, "src/settings.py", detect.ContextLocal},
		{`url = "amqp://app:` + pw + `@rabbitmq:5672/"`, "src/settings.py", detect.ContextLocal},
		{`url = "mysql://app:` + pw + `@192.168.1.20/app"`, "src/settings.py", detect.ContextLocal},
		{`url = "mysql://app:` + pw + `@dev.local/app"`, "src/settings.py", detect.ContextLocal},
		{"      POSTGRES_PASSWORD: " + pw, "docker-compose.yml", detect.ContextLocal},
		{"      POSTGRES_PASSWORD: " + pw, "deploy/compose.dev.yaml", detect.ContextLocal},
		{"DB_PASSWORD=" + pw, ".env.example", detect.ContextExample},
		{"DB_PASSWORD=" + pw, ".env.test", detect.ContextLocal},
		{`"ConnectionString": "Server=localhost;Database=app;User Id=sa;Password=` + pw + `;"`, "appsettings.json", detect.ContextLocal},
		// not local
		{`url = "postgres://app:` + pw + `@db.prod.corp.net:5432/app"`, "src/settings.py", ""},
		{`url = "postgres://app:` + pw + `@8.8.8.8:5432/app"`, "src/settings.py", ""},
		{"DB_PASSWORD=" + pw, ".env", ""},
		{"DB_PASSWORD=" + pw, ".env.production", ""},
	}
	for _, c := range cases {
		fs := d.Detect(detect.Fragment{Raw: c.line, FilePath: c.path})
		if len(fs) == 0 {
			t.Errorf("%s %q: not reported", c.path, c.line)
			continue
		}
		for _, f := range fs {
			if f.Context != c.ctx {
				t.Errorf("%s %q (%s): context %q, want %q", c.path, c.line, f.RuleID, f.Context, c.ctx)
			}
			if c.ctx != "" && (f.Confidence != detect.Low || !strings.HasPrefix(f.Evidence[len(f.Evidence)-1], detect.ContextCapPrefix)) {
				t.Errorf("%s: local/example not capped at low with evidence: %+v", c.path, f)
			}
		}
	}
	// Documentation hosts are still dropped.
	for _, line := range []string{`url = "postgres://app:` + pw + `@db.example.com/app"`, `url = "postgres://app:` + pw + `@hostname:5432/app"`} {
		if fs := d.Detect(detect.Fragment{Raw: line, FilePath: "README.md"}); len(fs) > 0 {
			t.Errorf("doc host reported: %q %v", line, ids(fs))
		}
	}
	// Provider formats never get a context or a cap.
	tok := "ghp_" + g(alnum, 36)
	f := findingFor(d.Detect(detect.Fragment{Raw: "      GITHUB_TOKEN: " + tok, FilePath: "docker-compose.yml"}), "github-pat")
	if f == nil || f.Context != "" || f.Confidence != detect.High {
		t.Errorf("provider token in compose file: %+v", f)
	}
}

func TestContextPolicy(t *testing.T) {
	local := detect.Finding{Confidence: detect.Low, Context: detect.ContextLocal, Evidence: []string{detect.FixtureCap, detect.ContextCapPrefix + "x"}}
	fixture := detect.Finding{Confidence: detect.Low, Evidence: []string{detect.FixtureCap}}
	for _, c := range []struct {
		policy, fixtures string
		f                detect.Finding
		want             bool
	}{
		{"balanced", "block", local, false},
		{"balanced", "review", local, false},
		{"strict", "block", local, true},
		{"strict", "review", local, true},
		{"balanced", "block", fixture, true}, // testFixtures semantics unchanged
		{"balanced", "review", fixture, false},
	} {
		if got := detect.BlocksFinding(c.policy, c.fixtures, c.f); got != c.want {
			t.Errorf("%s/%s %+v: blocks=%v want %v", c.policy, c.fixtures, c.f, got, c.want)
		}
	}
}
