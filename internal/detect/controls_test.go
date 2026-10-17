// SPDX-License-Identifier: Apache-2.0

package detect_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/AISolutionLabs/secret-scanner/internal/config"
	"github.com/AISolutionLabs/secret-scanner/internal/detect"
)

// Every noise filter needs positive controls.
//
// TestEveryFilterHasPositiveControls reads this package's source for every
// suppression reason it can emit and requires, for each one:
//
//	fire  an input the filter removes, with exactly this reason (proves the
//	      control is aimed at this filter, not passing by accident)
//	keep  at least one realistic secret in the same domain that must survive
//	pinned (optional) real-looking secrets the filter does remove: known,
//	      documented trade-offs (docs/precision.md), pinned so they cannot
//	      grow silently
//
// A new filter fails this test until it has controls.

type channel int

const (
	scan     channel = iota // Detector.Scan: findings and the suppression ledger
	noise                   // NoiseReason, used by triage on other tools' values
	embedded                // EmbeddedReason, used by triage
)

type probe struct {
	ch     channel
	line   string // scan: the fragment; embedded: the line
	path   string
	secret string // noise / embedded: the value
	quoted bool   // noise
}

// scv is a scan probe whose fragment has several values: only want is judged.
func scv(line, path, want string) probe {
	return probe{ch: scan, line: line, path: path, secret: want}
}

func sc(line string, path ...string) probe {
	p := probe{ch: scan, line: line, path: "src/settings.py"}
	if len(path) > 0 {
		p.path = path[0]
	}
	return p
}
func nz(secret string, quoted bool, path string) probe {
	return probe{ch: noise, secret: secret, quoted: quoted, path: path}
}
func em(line, secret string) probe { return probe{ch: embedded, line: line, secret: secret} }

type controls struct {
	fire   probe
	keep   []probe
	pinned []probe
}

// reasonsInSource returns every suppression reason the package can emit:
// returned reason-shaped literals, dropIt("...") arguments and string
// constants named *Reason.
func reasonsInSource(t *testing.T) map[string]string {
	t.Helper()
	fset := token.NewFileSet()
	pkgs, err := parser.ParseDir(fset, ".", func(fi os.FileInfo) bool { return !strings.HasSuffix(fi.Name(), "_test.go") }, 0)
	if err != nil {
		t.Fatal(err)
	}
	reasonShape := regexp.MustCompile(`^[a-z][a-z0-9=]*(-[a-z0-9=]+)*$`)
	out := map[string]string{}
	lit := func(e ast.Expr) (string, bool) {
		bl, ok := e.(*ast.BasicLit)
		if !ok || bl.Kind != token.STRING {
			return "", false
		}
		s, err := strconv.Unquote(bl.Value)
		return s, err == nil
	}
	for _, p := range pkgs {
		for _, f := range p.Files {
			ast.Inspect(f, func(n ast.Node) bool {
				switch x := n.(type) {
				case *ast.ReturnStmt:
					for _, e := range x.Results {
						if s, ok := lit(e); ok && reasonShape.MatchString(s) {
							out[s] = fset.Position(e.Pos()).String()
						}
					}
				case *ast.CallExpr:
					if id, ok := x.Fun.(*ast.Ident); ok && id.Name == "dropIt" && len(x.Args) == 1 {
						if s, ok := lit(x.Args[0]); ok {
							out[s] = fset.Position(x.Pos()).String()
						}
					}
				case *ast.ValueSpec:
					for i, name := range x.Names {
						if strings.HasSuffix(name.Name, "Reason") && i < len(x.Values) {
							if s, ok := lit(x.Values[i]); ok {
								out[s] = fset.Position(name.Pos()).String()
							}
						}
					}
				}
				return true
			})
		}
	}
	// Allowlist reasons are computed ("allowlist: <description>").
	out["allowlist"] = "detect.go: allowed()"
	return out
}

func filterControls() map[string]controls {
	rnd := func(n int) string { return g(alnum, n) }
	tok := "ghp_" + rnd(36)
	b32 := "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
	return map[string]controls{
		"word-like": {fire: sc(`auth_provider = "SecurityProfiles"`),
			keep: []probe{sc(`api_secret = "xK9mPasswordQ7zL2vN8wR"`), sc(`token = "aSecretTokenValue9x7Kq2LmN4"`)}},
		"camel-case-identifier": {fire: sc(`"downward_api": "V1DownwardAPIProjection",`),
			keep: []probe{sc(`api_secret = "AbqzXyvwKjhpTrmn9Q"`)}},
		"identifier": {fire: sc(`key := crypto.SHA256`, "main.go"),
			keep: []probe{sc(`api_secret = "MIVWdsoNuhGuoNge7Kx"`), sc("Key = "+g(hexs, 32), "test/kdf.txt")}},
		"uuid": {fire: sc(`request_token = "` + uuid() + `"`),
			keep: []probe{sc("HEROKU_API_KEY="+uuid(), ".env"), sc(`api_secret = "` + uuid() + `"`)}},
		"number-or-date": {fire: sc(`api_key = "1234567890123456789012345"`),
			keep: []probe{sc(`api_secret = "20240101aBcD9xYzQ7"`)}},
		"key=value-pair": {fire: sc(`endpoint_auth: "Region=eu-west-1"`),
			keep: []probe{sc(`client_secret = "d8ZJUhe2xp+U3TnFoLuTW2k+L74Brz8Hy=="`)}},
		"truncated-example": {fire: nz("sk_live_abc123...xyz", true, "src/app.py"),
			keep: []probe{nz(rnd(24), true, "src/app.py")}},
		"word-segments": {fire: sc(`OAUTH_API_BETA_HEADER = "oauth-2025-04-20"`),
			keep: []probe{sc(`license_key = "x7k2-9fj3-qq81-z0pa"`), sc(`api_key = "QX7V2-3OFV9-VV1UB-NKT0I"`)}},
		"test-vector-name": {fire: sc("PrivateKey=KAS-ECC-CDH_P-192_C8", "evppkey_ecc.txt"),
			keep: []probe{sc(`api_key = "k2f-dsa-9xq-` + rnd(6) + `"`), sc("Key = "+g(hexs, 32), "test/evpkdf.txt")}},
		"patterned-hex": {fire: sc("Key = 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", "evpmac.txt"),
			keep: []probe{sc("Key = "+g(hexs, 64), "test/evpciph.txt"), sc(`secret_key = "` + g(hexs, 32) + `"`)}},
		"single-case-letters": {fire: nz("SOMECONSTANT", true, "src/app.py"),
			keep: []probe{sc(`api_secret = "qzvxkwplmrtbnhgdfsyc7"`), sc(`api_secret = "qzvxkwplmrtbnhgdfsyc"`)}},
		"word-tokens": {fire: sc(`auth_score = weight*factor+bias_offset9`, "model.py"),
			keep: []probe{sc(`api_secret = "KeyQx7mVaultZp2Lw9TokenRb"`), sc(`client_secret = "dataTq8ZmXkWv2PbNs4c"`), sc(`db_password = "MySecretToken2024!x"`)},
			// Known trade-off: a human-chosen secret made of words plus a year
			// under a generic key is read as an identifier. Password keys keep
			// it (above). docs/precision.md.
			pinned: []probe{sc(`api_secret = "MySecretToken2024!x"`)}},
		"string-concatenation": {fire: sc(`html += ' key="'+value1.key+'"'`, "runtime.dev.js"),
			keep: []probe{sc(`api_secret = "+Kq9Zx7mVwP2bN4+Lx"`)}},
		"email-address": {fire: sc(`__author_email__ = "me@kennethreitz.org"`, "__version__.py"),
			keep: []probe{sc(`password = "Kq9@Zx7mN2pQ.v"`)}},
		"dotted-namespace": {fire: nz("core.core2.js", true, "src/app.py"),
			keep: []probe{sc(`api_secret = "Ab3.Kq9.Zx7mN2pQ"`)}},
		"credential-name": {fire: nz("inf-vsqt-01-secret-id", true, "src/app.py"),
			keep: []probe{sc(`api_secret = "` + rnd(6) + "-" + rnd(6) + "-" + rnd(6) + `"`)}},
		"stopword": {fire: nz("core-config2-js", true, "src/app.py"),
			keep: []probe{sc(`token = "aSecretTokenValue9x7Kq2LmN4"`), sc(`api_secret = "Kq9SecretZx7mVwP2bN4"`)}},
		"digit-free-name-or-path": {fire: nz("core/core/js", true, "src/app.py"),
			keep: []probe{sc(`api_secret = "qzvxkwplmrtbnhgdfsyc"`)}},
		"operator-in-code": {fire: nz("Wq8*Zk2+Lm9x", false, "model.py"),
			keep: []probe{sc(`password = "Wuy8vDv-a*+Q7Xtzp8+"`), sc("ADMIN_PASSWORD=Wuy8vDv-a*+Q7Xtzp8+", ".env")}},
		"known-public-example": {fire: sc("aws_access_key_id = AKIAIOSFODNN7EXAMPLE", "c.env"),
			keep: []probe{sc("aws_access_key_id = AKIA"+g(b32, 16), "c.env")}},
		"sequential-or-decoded-prose": {fire: sc(`api_secret = "abcdefghijklmnopqrstuvwxyz"`),
			keep: []probe{sc(`api_secret = "` + rnd(26) + `"`)}},
		"low-entropy": {fire: nz("corees7es7", true, "src/app.py"),
			keep: []probe{nz(rnd(20), true, "src/app.py")}},
		"digest-or-commit-hash": {fire: em("image: reg.io/x@sha256:eaaa7b11777babe28e6133a8b19ff71cea687e0d7f05158dee95a71f76ce3d00", "EAAA7b11777babe28e6133a8b19ff71cea687e0d7f05158dee95a71f76ce3d"), // secretscan:allow (gitleaks#1468 fixture)
			keep: []probe{em(`gh = "`+tok+`"`, tok), em("GITHUB_TOKEN="+tok, tok)}},
		"embedded-in-longer-token": {fire: em("payload=ZXlKaGJHY2lPaUpJVXpJMU5pSjkuZXlKemRXSWlPaUl4TWpNME5UWTNPRGt3SW4w", "aGJHY2lPaUpJVXpJMU5pSjkuZXlK"),
			keep: []probe{em(`token: "`+tok+`"`, tok)}},
		"echoes-key-name": {fire: sc(`"webhookKey": "my_webhookKey",`, "v1.d.ts"),
			keep: []probe{sc(`"webhookKey": "my_Kq9Zx7mVwP2bN4"`, "v1.d.ts"), sc(`basicAuthPassword: `+g("abcdefghijklmnopqrstuvwxyz", 4)+"_"+g("abcdefghijklmnopqrstuvwxyz", 5), "values.yaml")}},
		"placeholder-vocabulary": {fire: sc(`password = "changeme"`),
			keep: []probe{sc(`db_password = "Tr0ub4dor&3"`), sc(`db_password = "` + rnd(4) + "password" + rnd(4) + `"`), sc(`db_password = "SuperSecretPassword2024"`)}},
		"placeholder-password": {fire: sc(`password = "Mot de passe"`),
			keep: []probe{sc(`password: "Winter2026!"`), sc(`db_password = "s00pers3cret"`)}},
		detect.DefaultPasswordReason: {fire: sc(`password = "Welcome@2024"`, "tests/test_db.py"),
			keep: []probe{sc(`password = "Welcome@2024"`), sc(`password = "`+rnd(14)+`"`, "tests/test_db.py")}},
		"user-equals-password": {fire: sc(`url = "postgres://admin:admin@db.prod.example.com/app"`),
			keep: []probe{sc("DATABASE_URL=postgres://app:"+rnd(16)+"@db.internal.corp:5432/app", "deploy.sh")}},
		"hash-of-credential": {fire: sc(`password_hash = "` + g(hexs, 32) + `"`),
			keep: []probe{sc(`hash_secret = "` + rnd(32) + `"`), sc(`auth_token = "` + g(hexs, 64) + `"`)}},
		"public-key-token": {fire: sc(`PublicKeyToken = "` + g(hexs, 16) + `"`),
			keep: []probe{sc(`PrivateKeyToken="`+g(hexs, 16)+rnd(8)+`"`, "a.config")}},
		"ui-text": {fire: sc(`password_label = "Enter your password"`),
			keep: []probe{sc(`"LABEL_PASSWORD": "abcde7fgh",`, "en.json"), sc(`"ADMIN_PASSWORD": "`+g("abcdefghijklmnopqrstuvwxyz", 9)+`",`, "conf.json")}},
		"localized-text": {fire: sc(`"pwd": "Пароль",`, "ru.json"),
			keep: []probe{sc(`password = "` + rnd(10) + `é"`)}},
		"algorithm-name": {fire: sc(`config.Password.Algorithm = "sha512"`, "a.go"),
			keep: []probe{func() probe { s := rnd(32); return scv("jwt_algorithm: HS256\njwt_secret: "+s, "config.yml", s) }(),
				func() probe { s := rnd(18); return scv("PASSWORD_SCHEME=SHA512-CRYPT\nADMIN_PASSWORD="+s, ".env", s) }()},
			// Known trade-off: the key alone decides, so a random value under an
			// *_algorithm/_scheme/_cipher key is dropped. docs/precision.md.
			pinned: []probe{sc(`password_algorithm = "` + rnd(19) + `"`)}},
		"oid-bytes-or-version": {fire: sc(`passwordModifyOID = "1.3.6.1.4.1.4203.1.11.1"`, "a.go"),
			keep: []probe{sc(`password = "1.3.` + rnd(8) + `"`)}},
		"allowlist": {fire: sc(`token_url_name = "base64url-decode-v2"`),
			keep: []probe{sc(`public_key_id = "` + tok + `"`), sc("AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\nGITHUB_TOKEN="+tok, "deploy.env")}},
	}
}

// outcome runs a probe and returns (kept, reasons that fired).
func outcome(d *detect.Detector, p probe) (bool, []string) {
	switch p.ch {
	case noise:
		r := detect.NoiseReason(p.secret, p.quoted, p.path)
		return r == "", []string{r}
	case embedded:
		r := detect.EmbeddedReason(p.line, p.secret)
		return r == "", []string{r}
	}
	res := d.Scan(detect.Fragment{Raw: p.line, FilePath: p.path, StartLine: 1})
	if p.secret != "" { // judge only the named value
		kept := false
		for _, f := range res.Findings {
			kept = kept || f.Secret == p.secret
		}
		var rs []string
		for _, s := range res.Suppressed {
			if s.Secret == p.secret {
				rs = append(rs, s.Reason)
			}
		}
		return kept, rs
	}
	var rs []string
	for _, s := range res.Suppressed {
		r := s.Reason
		if strings.HasPrefix(r, "allowlist:") {
			r = "allowlist"
		}
		rs = append(rs, r)
	}
	return len(res.Findings) > 0, rs
}

func TestEveryFilterHasPositiveControls(t *testing.T) {
	cfg, _, _ := config.Resolve(config.Options{})
	rs, _ := config.Compile(cfg)
	d := detect.New(rs, detect.Options{MaxDecodeDepth: 2, RecordSuppressed: true})
	src := reasonsInSource(t)
	ctl := filterControls()
	var names []string
	for r := range src {
		names = append(names, r)
	}
	sort.Strings(names)
	for _, r := range names {
		c, ok := ctl[r]
		if !ok {
			t.Errorf("filter reason %q (%s) has no positive controls: add a fire case and keep cases to filterControls", r, src[r])
			continue
		}
		if len(c.keep) == 0 {
			t.Errorf("%s: no keep case (a realistic secret the filter must not remove)", r)
		}
		if _, fired := outcome(d, c.fire); !contains(fired, r) {
			t.Errorf("%s: fire case is not removed by this filter (reasons %v): %q", r, fired, c.fire.line+c.fire.secret)
		}
		for _, k := range c.keep {
			kept, fired := outcome(d, k)
			if !kept || contains(fired, r) {
				t.Errorf("%s must keep %q (%s): kept=%v reasons=%v", r, k.line+k.secret, k.path, kept, fired)
			}
		}
		for _, p := range c.pinned {
			if _, fired := outcome(d, p); !contains(fired, r) {
				t.Errorf("%s: pinned trade-off changed for %q (no longer removed); update docs/precision.md", r, p.line)
			}
		}
	}
	for r := range ctl {
		if _, ok := src[r]; !ok {
			t.Errorf("controls for %q, which no filter emits any more: remove them", r)
		}
	}
	if len(names) < 35 {
		t.Fatalf("found only %d filter reasons in the source; the collector is broken", len(names))
	}
}

func contains(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}
