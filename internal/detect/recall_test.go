// SPDX-License-Identifier: Apache-2.0

package detect_test

import (
	"encoding/base64"
	"testing"

	"github.com/AISolutionLabs/secret-scanner/internal/config"
	"github.com/AISolutionLabs/secret-scanner/internal/detect"
)

// Recall rules are tested in three directions: credentials the rule must
// catch, look-alikes it must not, and borderline cases whose current
// behaviour is pinned (with the reason) so a change to them is deliberate.

type recallCase struct {
	text, path string
	want       bool   // reported by rule
	why        string // borderline cases: why this is the intended outcome
}

func checkRule(t *testing.T, rule string, cases []recallCase) {
	t.Helper()
	d := defaultDetector(t, 0)
	for _, c := range cases {
		path := c.path
		if path == "" {
			path = "src/client.py"
		}
		fs := d.Detect(detect.Fragment{Raw: c.text, FilePath: path, StartLine: 1})
		if got := has(fs, rule); got != c.want {
			t.Errorf("%s: want reported=%v, got %v (%v) on %q %s", rule, c.want, got, ids(fs), c.text, c.why)
		}
	}
}

func b64(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }

func TestValidatorsMatchConfig(t *testing.T) {
	names := detect.ValidatorNames()
	if len(names) != len(config.Validators) {
		t.Fatalf("detect implements %v, config declares %v", names, config.Validators)
	}
	for _, n := range names {
		if !config.Validators[n] {
			t.Errorf("validator %q not declared in config.Validators", n)
		}
	}
}

func TestHTTPBasicAuth(t *testing.T) {
	cred := b64("svc_" + g2(lowAln, 5) + ":" + g2(alnum, 16))
	unpadded := b64("ab:" + g2(alnum, 11)) // 14 bytes -> padded; strip below
	for len(unpadded) > 0 && unpadded[len(unpadded)-1] == '=' {
		unpadded = unpadded[:len(unpadded)-1]
	}
	checkRule(t, "http-basic-auth", []recallCase{
		// must catch
		{text: `Authorization: Basic ` + cred, path: "docs/api.md", want: true},
		{text: `req.Header.Set("Proxy-Authorization", "Basic ` + cred + `")`, path: "proxy.go", want: true},
		{text: `headers: { Authorization: "Basic ` + cred + `" } # test_user`, path: "rest/10_basic.yml", want: true},
		{text: `{"key": "Authorization", "value": "Basic ` + cred + `"}`, path: "collection.json", want: true},
		{text: `conn.request("GET", "/", headers={"Authorization": b"Basic ` + cred + `"})`, want: true},
		{text: `curl -H 'authorization: basic ` + cred + `' https://h`, path: "run.sh", want: true},
		{text: `Authorization: Basic ` + unpadded, path: "a.http", want: true},
		// must not catch
		{text: `Authorization: Basic ` + b64(g2(alnum, 24)), want: false},                                                            // no user:password inside
		{text: `Authorization: Basic ` + base64.StdEncoding.EncodeToString([]byte{0, 1, 0xfe, ':', 0x9c, 7, 8, 9, 10}), want: false}, // binary
		{text: `Authorization: Basic ` + b64("user:password"), want: false},                                                          // placeholder pair
		{text: `Authorization: Basic ` + b64("admin:<password>"), want: false},                                                       // template
		{text: `Authorization: Basic ` + b64("deploy:${DEPLOY_PASSWORD}"), want: false},                                              // template
		{text: `Authorization: Basic ` + b64(":"+g2(alnum, 12)), want: false},                                                        // empty user
		{text: `Authorization: Basic ` + b64(g2(alnum, 8)+":"), want: false},                                                         // empty password
		{text: `headers["Authorization"] = "Basic " + base64(user + ":" + pw)`, want: false},                                         // built at runtime
		{text: `Authorization: Basic ${CREDENTIALS}`, want: false},
		{text: `Authorization: Basic <base64(user:pass)>`, want: false},
		{text: "X509v3 Basic Constraints: critical", want: false},
		{text: `response = client.get("/", headers={"Authorization": "basic foobar"})`, want: false},
		// borderline (pinned)
		{text: `Authorization: Basic ` + b64("admin:admin"), want: true,
			why: "weak default credentials are still credentials; reported, confidence reflects the evidence"},
		{text: `Authorization: Basic ` + b64("CK:CS"), want: true,
			why: "short user:password decodes cleanly; length alone is not evidence of a placeholder"},
		{text: `Authorization: Basic ` + b64(g2(alnum, 8)+":"+g2(alnum, 8)) + `...`, want: false,
			why: "a value followed by ... is a truncated doc example, and the boundary rejects it"},
	})
}

func TestHTTPBearerToken(t *testing.T) {
	tok := g2(alnum, 40)
	checkRule(t, "http-bearer-token", []recallCase{
		// must catch
		{text: `curl -H "Authorization: Bearer ` + tok + `" https://h/api`, path: "docs/README.md", want: true},
		{text: `{"key": "Authorization", "value": "Bearer ` + tok + `"}`, path: "c.json", want: true},
		{text: `this.req.headers = { authorization: 'Bearer ` + tok + `' };`, path: "server.ts", want: true},
		{text: `"headers": "Authorization: Bearer ` + tok + `\n",`, path: "c.json", want: true},
		{text: `"expectedHeaders" => ["Authorization" => "Bearer ` + tok + `=",],`, path: "t.php", want: true},
		{text: `ab -c 10 -H "Authorization: Bearer ` + g2(lowAln, 16) + `"`, path: "bench.sh", want: true},
		// must not catch
		{text: `Authorization: Bearer ${token}`, want: false},
		{text: `Authorization: Bearer <access_token>`, want: false},
		{text: `Authorization: Bearer YOUR_ACCESS_TOKEN_HERE`, want: false},
		{text: `Authorization: Bearer xxxxxxxxxxxxxxxxxxxxxxxx`, want: false},
		{text: `Authorization: Bearer {{token}}`, want: false},
		{text: `headers["Authorization"] = f"Bearer {self.bearer_token}"`, want: false},
		{text: `req.Header.Set("Authorization", "Bearer "+accessToken)`, want: false},
		{text: `"Bearer authorization_uri=https://login.microsoftonline.com/tenant1"`, want: false},
		{text: `Authorization: Bearer someAccessTokenValue`, want: false}, // identifier
		{text: `Authorization: Bearer abcdefghijklmnop12`, want: false},   // keyboard run
		{text: `> Authorization: Bearer vp7jx...`, want: false},           // truncated
		{text: `"Authorization": "Bearer mF_9.B5f-4.1JqM"`, want: false},  // RFC 6750 example, 15 chars
		{text: `// SetAuthToken sets the bearer auth token header in the request`, want: false},
		{text: `"Authorization": "Bearer ` + b64("this token is only a unit test value!") + `"`, want: false}, // encoded prose
		// provider-shaped values are reported once, by the provider rule
		{text: `Authorization: Bearer ghp_` + g2(alnum, 36), want: false, why: "yields to github-pat"},
		// borderline (pinned)
		{text: `Authorization: Bearer ` + g2(lowAln, 15), want: false,
			why: "under 16 characters: too short to tell a token from a doc example"},
		{text: `Authorization: Bearer ` + uuid(), want: true,
			why: "a UUID after Bearer is an opaque access token (scheme context, not a key name)"},
	})
}
