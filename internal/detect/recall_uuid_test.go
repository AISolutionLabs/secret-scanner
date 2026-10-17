// SPDX-License-Identifier: Apache-2.0

package detect_test

import (
	"testing"

	"github.com/AISolutionLabs/secret-scanner/internal/detect"
)

// UUID-shaped values: reported (low) under credential-named keys, dropped
// under request/correlation/concurrency-style keys.
func TestUUIDUnderCredentialKeys(t *testing.T) {
	d := defaultDetector(t, 0)
	type c struct {
		line string
		want bool
		why  string
	}
	u := uuid()
	U := "A26D554F-BFE6-9F69-02B8-E6814F86922D" // secretscan:allow (fixture: upper-case UUID shape)
	for _, x := range []c{
		// must catch (credential-named keys)
		{line: `"access_token": "` + u + `",`, want: true},
		{line: `secretVal := "` + u + `"`, want: true},
		{line: `const key = "` + U + `"`, want: true},
		{line: `private static final String REFRESH_TOKEN = "` + u + `";`, want: true},
		{line: `"identitytoken": "` + u + `"`, want: true},
		{line: `api_secret = "` + u + `"`, want: true},
		{line: `password: ` + u, want: true},
		// must not catch (identifier-style keys)
		{line: `"request_token": "` + u + `"`, want: false},
		{line: `"clientRequestToken": "` + u + `",`, want: false},
		{line: `"idempotency_key": "` + u + `"`, want: false},
		{line: `"ChangeToken": "` + u + `",`, want: false, why: "AWS WAF concurrency token: grants no access"},
		{line: `"NextToken": "` + u + `"`, want: false},
		{line: `"SyncToken": "` + u + `"`, want: false},
		{line: `csrf_token = "` + u + `"`, want: false},
		{line: `"keyId": "` + u + `"`, want: false},
		{line: `secret_id = "` + u + `"`, want: false},
		{line: `"correlationId": "` + u + `"`, want: false},
		{line: `"traceId": "` + u + `"`, want: false},
		{line: `"subscription_key_id": "` + u + `"`, want: false},
		{line: `"id": "` + u + `"`, want: false},
		{line: `"user": "` + u + `"`, want: false},
		// borderline (pinned)
		{line: `"session_token": "` + u + `"`, want: true,
			why: "session tokens authenticate; only session_id is identifier-style"},
		{line: `prevKey = "` + U + `"`, want: false,
			why: "the name allowlist reads prev/next + key as a paging marker; rotation fixtures (CredData) are knowingly missed"},
		{line: `"tenant_secret": "` + u + `"`, want: false,
			why: "request-style words (tenant, subscription, resource) win over credential words: a deliberate precision bias"},
	} {
		fs := d.Detect(detect.Fragment{Raw: x.line, FilePath: "src/app.json"})
		got := has(fs, "generic-api-key")
		if got != x.want {
			t.Errorf("want reported=%v got %v (%v) for %q %s", x.want, got, ids(fs), x.line, x.why)
			continue
		}
		if got {
			for _, f := range fs {
				if f.RuleID == "generic-api-key" && f.Confidence != detect.Low {
					t.Errorf("UUID under credential key must be low confidence, got %s for %q", f.Confidence, x.line)
				}
			}
		}
	}
}
