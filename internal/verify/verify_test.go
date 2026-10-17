// SPDX-License-Identifier: Apache-2.0

package verify

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/AISolutionLabs/secret-scanner/internal/detect"
)

func TestVerifierStatuses(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		switch r.Header.Get("Authorization") {
		case "Bearer live":
			w.WriteHeader(200)
		case "Bearer dead":
			w.WriteHeader(401)
		default:
			w.WriteHeader(500)
		}
	}))
	defer srv.Close()
	slack := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "Bearer live" {
			w.Write([]byte(`{"ok":true}`))
			return
		}
		w.Write([]byte(`{"ok":false,"error":"invalid_auth"}`))
	}))
	defer slack.Close()

	saved := Checks
	defer func() { Checks = saved }()
	Checks = map[string]Check{
		"t":     {Method: "GET", URL: srv.URL, Header: bearer},
		"slack": {Method: "POST", URL: slack.URL, Header: bearer, Interpret: slackOK},
	}
	fs := []detect.Finding{
		{RuleID: "t", Secret: "live", SecretHash: "1"},
		{RuleID: "t", Secret: "dead", SecretHash: "2"},
		{RuleID: "t", Secret: "boom", SecretHash: "3"},
		{RuleID: "slack", Secret: "live", SecretHash: "4"},
		{RuleID: "slack", Secret: "nope", SecretHash: "5"},
		{RuleID: "no-verifier", Secret: "x", SecretHash: "6"},
	}
	New().Run(context.Background(), fs, 3)
	want := []string{Verified, Invalid, Unknown, Verified, Invalid, Unknown}
	for i, f := range fs {
		if f.Verification != want[i] {
			t.Errorf("finding %d: got %s want %s", i, f.Verification, want[i])
		}
	}
}

// A provider endpoint that redirects must not receive a second request
// elsewhere carrying the secret in a custom header.
func TestVerifierNeverFollowsRedirects(t *testing.T) {
	leaked := false
	elsewhere := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		leaked = r.Header.Get("X-Api-Key") != ""
		w.WriteHeader(200)
	}))
	defer elsewhere.Close()
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, elsewhere.URL, http.StatusFound)
	}))
	defer provider.Close()
	saved := Checks
	defer func() { Checks = saved }()
	Checks = map[string]Check{"k": {Method: "GET", URL: provider.URL, Header: func(s string) http.Header { return http.Header{"X-Api-Key": {s}} }}}
	fs := []detect.Finding{{RuleID: "k", Secret: "live", SecretHash: "1"}}
	New().Run(context.Background(), fs, 1)
	if leaked {
		t.Fatal("secret was forwarded to the redirect target")
	}
	if fs[0].Verification != Unknown {
		t.Errorf("redirect answer = %s, want %s", fs[0].Verification, Unknown)
	}
}

// Only an answer from the provider's API decides a status. Proxy block and
// caution pages (HTML 403 / 200), rate limits, server errors and network
// failures are never "verified" or "invalid", and a 401 from the public
// endpoint does not make a token of a self-managed instance (GitHub
// Enterprise Server, GitLab self-managed) invalid.
func TestVerifierOnlyTrustsProviderAnswers(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Header.Get("Authorization") {
		case "Bearer html200": // TLS-inspecting proxy "caution" page / captive portal
			w.Header().Set("Content-Type", "text/html")
			w.Write([]byte("<html>Continue to site</html>"))
		case "Bearer html403": // proxy block page
			w.Header().Set("Content-Type", "text/html")
			w.WriteHeader(403)
		case "Bearer json403": // authenticated, missing scope
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(403)
		case "Bearer rate":
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(429)
		case "Bearer down":
			w.WriteHeader(503)
		default:
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(401)
		}
	}))
	defer srv.Close()
	closed := httptest.NewServer(http.NotFoundHandler())
	closed.Close() // connection refused: a network failure
	saved := Checks
	defer func() { Checks = saved }()
	Checks = map[string]Check{
		"t":    {Method: "GET", URL: srv.URL, Header: bearer},
		"self": {Method: "GET", URL: srv.URL, Header: bearer, SelfHosted: true},
		"down": {Method: "GET", URL: closed.URL, Header: bearer},
	}
	cases := []struct{ rule, secret, want string }{
		{"t", "html200", Unknown},
		{"t", "html403", Unknown},
		{"t", "json403", Verified},
		{"t", "rate", Unknown},
		{"t", "down", Unknown},
		{"t", "bad", Invalid},
		{"self", "bad", Unknown},
		{"down", "x", Errored},
	}
	fs := make([]detect.Finding, len(cases))
	for i, c := range cases {
		fs[i] = detect.Finding{RuleID: c.rule, Secret: c.secret, SecretHash: c.rule + c.secret}
	}
	New().Run(context.Background(), fs, 2)
	for i, c := range cases {
		if fs[i].Verification != c.want {
			t.Errorf("%s/%s: got %s want %s", c.rule, c.secret, fs[i].Verification, c.want)
		}
	}
	for _, id := range []string{"github-pat", "github-fine-grained-pat", "gitlab-pat"} {
		if !saved[id].SelfHosted {
			t.Errorf("%s: tokens of self-managed instances must not be called invalid", id)
		}
	}
}
