// SPDX-License-Identifier: Apache-2.0

// Package verify optionally checks whether detected secrets are live by
// calling the issuing provider's read-only identity endpoint.
//
// Verification sends the secret to its provider. It is off by default and
// should never run from a commit hook.
package verify

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/AISolutionLabs/secret-scanner/internal/detect"
)

// Status values.
const (
	Verified = "verified"   // provider accepted the credential
	Invalid  = "invalid"    // provider rejected it
	Unknown  = "unverified" // no verifier, or inconclusive response
	Errored  = "error"      // network/transport failure
)

// Check describes how to verify one rule's secrets.
type Check struct {
	Method string
	URL    string
	Header func(secret string) http.Header
	Basic  func(secret string) (user, pass string)
	// Interpret overrides status-code handling (e.g. Slack returns 200 + ok:false).
	Interpret func(status int, body []byte) string
	// SelfHosted marks token formats that self-managed instances issue too
	// (GitHub Enterprise Server, GitLab self-managed): a 401 from the public
	// endpoint only means "not a token of the SaaS", so it is unknown, not
	// invalid.
	SelfHosted bool
}

func bearer(secret string) http.Header {
	return http.Header{"Authorization": {"Bearer " + secret}}
}

// Checks maps rule IDs to verifiers. Endpoints are read-only identity calls.
var Checks = map[string]Check{
	"github-pat":              {Method: "GET", URL: "https://api.github.com/user", Header: githubHeader, SelfHosted: true},
	"github-fine-grained-pat": {Method: "GET", URL: "https://api.github.com/user", Header: githubHeader, SelfHosted: true},
	"github-oauth":            {Method: "GET", URL: "https://api.github.com/user", Header: githubHeader, SelfHosted: true},
	"github-app-token":        {Method: "GET", URL: "https://api.github.com/user", Header: githubHeader, SelfHosted: true},
	"gitlab-pat": {Method: "GET", URL: "https://gitlab.com/api/v4/user", SelfHosted: true,
		Header: func(s string) http.Header { return http.Header{"Private-Token": {s}} }},
	"slack-bot-token":  {Method: "POST", URL: "https://slack.com/api/auth.test", Header: bearer, Interpret: slackOK},
	"slack-user-token": {Method: "POST", URL: "https://slack.com/api/auth.test", Header: bearer, Interpret: slackOK},
	"slack-app-token":  {Method: "POST", URL: "https://slack.com/api/apps.connections.open", Header: bearer, Interpret: slackOK},
	"stripe-key": {Method: "GET", URL: "https://api.stripe.com/v1/balance",
		Basic: func(s string) (string, string) { return s, "" }},
	"openai-api-key": {Method: "GET", URL: "https://api.openai.com/v1/models", Header: bearer},
	"anthropic-api-key": {Method: "GET", URL: "https://api.anthropic.com/v1/models",
		Header: func(s string) http.Header {
			return http.Header{"X-Api-Key": {s}, "Anthropic-Version": {"2023-06-01"}}
		}},
	"huggingface-token":  {Method: "GET", URL: "https://huggingface.co/api/whoami-v2", Header: bearer},
	"npm-access-token":   {Method: "GET", URL: "https://registry.npmjs.org/-/whoami", Header: bearer},
	"sendgrid-api-key":   {Method: "GET", URL: "https://api.sendgrid.com/v3/scopes", Header: bearer},
	"digitalocean-token": {Method: "GET", URL: "https://api.digitalocean.com/v2/account", Header: bearer},
	"groq-api-key":       {Method: "GET", URL: "https://api.groq.com/openai/v1/models", Header: bearer},
	"linear-api-key": {Method: "POST", URL: "https://api.linear.app/graphql",
		Header: func(s string) http.Header {
			return http.Header{"Authorization": {s}, "Content-Type": {"application/json"}}
		}},
}

func githubHeader(s string) http.Header {
	return http.Header{"Authorization": {"token " + s}, "Accept": {"application/vnd.github+json"}}
}

func slackOK(status int, body []byte) string {
	if status != 200 {
		return Unknown
	}
	var r struct {
		OK    bool   `json:"ok"`
		Error string `json:"error"`
	}
	if json.Unmarshal(body, &r) != nil {
		return Unknown
	}
	if r.OK {
		return Verified
	}
	if r.Error == "invalid_auth" || r.Error == "token_revoked" || r.Error == "account_inactive" || r.Error == "not_authed" {
		return Invalid
	}
	return Unknown
}

// noRedirects keeps a secret on the provider endpoint it was meant for: on a
// cross-host redirect Go drops Authorization but forwards custom headers
// (x-api-key, DD-API-KEY, ...). A redirect answer is reported as unknown.
func noRedirects(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }

// Verifier runs checks with caching and bounded concurrency.
type Verifier struct {
	Client  *http.Client
	Timeout time.Duration
	mu      sync.Mutex
	cache   map[string]string
}

// New returns a verifier honoring HTTPS_PROXY and the system CA store.
func New() *Verifier {
	return &Verifier{Client: &http.Client{Timeout: 15 * time.Second, CheckRedirect: noRedirects}, Timeout: 10 * time.Second, cache: map[string]string{}}
}

// Status verifies a single finding (raw, un-redacted secret required).
func (v *Verifier) Status(ctx context.Context, f detect.Finding) string {
	c, ok := Checks[f.RuleID]
	if !ok || c.URL == "" || f.Secret == "" {
		return Unknown
	}
	key := f.RuleID + "\x00" + f.SecretHash
	v.mu.Lock()
	if s, ok := v.cache[key]; ok {
		v.mu.Unlock()
		return s
	}
	v.mu.Unlock()

	s := v.do(ctx, c, f.Secret)
	v.mu.Lock()
	v.cache[key] = s
	v.mu.Unlock()
	return s
}

func (v *Verifier) do(ctx context.Context, c Check, secret string) string {
	ctx, cancel := context.WithTimeout(ctx, v.Timeout)
	defer cancel()
	var body io.Reader
	if c.Method == "POST" {
		if strings.Contains(c.URL, "graphql") {
			body = strings.NewReader(`{"query":"{ viewer { id } }"}`)
		} else {
			body = strings.NewReader("")
		}
	}
	req, err := http.NewRequestWithContext(ctx, c.Method, c.URL, body)
	if err != nil {
		return Errored
	}
	req.Header.Set("User-Agent", "secretscan-verify")
	if c.Header != nil {
		for k, vs := range c.Header(secret) {
			for _, val := range vs {
				req.Header.Add(k, val)
			}
		}
	}
	if c.Basic != nil {
		u, p := c.Basic(secret)
		req.SetBasicAuth(u, p)
	}
	resp, err := v.Client.Do(req)
	if err != nil {
		return Errored
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if c.Interpret != nil {
		return c.Interpret(resp.StatusCode, b)
	}
	// Every endpoint here answers in JSON. An HTML or empty answer comes from
	// something in between (a TLS-inspecting proxy's block or caution page,
	// a captive portal, a WAF) and proves nothing about the secret.
	fromAPI := strings.Contains(strings.ToLower(resp.Header.Get("Content-Type")), "json")
	switch {
	case resp.StatusCode >= 200 && resp.StatusCode < 300 && fromAPI:
		return Verified
	case resp.StatusCode == 401 && c.SelfHosted:
		return Unknown // may belong to a self-managed instance
	case resp.StatusCode == 401:
		return Invalid
	case resp.StatusCode == 403 && fromAPI:
		// Authenticated but lacking scope still proves the key is live for
		// most providers; treat as verified.
		return Verified
	default:
		return Unknown
	}
}

// Run verifies findings concurrently, setting Verification on each.
func (v *Verifier) Run(ctx context.Context, fs []detect.Finding, workers int) {
	if workers < 1 {
		workers = 4
	}
	sem := make(chan struct{}, workers)
	var wg sync.WaitGroup
	for i := range fs {
		wg.Add(1)
		sem <- struct{}{}
		go func(i int) {
			defer wg.Done()
			defer func() { <-sem }()
			fs[i].Verification = v.Status(ctx, fs[i])
		}(i)
	}
	wg.Wait()
}
