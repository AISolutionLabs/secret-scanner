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
	// Success lists JSON fields a genuine success response from this provider
	// always contains (dot paths, e.g. "data.viewer.id"). A 2xx answer
	// without them, such as a JSON error object or an empty document from a
	// proxy, proves nothing and is reported as unverified.
	Success []string
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
	"github-pat":              {Method: "GET", URL: "https://api.github.com/user", Header: githubHeader, SelfHosted: true, Success: []string{"login", "id"}},
	"github-fine-grained-pat": {Method: "GET", URL: "https://api.github.com/user", Header: githubHeader, SelfHosted: true, Success: []string{"login", "id"}},
	"github-oauth":            {Method: "GET", URL: "https://api.github.com/user", Header: githubHeader, SelfHosted: true, Success: []string{"login", "id"}},
	// GitHub App installation tokens cannot call /user; /installation/repositories works.
	"github-app-token": {Method: "GET", URL: "https://api.github.com/installation/repositories", Header: githubHeader, SelfHosted: true, Success: []string{"total_count"}},
	"gitlab-pat": {Method: "GET", URL: "https://gitlab.com/api/v4/user", SelfHosted: true, Success: []string{"id", "username"},
		Header: func(s string) http.Header { return http.Header{"Private-Token": {s}} }},
	"slack-bot-token":  {Method: "POST", URL: "https://slack.com/api/auth.test", Header: bearer, Interpret: slackOK},
	"slack-user-token": {Method: "POST", URL: "https://slack.com/api/auth.test", Header: bearer, Interpret: slackOK},
	"slack-app-token":  {Method: "POST", URL: "https://slack.com/api/apps.connections.open", Header: bearer, Interpret: slackOK},
	"stripe-key": {Method: "GET", URL: "https://api.stripe.com/v1/balance", Success: []string{"object=balance"},
		Basic: func(s string) (string, string) { return s, "" }},
	"openai-api-key": {Method: "GET", URL: "https://api.openai.com/v1/models", Header: bearer, Success: []string{"object=list", "data"}},
	"anthropic-api-key": {Method: "GET", URL: "https://api.anthropic.com/v1/models", Success: []string{"data", "has_more"},
		Header: func(s string) http.Header {
			return http.Header{"X-Api-Key": {s}, "Anthropic-Version": {"2023-06-01"}}
		}},
	"huggingface-token":  {Method: "GET", URL: "https://huggingface.co/api/whoami-v2", Header: bearer, Success: []string{"name", "type"}},
	"npm-access-token":   {Method: "GET", URL: "https://registry.npmjs.org/-/whoami", Header: bearer, Success: []string{"username"}},
	"sendgrid-api-key":   {Method: "GET", URL: "https://api.sendgrid.com/v3/scopes", Header: bearer, Success: []string{"scopes"}},
	"digitalocean-token": {Method: "GET", URL: "https://api.digitalocean.com/v2/account", Header: bearer, Success: []string{"account.uuid"}},
	"groq-api-key":       {Method: "GET", URL: "https://api.groq.com/openai/v1/models", Header: bearer, Success: []string{"object=list", "data"}},
	// GraphQL answers 200 even for errors; only a viewer id proves the key.
	"linear-api-key": {Method: "POST", URL: "https://api.linear.app/graphql", Success: []string{"data.viewer.id"},
		Header: func(s string) http.Header {
			return http.Header{"Authorization": {s}, "Content-Type": {"application/json"}}
		}},
}

// successful reports whether body is a JSON object that has every field in
// want: "a.b.c" must exist and be non-null, non-empty; "k=v" must equal v.
// A top-level "error" or "errors" member always fails.
func successful(body []byte, want []string) bool {
	var doc map[string]any
	if json.Unmarshal(body, &doc) != nil || len(doc) == 0 {
		return false
	}
	if _, ok := doc["error"]; ok {
		return false
	}
	if _, ok := doc["errors"]; ok {
		return false
	}
	for _, w := range want {
		path, value, eq := strings.Cut(w, "=")
		var cur any = doc
		for _, k := range strings.Split(path, ".") {
			m, ok := cur.(map[string]any)
			if !ok {
				return false
			}
			if cur, ok = m[k]; !ok || cur == nil {
				return false
			}
		}
		switch x := cur.(type) {
		case string:
			if x == "" || eq && x != value {
				return false
			}
		default:
			if eq {
				return false
			}
		}
	}
	return true
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

// Verifier runs checks with caching and bounded concurrency. Each secret is
// checked at most once per run: concurrent callers for the same rule and
// secret wait for the one request in flight and share its result.
type Verifier struct {
	Client   *http.Client
	Timeout  time.Duration
	mu       sync.Mutex
	cache    map[string]string
	inflight map[string]chan struct{}
}

// New returns a verifier honoring HTTPS_PROXY and the system CA store.
func New() *Verifier {
	return &Verifier{Client: &http.Client{Timeout: 15 * time.Second, CheckRedirect: noRedirects}, Timeout: 10 * time.Second,
		cache: map[string]string{}, inflight: map[string]chan struct{}{}}
}

// Status verifies a single finding (raw, un-redacted secret required).
func (v *Verifier) Status(ctx context.Context, f detect.Finding) string {
	c, ok := Checks[f.RuleID]
	if !ok || c.URL == "" || f.Secret == "" {
		return Unknown
	}
	key := f.RuleID + "\x00" + f.SecretHash
	if f.SecretHash == "" {
		key = f.RuleID + "\x00" + f.Secret
	}
	for {
		v.mu.Lock()
		if v.cache == nil {
			v.cache = map[string]string{}
		}
		if v.inflight == nil {
			v.inflight = map[string]chan struct{}{}
		}
		if s, ok := v.cache[key]; ok {
			v.mu.Unlock()
			return s
		}
		if wait, busy := v.inflight[key]; busy {
			v.mu.Unlock()
			select {
			case <-wait:
				continue // the result is in the cache now
			case <-ctx.Done():
				return Errored
			}
		}
		done := make(chan struct{})
		v.inflight[key] = done
		v.mu.Unlock()

		s := v.do(ctx, c, f.Secret)
		v.mu.Lock()
		v.cache[key] = s
		delete(v.inflight, key)
		v.mu.Unlock()
		close(done)
		return s
	}
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
	case resp.StatusCode >= 200 && resp.StatusCode < 300 && fromAPI && successful(b, c.Success):
		// Only the provider's documented success shape proves the key: a 2xx
		// JSON error object or empty document (proxies, gateways) does not.
		return Verified
	case resp.StatusCode == 401 && c.SelfHosted:
		return Unknown // may belong to a self-managed instance
	case resp.StatusCode == 401:
		return Invalid
	default:
		// 403 is ambiguous (missing scope, rate limit, IP allowlist, a
		// proxy's block page), 429/5xx are temporary, redirects and
		// unexpected shapes prove nothing.
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
