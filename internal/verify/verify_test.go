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
