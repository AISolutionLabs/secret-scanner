// SPDX-License-Identifier: Apache-2.0

package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"math/rand"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func rnd(seed int64, n int) string {
	r := rand.New(rand.NewSource(seed))
	const cs = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, n)
	for i := range b {
		b[i] = cs[r.Intn(len(cs))]
	}
	return string(b)
}

// privacyRepo writes one file per secret kind, including a weak password,
// and returns the directory and the raw values.
func privacyRepo(t *testing.T) (string, map[string]string) {
	t.Helper()
	dir := t.TempDir()
	pem := "-----BEGIN RSA PRIVATE KEY-----\n" + rnd(5, 64) + "\n" + rnd(6, 64) + "\n" + rnd(7, 64) + "\n-----END RSA PRIVATE KEY-----"
	secrets := map[string]string{
		"github token":    "ghp_" + rnd(1, 36),
		"generic key":     rnd(2, 32),
		"url password":    rnd(3, 18),
		"weak password":   "Welcome1!",
		"private key row": rnd(6, 64),
	}
	writeFile(t, filepath.Join(dir, "app.py"), "GH = \""+secrets["github token"]+"\"\nAPI_SECRET = \""+secrets["generic key"]+"\"\n")
	writeFile(t, filepath.Join(dir, "config/database.yml"), "production:\n  url: postgres://app:"+secrets["url password"]+"@db.prod.acme-corp.io:5432/app\n  password: "+secrets["weak password"]+"\n")
	writeFile(t, filepath.Join(dir, "deploy/key.pem"), pem+"\n")
	return dir, secrets
}

func plainHash(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// With default settings no output (any report format, the suppression
// ledger, the summary, report files, triage) contains a raw secret.
func TestRawSecretsNeverInOutput(t *testing.T) {
	dir, secrets := privacyRepo(t)
	var runs []string
	check := func(name string, texts ...string) {
		t.Helper()
		runs = append(runs, name)
		all := strings.Join(texts, "\n")
		for kind, s := range secrets {
			if strings.Contains(all, s) {
				t.Errorf("%s: raw %s appears in the output", name, kind)
			}
		}
	}
	for _, f := range []string{"text", "json", "sarif", "csv", "junit", "stats"} {
		r := run(t, dir, "", "dir", ".", "-f", f, "--show-suppressed", "--remediation", "full")
		if r.code != 1 {
			t.Fatalf("%s: exit %d: %s", f, r.code, r.stderr)
		}
		check(f, r.stdout, r.stderr)
		rp := filepath.Join(t.TempDir(), "report."+f)
		r = run(t, dir, "", "dir", ".", "-f", f, "-r", rp)
		b, _ := os.ReadFile(rp)
		check(f+" report file", r.stdout, r.stderr, string(b))
	}
	// Every kind was actually found (otherwise the test proves nothing).
	r := run(t, dir, "", "dir", ".", "-f", "json", "--redact=0")
	for kind, s := range secrets {
		if !strings.Contains(r.stdout, s) {
			t.Errorf("%s not reported at all; the privacy check above is vacuous for it", kind)
		}
	}
	// Triage of an unredacted gitleaks report: its own output stays redacted.
	var gl []map[string]any
	for kind, s := range secrets {
		file, line := "app.py", 1
		switch kind {
		case "generic key":
			line = 2
		case "url password":
			file, line = "config/database.yml", 2
		case "weak password":
			file, line = "config/database.yml", 3
		case "private key row":
			file, line = "deploy/key.pem", 3
		}
		gl = append(gl, map[string]any{"RuleID": "generic-api-key", "File": file, "StartLine": line, "Secret": s, "Match": s})
	}
	rep, _ := json.Marshal(gl)
	for _, f := range []string{"text", "json", "sarif"} {
		r := run(t, dir, string(rep), "triage", "-", "-f", f)
		check("triage "+f, r.stdout, r.stderr)
	}
	if len(runs) < 15 {
		t.Fatalf("only %d outputs checked", len(runs))
	}
}

// Keyed fingerprints: reports carry hmac-sha256:, never the plain SHA-256,
// and keyed baselines and ignore entries round-trip with the same key.
func TestKeyedFingerprints(t *testing.T) {
	dir, secrets := privacyRepo(t)
	key := "k-" + rnd(42, 30)
	env := func(args ...string) result {
		t.Helper()
		cmd := exec.Command(bin, args...)
		cmd.Dir = dir
		cmd.Env = append(os.Environ(), "NO_COLOR=1", "SECRETSCAN_HASH_KEY="+key)
		var so, se strings.Builder
		cmd.Stdout, cmd.Stderr = &so, &se
		err := cmd.Run()
		code := 0
		if ee, ok := err.(*exec.ExitError); ok {
			code = ee.ExitCode()
		}
		return result{code, so.String(), se.String()}
	}
	base := filepath.Join(t.TempDir(), "baseline.json")
	r := env("dir", ".", "-f", "json", "-r", base)
	if r.code != 1 {
		t.Fatalf("scan: %+v", r)
	}
	var fs []struct{ RuleID, SecretHash string }
	b, _ := os.ReadFile(base)
	if err := json.Unmarshal(b, &fs); err != nil || len(fs) == 0 {
		t.Fatalf("report: %v %s", err, b)
	}
	for _, f := range fs {
		if !strings.HasPrefix(f.SecretHash, "hmac-sha256:") {
			t.Errorf("%s: SecretHash %q is not keyed", f.RuleID, f.SecretHash)
		}
	}
	for kind, s := range secrets {
		for _, out := range []string{string(b), env("dir", ".", "-f", "sarif").stdout, env("dir", ".", "-f", "csv").stdout} {
			if strings.Contains(out, plainHash(s)) {
				t.Errorf("plain SHA-256 of the %s published despite the key", kind)
			}
		}
	}
	// Keyed baseline: everything accepted.
	if r := env("dir", ".", "-b", base, "-q"); r.code != 0 {
		t.Errorf("keyed baseline did not match: %+v", r)
	}
	// Keyed ignore entry for one finding.
	ig := filepath.Join(t.TempDir(), "ignore")
	os.WriteFile(ig, []byte(fs[0].SecretHash+"  # accepted\n"), 0o600)
	r = env("dir", ".", "-f", "json", "--ignore-file", ig)
	if strings.Contains(r.stdout, fs[0].SecretHash) {
		t.Errorf("keyed ignore entry did not suppress its finding")
	}
	// Plain sha256: entries still work with a key configured.
	os.WriteFile(ig, []byte("sha256:"+plainHash(secrets["github token"])+"\n"), 0o600)
	if r := env("dir", ".", "-f", "json", "--ignore-file", ig, "--redact=0"); strings.Contains(r.stdout, secrets["github token"]) {
		t.Errorf("plain sha256 ignore entry stopped working with a key")
	}
	// Baselines also match by location (file:rule:line). The keyed hash is
	// what keeps a moved secret accepted: move every secret down one line.
	for _, p := range []string{"app.py", "config/database.yml", "deploy/key.pem"} {
		b, _ := os.ReadFile(filepath.Join(dir, p))
		os.WriteFile(filepath.Join(dir, p), append([]byte("\n"), b...), 0o644)
	}
	if r := env("dir", ".", "-b", base, "-q"); r.code != 0 {
		t.Errorf("keyed baseline lost moved secrets: %+v", r)
	}
	// Without the key the moved secrets are reported again, with a warning.
	r = run(t, dir, "", "dir", ".", "-b", base, "-q")
	if r.code != 1 || !strings.Contains(r.stderr, "match by location only") {
		t.Errorf("keyed baseline without key: %+v", r)
	}
	// A different key does not match either.
	key = "other-" + rnd(43, 30)
	if r := env("dir", ".", "-b", base, "-q"); r.code != 1 {
		t.Errorf("baseline matched with a different key: %+v", r)
	}
	// Short keys are refused; a key file works like the variable.
	kf := filepath.Join(t.TempDir(), "key")
	os.WriteFile(kf, []byte("short\n"), 0o600)
	if r := run(t, dir, "", "dir", ".", "--hash-key-file", kf, "-q"); r.code != 2 || !strings.Contains(r.stderr, "at least 16 bytes") {
		t.Errorf("short key accepted: %+v", r)
	}
	os.WriteFile(kf, []byte("k-"+rnd(42, 30)+"\n"), 0o600)
	if r := run(t, dir, "", "dir", ".", "--hash-key-file", kf, "-b", base, "-q"); r.code != 0 { // secrets moved: hash match only
		t.Errorf("key file did not reproduce the keyed baseline: %+v", r)
	}
}
