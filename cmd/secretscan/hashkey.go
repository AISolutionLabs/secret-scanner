// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bufio"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/AISolutionLabs/secret-scanner/internal/detect"
)

// Secret fingerprints in reports.
//
// By default a report's SecretHash is the unsalted SHA-256 of the secret:
// portable (any machine can match a baseline) but not anonymous. Anyone
// holding the report can test guesses, which recovers weak passwords
// quickly. With a key (SECRETSCAN_HASH_KEY, or --hash-key-file), every
// fingerprint written to a report is "hmac-sha256:<hex>" instead, which
// cannot be tested without the key. Matching inside one run always uses
// the plain hash, so existing sha256: ignore entries and baselines keep
// working; keyed ignore entries and keyed baselines need the same key.

const keyedPrefix = "hmac-sha256:"

const minHashKey = 16

type hashKeyer struct {
	key       []byte
	hashes    map[string]bool // keyed ignore entries
	ruleFiles map[string]bool // keyed baseline entries: rule \0 file \0 hash
	unmatched int             // keyed ignore entries loaded without a key
	baseOnly  int             // keyed baseline hashes loaded without a key
}

// loadHashKey returns the configured key, or nil for plain SHA-256.
func loadHashKey(keyFile string) (*hashKeyer, error) {
	h := &hashKeyer{hashes: map[string]bool{}, ruleFiles: map[string]bool{}}
	var key []byte
	switch {
	case keyFile != "":
		if fi, err := os.Stat(keyFile); err == nil && fi.Mode().Perm()&0o077 != 0 {
			fmt.Fprintf(os.Stderr, "secretscan: warning: hash key file %s is readable by other users (mode %v)\n", keyFile, fi.Mode().Perm())
		}
		b, err := os.ReadFile(keyFile)
		if err != nil {
			return nil, fmt.Errorf("hash key: %w", err)
		}
		key = []byte(strings.TrimRight(string(b), "\r\n"))
	case os.Getenv("SECRETSCAN_HASH_KEY") != "":
		key = []byte(os.Getenv("SECRETSCAN_HASH_KEY"))
	}
	if key != nil && len(key) < minHashKey {
		return nil, errors.New("hash key must be at least 16 bytes (use a random value, e.g. openssl rand -hex 32)")
	}
	h.key = key
	return h, nil
}

func (h *hashKeyer) enabled() bool { return h != nil && h.key != nil }

func (h *hashKeyer) keyed(secret string) string {
	m := hmac.New(sha256.New, h.key)
	m.Write([]byte(secret))
	return keyedPrefix + hex.EncodeToString(m.Sum(nil))
}

// addIgnoreFile collects hmac-sha256: entries; other entries are handled by
// detect.IgnoreSet. A missing file is not an error (as there).
func (h *hashKeyer) addIgnoreFile(path string) error {
	f, err := os.Open(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if i := strings.Index(line, " #"); i >= 0 {
			line = strings.TrimSpace(line[:i])
		}
		if strings.HasPrefix(line, keyedPrefix) {
			h.hashes[strings.ToLower(line)] = true
			if !h.enabled() {
				h.unmatched++
			}
		}
	}
	return sc.Err()
}

func (h *hashKeyer) addBaseline(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil // reported by detect.IgnoreSet.LoadBaseline
	}
	var fs []detect.Finding
	if json.Unmarshal(data, &fs) != nil {
		return nil
	}
	for _, f := range fs {
		if strings.HasPrefix(f.SecretHash, keyedPrefix) {
			h.ruleFiles[f.RuleID+"\x00"+f.File+"\x00"+f.SecretHash] = true
			if !h.enabled() {
				h.baseOnly++
			}
		}
	}
	return nil
}

// ignored reports whether a keyed ignore entry or baseline covers f, whose
// Secret must still be the raw value.
func (h *hashKeyer) ignored(f detect.Finding) bool {
	if !h.enabled() || f.Secret == "" || len(h.hashes)+len(h.ruleFiles) == 0 {
		return false
	}
	k := h.keyed(f.Secret)
	return h.hashes[k] || h.ruleFiles[f.RuleID+"\x00"+f.File+"\x00"+k]
}

// publish replaces the plain hash with the keyed one before f leaves the
// process. Must run while f.Secret is still raw (before redaction).
func (h *hashKeyer) publish(f *detect.Finding) {
	if h.enabled() && f.Secret != "" {
		f.SecretHash = h.keyed(f.Secret)
	}
}
