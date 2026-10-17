// SPDX-License-Identifier: Apache-2.0

package detect

import (
	"encoding/base64"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/AISolutionLabs/secret-scanner/internal/wordy"
)

// validators are the content checks rules name in config.Rule.Validate.
// Each returns whether the candidate qualifies and, if it does, an evidence
// line for the finding. A candidate that fails never qualified as a match
// (like failing the entropy gate): it is not a suppression and is not listed
// in the ledger.
var validators = map[string]func(secret string) (bool, string){
	"basic-auth":   validBasicAuth,
	"opaque-token": validOpaqueToken,
}

// ValidatorNames lists the implemented validators (tests check it matches
// config.Validators).
func ValidatorNames() []string {
	var out []string
	for k := range validators {
		out = append(out, k)
	}
	return out
}

// basicPlaceholder matches decoded passwords that are templates or doc
// placeholders, not credentials: user:password, user:<pass>, u:${PASS}.
var basicPlaceholder = regexp.MustCompile(`(?i)^(?:pass(?:word)?|passwd|pwd|secret|changeme|x{3,}|\*+|\.{3,}|<[^>]*>|\$\{?\w+\}?|\{\{.*\}\}|%s|\[\w+\])$`)

// DecodeBasicAuth decodes an HTTP Basic credential (base64 of
// "user:password"). It reports ok only for printable text with a non-empty
// user and password; random base64 or encoded binary does not qualify.
func DecodeBasicAuth(b64 string) (user, password string, ok bool) {
	core := strings.TrimRight(b64, "=")
	if len(core) < 4 {
		return "", "", false
	}
	raw, err := base64.RawStdEncoding.DecodeString(core)
	if err != nil {
		return "", "", false
	}
	s := string(raw)
	if !utf8.ValidString(s) {
		return "", "", false
	}
	for _, r := range s {
		if !unicode.IsPrint(r) {
			return "", "", false
		}
	}
	i := strings.IndexByte(s, ':')
	if i <= 0 || i == len(s)-1 {
		return "", "", false
	}
	user, password = s[:i], s[i+1:]
	if strings.TrimSpace(user) == "" || strings.TrimSpace(password) == "" {
		return "", "", false
	}
	return user, password, true
}

func validBasicAuth(secret string) (bool, string) {
	_, pw, ok := DecodeBasicAuth(secret)
	if !ok || basicPlaceholder.MatchString(pw) {
		return false, ""
	}
	return true, "decodes to user:password (HTTP Basic credentials)"
}

// validOpaqueToken rejects values that are words, placeholders or
// identifiers (Bearer YOUR_ACCESS_TOKEN, Bearer authorization_uri, Bearer
// someAccessToken) and keeps token-shaped values: letters and digits mixed,
// random-looking, not a dictionary phrase or keyboard run.
func validOpaqueToken(secret string) (bool, string) {
	core := strings.TrimRight(secret, "=")
	hasDigit := strings.IndexFunc(core, unicode.IsDigit) >= 0
	hasLetter := strings.IndexFunc(core, unicode.IsLetter) >= 0
	// Random tokens without a digit are common: 3% of 20-character and 0.4%
	// of 32-character alphanumeric tokens have none. A digit-free value
	// qualifies when it is long, mixed-case, high-entropy and not words.
	if !hasDigit && hasLetter && digitFreeToken(core) {
		hasDigit = true
	}
	if !hasDigit || !hasLetter || Shannon(core) < 3.0 {
		return false, ""
	}
	if strings.Contains(secret, "..") || isSequential(secret) || looksLikeIdentifier(core, true) ||
		segmentsAreWords(core) || wordTokens(core) || camelWords(core) || dottedNamespace(core) {
		return false, ""
	}
	return true, "token-shaped value (mixed letters and digits, not words or an identifier)"
}

// digitFreeToken reports long mixed-case random-looking values without
// digits (Bearer tokens drawn from a letters-heavy alphabet). Placeholders
// (YOUR_ACCESS_TOKEN, someAccessTokenValue) are single-case or read as
// words, and are still rejected by the identifier and word checks.
func digitFreeToken(s string) bool {
	upper, lower := 0, 0
	for i := 0; i < len(s); i++ {
		switch c := s[i]; {
		case c >= 'A' && c <= 'Z':
			upper++
		case c >= 'a' && c <= 'z':
			lower++
		}
	}
	return len(s) >= 20 && upper >= 3 && lower >= 3 && Shannon(s) >= 3.8 && wordy.Wordiness(s) < 0.5
}
