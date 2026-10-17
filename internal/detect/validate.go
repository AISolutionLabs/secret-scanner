// SPDX-License-Identifier: Apache-2.0

package detect

import (
	"encoding/base64"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"
)

// validators are the content checks rules name in config.Rule.Validate.
// Each returns whether the candidate qualifies and, if it does, an evidence
// line for the finding. A candidate that fails never qualified as a match
// (like failing the entropy gate): it is not a suppression and is not listed
// in the ledger.
var validators = map[string]func(secret string) (bool, string){
	"basic-auth":   validBasicAuth,
	"bearer-token": validBearerToken,
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

// validBearerToken rejects scheme arguments that are words, placeholders or
// identifiers (Bearer YOUR_ACCESS_TOKEN, Bearer authorization_uri, Bearer
// someAccessToken) and keeps token-shaped values: letters and digits mixed,
// random-looking, not a dictionary phrase or keyboard run.
func validBearerToken(secret string) (bool, string) {
	core := strings.TrimRight(secret, "=")
	hasDigit := strings.IndexFunc(core, unicode.IsDigit) >= 0
	hasLetter := strings.IndexFunc(core, unicode.IsLetter) >= 0
	if !hasDigit || !hasLetter || Shannon(core) < 3.0 {
		return false, ""
	}
	if strings.Contains(secret, "..") || isSequential(secret) || looksLikeIdentifier(core, true) ||
		segmentsAreWords(core) || wordTokens(core) || camelWords(core) || dottedNamespace(core) {
		return false, ""
	}
	return true, "value of an HTTP Bearer authorization scheme"
}
