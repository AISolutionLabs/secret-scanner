// SPDX-License-Identifier: Apache-2.0

package detect

import (
	"regexp"
	"strings"
)

// Key-name context shared by detection and triage. Both match the end of
// "<key> <operator>" text immediately before a value.

// CredentialKey matches a credential-named key before a value:
// tokenValue = , "SecretID": , secretVal := , api_key", , Authorization: .
var CredentialKey = regexp.MustCompile(`(?i)(?:secret|token|passw|pwd|passphrase|api[_-]?key|apikey|auth(?:orization)?|credential|private[_-]?key|access[_-]?key|key)[a-z0-9_]{0,8}["'\x60]?\s*(?::=|=>|[:=,])\s*["'\x60]?$`)

// RequestIDKey matches keys whose values are identifiers even when the name
// contains "token" or "key": request/correlation/idempotency tokens,
// concurrency and paging tokens (AWS WAF ChangeToken, NextToken, sync
// tokens, CSRF/state nonces) and any key ending in id (keyId, secret_id).
// A UUID under such a key is an ID, unlike access_token = <uuid>.
var RequestIDKey = regexp.MustCompile(`(?i)(?:(?:request|idempoten|correlation|trace|transaction|session[_-]?id|client[_-]?id|tenant|subscription|object|resource|message|change|sync|csrf|xsrf|nonce|state|lock|lease|revision|etag|continuation|pagination|next|page|cursor|upload|batch|job|order|device|instance|install)[a-z0-9_-]{0,20}|(?:^|[^a-z])[a-z0-9_-]*?(?:id|ids|guid|uuid))["'\x60]?\s*(?::=|=>|[:=,])\s*["'\x60]?$`)

// UUIDCredentialEvidence is the evidence line of a UUID reported because
// its key names a credential.
const UUIDCredentialEvidence = "UUID-shaped value under a credential-named key: kept at low confidence (UUIDs are usually identifiers)"

// credentialUUIDKey reports whether the text before a UUID value names a
// credential (and not a request-style identifier).
func credentialUUIDKey(text string, at int) bool {
	ls := strings.LastIndexByte(text[:at], '\n') + 1
	before := strings.TrimRight(text[max(ls, at-80):at], " \t")
	return CredentialKey.MatchString(before) && !RequestIDKey.MatchString(before)
}
