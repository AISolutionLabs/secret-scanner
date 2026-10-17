// SPDX-License-Identifier: Apache-2.0

package detect

import (
	"encoding/hex"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/AISolutionLabs/secret-scanner/internal/config"
	"github.com/AISolutionLabs/secret-scanner/internal/wordy"
)

// Placeholder vocabulary: words that documentation, tests and templates use
// when they need "a password" (some_password, s3krit-password, admin123,
// postgres:postgres, x-pack-test-password). A value is a dummy only when it
// is (nearly) made of these words, so ordinary words are not evidence on
// their own: CorrectHorseBatteryStaple9 or Winter2026! are reported.
var dummyVocab = func() map[string]bool {
	m := map[string]bool{}
	for _, w := range strings.Fields(`
		password passwd passw pass pwd pswd pw passphrase passcode pin
		secret secrets sekrit skrit secure token tokens key keys apikey credential credentials creds
		test tests testing tester dummy fake sample example examples demo mock mocked placeholder
		changeme change changeit default defaults some my your our top super admin administrator
		root user username users guest login logon master foo bar baz qux quux foobar
		qwerty qwertz asdf asdasd asd qwe zxc letmein welcome hello world abc abcd abcdef xyz
		local localhost dev devel development temp tmp invalid wrong bad new old basic auth api db
		database access postgres postgresql pgsql mysql mariadb sa oracle redis mongo mongodb
		rabbitmq rabbit guest elastic elasticsearch kibana changethis tiger scott hunter2 sesame open
		this is not my real very the me in it let insecure unsafe value here enter insert
		another other alt sql app service bogus nopass nothing none empty blank`) {
		m[w] = true
	}
	return m
}()

// leet undoes the usual substitutions (s3krit, p@ssw0rd, $ecret).
var leet = strings.NewReplacer("0", "o", "1", "i", "3", "e", "4", "a", "5", "s", "7", "t", "@", "a", "$", "s")
var leetL = strings.NewReplacer("0", "o", "1", "l", "3", "e", "4", "a", "5", "s", "7", "t", "@", "a", "$", "s")

// segmentVocab reports whether a lowercase letter run splits entirely into
// vocabulary words. Unless the run is itself one word, at least one piece
// must be 4+ letters: short words (my, db, sa) alone would also split random
// strings.
func segmentVocab(s string) bool {
	if s == "" {
		return false
	}
	if dummyVocab[s] {
		return true
	}
	n := len(s)
	// ok[i]: s[:i] segments; long[i]: some segmentation of s[:i] used a 4+ word.
	ok := make([]bool, n+1)
	long := make([]bool, n+1)
	ok[0] = true
	for i := 1; i <= n; i++ {
		for j := max(0, i-14); j < i; j++ {
			if !ok[j] || !dummyVocab[s[j:i]] {
				continue
			}
			ok[i] = true
			if long[j] || i-j >= 4 {
				long[i] = true
			}
		}
	}
	return ok[n] && long[n]
}

// isVocabChunk reports whether one alphanumeric chunk is placeholder words,
// optionally leet-spelled and followed by a short number (pass123, Passw0rd,
// s3krit, hunter2).
func isVocabChunk(c string) bool {
	lc := strings.ToLower(c)
	if dummyVocab[lc] {
		return true
	}
	core := strings.TrimRight(lc, "0123456789")
	if len(lc)-len(core) > 6 || core == "" {
		return false
	}
	if !strings.ContainsAny(core, "0123456789@$") {
		return segmentVocab(core)
	}
	for _, r := range []*strings.Replacer{leet, leetL} {
		v := r.Replace(core)
		if isLowerLetters(v) && segmentVocab(v) {
			return true
		}
	}
	return false
}

func isLowerLetters(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < 'a' || s[i] > 'z' {
			return false
		}
	}
	return s != ""
}

// dummyChunks splits a value into alphanumeric chunks. '@' and '$' inside a
// word are leet letters (p@ss, $ecret), elsewhere separators.
func dummyChunks(v string) []string {
	isAl := func(c byte) bool { return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' }
	isAN := func(c byte) bool { return isAl(c) || c >= '0' && c <= '9' }
	var out []string
	start := -1
	for i := 0; i <= len(v); i++ {
		in := false
		if i < len(v) {
			c := v[i]
			in = isAN(c) || (c == '@' || c == '$') && i+1 < len(v) && isAl(v[i+1]) && (i == 0 || isAN(v[i-1]))
		}
		if in && start < 0 {
			start = i
		} else if !in && start >= 0 {
			out = append(out, v[start:i])
			start = -1
		}
	}
	return out
}

// dummyReason reports placeholder credential values: the value repeats its
// own key name (basicAuthPassword: basic_auth_password), or every word in it
// comes from the placeholder vocabulary (some_password, top_secret,
// my-s3cr3t-t0ken, admin123, x-pack-test-password). Random-looking values
// never qualify: each letter run must split completely into vocabulary words.
func dummyReason(key, value string) string {
	v := strings.TrimRight(value, "!.?*#")
	if len(v) < 2 || !utf8.ValidString(v) {
		return ""
	}
	if k := alnumLower(key); len(k) >= 6 {
		if a := alnumLower(v); len(a) >= 6 && strings.Contains(k, a) && letterFraction(a) == 1 {
			return "echoes-key-name"
		}
	}
	vocab, long, single, unknown, digits := 0, 0, 0, []string{}, 0
	wholeWord := false
	for _, c := range dummyChunks(v) {
		lc := strings.ToLower(c)
		switch {
		case strings.Trim(lc, "0123456789") == "":
			digits += len(lc)
		case isVocabChunk(c):
			vocab++
			wholeWord = oneWord(c)
			if len(strings.TrimRight(lc, "0123456789")) >= 4 {
				long++
			}
			digits += len(lc) - len(strings.TrimRight(lc, "0123456789"))
		case len(lc) == 1:
			single++ // x-pack, \t escapes
		default:
			unknown = append(unknown, lc)
		}
	}
	if single > 0 && long < 2 {
		return ""
	}
	if vocab == 0 || digits > 6 {
		return ""
	}
	// Nearly all: one leftover short word or letter is tolerated next to two
	// or more long vocabulary words (x-pack-test-password).
	switch {
	case len(unknown) == 0:
	case len(unknown) == 1 && long >= 2 && len(unknown[0]) <= 5 && isLowerLetters(unknown[0]) && wordLike(unknown[0]):
	default:
		return ""
	}
	// Words plus a number (Password1, admin123, SuperSecretPassword2024) are
	// what weak real passwords look like too. Values that say they are fake
	// (testpwd1, s3krit-password2) are dummies. The canonical one-word
	// defaults plus digits (admin123, root@123, Welcome@2024, P@ssw0rd1) are
	// as often real weak passwords as doc placeholders: see
	// DefaultPasswordReason.
	if digits > 0 && !placeholderMarker(v) {
		if vocab == 1 && len(unknown) == 0 && single == 0 && wholeWord {
			return DefaultPasswordReason
		}
		return ""
	}
	return "placeholder-vocabulary"
}

// DefaultPasswordReason is the ledger reason for a one-word default
// password plus digits (admin123, Welcome@2024) in a test, example or
// documentation file, where it is dropped. Elsewhere it is reported at low
// confidence with DefaultPasswordEvidence: production configs really do
// contain these, and an attacker tries them first.
const DefaultPasswordReason = "default-password-in-test-or-doc"

// DefaultPasswordEvidence is the evidence line of a default password
// reported outside test, example and documentation files.
const DefaultPasswordEvidence = "common default password plus digits (admin123, Welcome@2024): reported at low confidence, it may be a placeholder or a real weak password"

// passwordContext reports a password rule (password-assignment, SQL and
// command-line passwords, URL credentials) or a password-named key; a
// default-password shape under a token or API-key name ("access token:
// abcdef123456") stays a placeholder.
func passwordContext(rule *config.CompiledRule, before string) bool {
	return rule.HasTag("password") || rule.HasTag("url") || strings.Contains(rule.ID, "password") ||
		passwordKey.MatchString(keyName(before))
}

var passwordKey = regexp.MustCompile(`(?i)pass|pwd`)

// docFile matches prose documentation, where default passwords are
// examples (README.md, docs pages).
var docFile = regexp.MustCompile(`(?i)\.(?:md|markdown|mdx|rst|adoc|asciidoc|txt)$|(?:^|/)readme[^/]*$`)

// Words that mark a value as made up for docs or tests (not merely weak).
var markerWords = []string{"test", "dummy", "fake", "sample", "example", "demo", "mock", "placeholder", "changeme",
	"invalid", "wrong", "bad", "some", "your", "sekrit", "skrit", "foo", "bar", "baz", "xxx", "bogus", "notreal", "insecure"}

func placeholderMarker(v string) bool {
	lv := strings.ToLower(v)
	for _, r := range []*strings.Replacer{nil, leet} {
		s := lv
		if r != nil {
			s = r.Replace(lv)
		}
		for _, w := range markerWords {
			if strings.Contains(s, w) {
				return true
			}
		}
	}
	return false
}

// oneWord reports a chunk that is a single vocabulary word plus digits
// (admin123, Passw0rd1), not a composition of several.
func oneWord(c string) bool {
	lc := strings.ToLower(c)
	core := strings.TrimRight(lc, "0123456789")
	return dummyVocab[lc] || dummyVocab[core] || dummyVocab[leet.Replace(core)] || dummyVocab[leetL.Replace(core)]
}

func wordLike(s string) bool {
	// pronounceable: has a vowel and no 3-consonant run
	vowels, run := 0, 0
	for i := 0; i < len(s); i++ {
		if strings.IndexByte("aeiouy", s[i]) >= 0 {
			vowels++
			run = 0
		} else if run++; run >= 3 {
			return false
		}
	}
	return vowels > 0
}

func alnumLower(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'A' && c <= 'Z':
			b.WriteByte(c + 32)
		case c >= 'a' && c <= 'z' || c >= '0' && c <= '9':
			b.WriteByte(c)
		}
	}
	return b.String()
}

// keyName returns the identifier a value is assigned to, from the matched
// text before the value: `"password_hash": "` -> password_hash.
func keyName(before string) string {
	s := strings.TrimRight(before, " \t'\"`=:>,;([{?|")
	i := len(s)
	for i > 0 {
		c := s[i-1]
		if c == '_' || c == '-' || c == '.' || c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' {
			i--
			continue
		}
		break
	}
	return s[i:]
}

var (
	// Keys that hold a digest of a credential, not the credential:
	// password_hash, token_hash, authConfigHash, apiAccessTokenSha256,
	// root_password_sha2, hashedPassword, password_digest.
	hashKey = regexp.MustCompile(`(?i)(?:hash|hashed|sha\d*|digest|md5|checksum|fingerprint)$|^hashed|(?:^|[_.-])hashed[_.-]`)
	// Public identity, never secret: .NET strong-name public key tokens.
	publicKeyTokenKey = regexp.MustCompile(`(?i)^publickeytoken$`)
	// Keys naming an algorithm: Password.Algorithm = "sha512",
	// PASSWORD_SCHEME=SHA512-CRYPT.
	algorithmKey = regexp.MustCompile(`(?i)(?:algorithm|algo|scheme|hasher|cipher)$`)
	// Values that are structured data, not passwords: OIDs, escaped byte
	// strings, version ranges.
	structuredValue = regexp.MustCompile(`^(?:\d+(?:\.\d+){3,}|(?:\\x[0-9A-Fa-f]{2}){3,}|[~^]\d+\.\d+(?:\.\d+)?(?:[-+][\w.]+)?)$`)
)

// UI string keys in translation files: LABEL_PASSWORD, MANDATORY_PASSWORD,
// FORGOT_PASSWORD, SHOW_PWD_TOOLTIP, labelPassword, passwordPlaceholder.
var (
	uiKeyFirst = map[string]bool{"label": true, "lbl": true, "title": true, "mandatory": true, "show": true, "hide": true,
		"forgot": true, "placeholder": true, "hint": true, "tooltip": true, "msg": true, "message": true, "text": true,
		"caption": true, "prompt": true, "btn": true, "button": true, "heading": true, "desc": true, "description": true}
	uiKeyLast = map[string]bool{"label": true, "title": true, "tooltip": true, "placeholder": true, "hint": true, "advice": true,
		"prompt": true, "message": true, "msg": true, "caption": true, "heading": true, "description": true, "help": true, "text": true}
)

func uiTextKey(key string) bool {
	var toks []string
	for _, part := range strings.FieldsFunc(key, func(r rune) bool { return r == '_' || r == '-' || r == '.' }) {
		for _, t := range wordy.Tokens(part) {
			toks = append(toks, strings.ToLower(t))
		}
	}
	return len(toks) >= 2 && (uiKeyFirst[toks[0]] || uiKeyLast[toks[len(toks)-1]])
}

// keyNoise reports values whose key says they are not a usable credential.
func keyNoise(key, value string) string {
	switch {
	case key == "":
		return ""
	case publicKeyTokenKey.MatchString(key):
		return "public-key-token"
	case hashKey.MatchString(key):
		return "hash-of-credential"
	case algorithmKey.MatchString(key):
		return "algorithm-name"
	case uiTextKey(key) && !strings.ContainsAny(value, "0123456789") && naturalText(value):
		return "ui-text"
	}
	return ""
}

// naturalText: letters (any script), spaces and sentence punctuation only.
func naturalText(s string) bool {
	letters := 0
	for _, r := range s {
		switch {
		case unicode.IsLetter(r) || unicode.Is(unicode.Mn, r) || unicode.Is(unicode.Mc, r):
			letters++
		case unicode.IsSpace(r) || strings.ContainsRune(".,:;?!()'¿¡。、？！（）：-", r):
		default:
			return false
		}
	}
	return letters > 0
}

// localizedText reports translated UI strings used as "password" values in
// locale files ("パスワードを入力してください", "Пароль:"): mostly letters
// from non-Latin scripts and no ASCII digits. Generated passwords are ASCII.
func localizedText(v string) bool {
	if strings.ContainsAny(v, "0123456789") || !naturalText(v) {
		return false
	}
	non, total := 0, 0
	for _, r := range v {
		if unicode.IsLetter(r) || unicode.Is(unicode.Mn, r) || unicode.Is(unicode.Mc, r) {
			total++
			if r > unicode.MaxLatin1 {
				non++
			}
		}
	}
	return total > 0 && non*2 >= total
}

// Test-vector reference names in crypto test files (OpenSSL evp*.txt,
// Wycheproof), such as KAS-ECC-CDH_P-192_C8, ALICE_cf_sect193r1_PUB or
// ED448-1-PUBLIC after PrivateKey/PeerKey/Key. They name a key defined
// elsewhere in the file.
var (
	vectorRole  = regexp.MustCompile(`(?i)^(?:alice|bob|malice|eve|carol|pub|public|priv|private|peer|raw|zero|kas|ecc|cdh|ecdh|dh|dhx|dsa|ecdsa|rsa|oaep|pss|pkcs\d*|ed25519|ed448|x25519|x448|fips\d*|rfc\d+|ffdhe\d+|modp\d+|sec[pt]\d+[rk]\d|prime\d+v\d|brainpoolp\d+[rt]\d|c2[pt]nb\d+[rvw]\d|wtls\d+|wap|wsg|idm|ecid|sm2|gost\w*)$`)
	vectorShort = regexp.MustCompile(`^[A-Za-z0-9]{1,3}$`)
)

func testVectorName(s string) bool {
	if isAllHex(strings.NewReplacer("-", "", "_", "").Replace(s)) {
		return false
	}
	parts := strings.FieldsFunc(s, func(r rune) bool { return r == '-' || r == '_' })
	if len(parts) < 2 {
		return false
	}
	roles, numeric := 0, 0
	for _, p := range parts {
		switch {
		case vectorRole.MatchString(p):
			roles++
		case strings.Trim(p, "0123456789") == "":
			numeric++
		case vectorShort.MatchString(p):
		default:
			return false
		}
	}
	return roles >= 2 || roles == 1 && numeric >= 1
}

// patternedHex reports hex test patterns: byte counters (000102...1f,
// fffefd..., 00112233...ff) and short repeated units (ef012345ef012345...).
// Random hex never has a constant byte step or a period of half its length.
func patternedHex(s string) bool {
	if len(s) < 16 || !isAllHex(s) {
		return false
	}
	ls := strings.ToLower(s)
	for p := 1; p <= len(ls)/2; p++ {
		periodic := true
		for i := p; i < len(ls); i++ {
			if ls[i] != ls[i-p] {
				periodic = false
				break
			}
		}
		if periodic {
			return true
		}
	}
	b, err := hex.DecodeString(ls[:len(ls)&^1])
	if err != nil || len(b) < 8 {
		return false
	}
	// Counters may run up or down (7f7e7d...70 404142...4f), so a step and
	// its negation count together.
	steps := map[byte]int{}
	for i := 1; i < len(b); i++ {
		d := b[i] - b[i-1]
		if d > 128 {
			d = -d
		}
		steps[d]++
	}
	for d, n := range steps {
		if d != 0 && n*10 >= (len(b)-1)*9 {
			return true
		}
	}
	return false
}

// credentialValueNoise applies the key- and vocabulary-based filters to
// values of generic and credential rules (never provider formats): digests
// stored under hash keys, public key tokens, translated UI strings and
// placeholder passwords. before is the matched text ahead of the value.
func credentialValueNoise(rule *config.CompiledRule, before, secret string) string {
	key := keyName(before)
	if why := keyNoise(key, secret); why != "" {
		return why
	}
	if localizedText(secret) {
		return "localized-text"
	}
	if structuredValue.MatchString(secret) {
		return "oid-bytes-or-version"
	}
	if rule.HasTag("url") {
		key = "" // the "key" of a URL password is its user name; see below
		if u := urlUser(before); u != "" && strings.EqualFold(u, secret) {
			return "user-equals-password" // postgres:postgres@, admin:admin@
		}
	}
	if why := dummyReason(key, secret); why != "" {
		return why
	}
	return ""
}

func urlUser(before string) string {
	i := strings.LastIndex(before, "://")
	if i < 0 {
		return ""
	}
	return strings.TrimSuffix(before[i+3:], ":")
}
