// SPDX-License-Identifier: Apache-2.0

package detect_test

import "testing"

// password-assignment: syntax gaps closed (indexers, comparisons, wrappers,
// 4-5 character values, spaced passphrases) and the noise filters that keep
// UI text, versions and settings out. Word-like and low-entropy passwords
// are pinned explicitly: which are caught and which are knowingly missed.
func TestPasswordAssignmentGaps(t *testing.T) {
	pw := g2(alnum, 10)
	checkRule(t, "password-assignment", []recallCase{
		// must catch
		{text: `                ["password"] = "` + pw + `"`, path: "Tests.cs", want: true},         // C# indexer
		{text: `headers['password'] = '` + pw + `'`, path: "a.js", want: true},                      // JS indexer
		{text: `assert cfg['password'] == '` + pw + `'`, path: "test_cfg.py", want: true},           // comparison
		{text: `return req.body.password === '` + pw + `'`, path: "login.ts", want: true},           // strict comparison
		{text: `      password = Some("` + pw + `"),`, path: "Conf.scala", want: true},              // Option wrapper
		{text: `	Password: types.StringValue("` + pw + `"),`, path: "provider_test.go", want: true}, // Terraform value
		{text: `final StringCredentialValue password = new StringCredentialValue("` + pw + `");`, path: "T.java", want: true},
		{text: `char[] password = "` + pw + `".toCharArray();`, path: "Ks.java", want: true},
		{text: `const proxyPass   = "` + pw + `";`, path: "P.cs", want: true},
		{text: `con = pymysql.Connect(host="127.0.0.1", user="root", password="x7Qe", charset="utf8")`, want: true}, // 4 chars
		{text: `    pass => 'a9Kd2',`, path: "conf.pl", want: true},                                                 // 5 chars
		{text: `KIBANA_PASSWORD = "T8j@jl T5w@dr P5f@ir"`, path: "S.java", want: true},                              // spaced passphrase with digits
		{text: `auth_password="9vnz b2ukyquf",`, path: "client.py", want: true},                                     // kwarg with a space
		{text: `password: "` + g2(alnum+"!@#^&*", 18) + `"`, path: "values.yml", want: true},                        // symbols
		// must not catch: UI text, labels, versions, settings, references
		{text: `  "LABEL_NEW_PASSWORD": "Nyt kodeord",`, path: "i18n/da.json", want: false},
		{text: `  "FORGOT_PASSWORD": "Glemt din adgangskode?",`, path: "i18n/da.json", want: false},
		{text: `  "LABEL_PASSWORD_REPEAT": "パスワードを再入力してください",`, path: "i18n/ja.json", want: false},
		{text: `		'labelPassword'     : 'Clau:',`, path: "lang.js", want: false},
		{text: `  "hint": "", "password": "Must be at least 8 characters long"`, path: "a.json", want: false},
		{text: `        "parse-passwd": "1.0.0"`, path: "package.json", want: false},
		{text: `$config['password_charset'] = 'UTF-8';`, path: "config.php", want: false},
		{text: `config.Password.Algorithm = "sha512"`, path: "conf.go", want: false},
		{text: `self.__pwd = 'C:\\'`, path: "fs.py", want: false},
		{text: `password = "${DB_PASSWORD}"`, want: false},
		{text: `password = "<your password>"`, want: false},
		{text: `password: "changeme"`, want: false},
		{text: `password = "invalid-password"`, want: false},
		{text: `password: "abc"`, want: false}, // 3 chars: below the minimum
		// borderline (pinned): word-like and low-entropy passwords
		{text: `password: 'pass1'`, path: "test/conf.json", want: false,
			why: "one-word default plus digit: dropped as a placeholder (ledger reason placeholder-vocabulary); a real weak credential like this is the accepted cost"},
		{text: `password = "SuperSecretPassword2024"`, want: true,
			why: "word-like with digits: weak passwords look like this, reported low"},
		{text: `password = "correcthorsebattery"`, want: false,
			why: "digit-free dictionary words read as a label; real passphrases of words are knowingly missed"},
		{text: `password = "aaaa1111"`, want: true,
			why: "repetitive but not a placeholder word: reported (low entropy is not evidence of a placeholder)"},
		{text: `password: "omq amqltypznj"`, want: false,
			why: "spaced value without digits reads as UI text; random letter-only passphrases are knowingly missed"},
		{text: `password: 'ozyy'`, want: true,
			why: "4-letter value with no structure: reported (CredData T); word-like 4-letter values such as 'john' too"},
		{text: `"password": "rltskqifajd-meyphmdn"`, want: false,
			why: "digit-free hyphenated value: weak-password filter treats it as a label; knowingly missed"},
	})
}
