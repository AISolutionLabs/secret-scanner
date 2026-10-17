// SPDX-License-Identifier: Apache-2.0

package detect_test

import "testing"

// Passwords in SQL statements, environment assignments, command lines and
// calls. Same three directions as recall_test.go.

func TestSQLPassword(t *testing.T) {
	pw := g2(alnum, 12) + "!"
	checkRule(t, "sql-password", []recallCase{
		// must catch
		{text: `CREATE USER 'app'@'%' IDENTIFIED BY '` + pw + `';`, path: "db/init.sql", want: true},
		{text: `mysql -uroot -e 'CREATE USER gotest IDENTIFIED BY "` + pw + `"'`, path: ".travis.yml", want: true},
		{text: `echo CREATE USER typeorm IDENTIFIED BY ` + g2(alnum, 10) + `\; >> /tmp/user.sql`, path: "ci.yml", want: true}, // Oracle, unquoted
		{text: `CREATE ROLE reporting LOGIN PASSWORD '` + pw + `';`, path: "schema.sql", want: true},
		{text: `ALTER USER postgres WITH PASSWORD '` + pw + `';`, path: "Dockerfile", want: true},
		{text: `CREATE USER IF NOT EXISTS sandy WITH PASSWORD '` + pw + `' NOSUPERUSER;`, want: true},
		{text: `CREATE LOGIN svc WITH PASSWORD = '` + pw + `', CHECK_POLICY = OFF;`, want: true},
		{text: `GRANT ALL ON app.* TO 'app'@'localhost' IDENTIFIED BY '` + pw + `';`, want: true},
		{text: `SET PASSWORD FOR 'root'@'localhost' = PASSWORD('` + pw + `');`, want: true},
		{text: `su -c "psql -c \"ALTER USER postgres WITH PASSWORD '` + pw + `';\"" - postgres`, path: "build.sh", want: true},
		// must not catch
		{text: `CREATE USER app IDENTIFIED BY :password;`, want: false},                                      // bind parameter
		{text: `ALTER USER app WITH PASSWORD $1`, want: false},                                               // bind parameter
		{text: "db.Exec(`ALTER USER ` + user + ` PASSWORD '` + newpw + `'`)", path: "store.go", want: false}, // concatenation
		{text: `mysql_query("set password for 'root'@'localhost' = PASSWORD('{$password}')");`, want: false}, // interpolation
		{text: `CREATE LOGIN %%USER%% WITH PASSWORD = '%%PWD%%'`, want: false},                               // template
		{text: `CREATE USER app WITH PASSWORD '${DB_PASSWORD}';`, want: false},                               // template
		{text: `ALTER USER app PASSWORD EXPIRE;`, want: false},                                               // keyword
		{text: `ALTER ROLE app PASSWORD NULL;`, want: false},                                                 // keyword
		{text: `CREATE USER app WITH PASSWORD 'password';`, want: false},                                     // placeholder
		{text: `-- the user is identified by the token in the header`, want: false},                          // prose
		{text: `grant_type=password&username=alice`, want: false},                                            // OAuth form
		{text: `header grants the accounts identified by account IDs permissions`, want: false},              // prose GRANT
		{text: `set password(e){this[u].url.password=e}get username(){}`, path: "a.js", want: false},         // JS setter
		{text: `CREATE USER app WITH PASSWORD encrypted_pw;`, want: false},                                   // bare value only after IDENTIFIED BY
		// borderline (pinned)
		{text: `ALTER USER 'test'@'1.1.1.1' IDENTIFIED WITH 'mysql_native_password' AS '*` + g2(hexs, 40) + `';`, want: true,
			why: "a mysql_native_password hash authenticates in the native protocol (pass-the-hash), so it is reported"},
		{text: `CREATE USER db1 WITH PASSWORD 'db1';`, want: true,
			why: "one-word default plus digit outside test/doc files: reported at low confidence (DefaultPasswordEvidence), listed for review under balanced"},
	})
}

func TestEnvPasswordAssignment(t *testing.T) {
	pw := g2(alnum, 14)
	checkRule(t, "env-password-assignment", []recallCase{
		// must catch
		{text: `      - MYSQL_ROOT_PASSWORD=` + pw, path: "docker-compose.yml", want: true},
		{text: `docker run -d -e MYSQL_PASSWORD=` + pw + ` -e MYSQL_USER=app mysql`, path: ".travis.yml", want: true},
		{text: `docker run -e "SA_PASSWORD=` + pw + `" -p 1433:1433 mssql`, path: "test.cmd", want: true},
		{text: `- run: 'PGPASSWORD=` + pw + ` psql -h 127.0.0.1 -U ci -f setup.sql'`, path: "ci.yml", want: true},
		{text: `ENV TRUST_STORE_PASSWORD=` + pw, path: "docker/Dockerfile.base", want: true},
		{text: `MAILGUN_PASSWORD=` + pw, path: "deploy/settings.example", want: true},
		{text: `ENV="MYSQL_ROOT_PASSWORD=` + pw + `"`, path: "conf/docker", want: true},
		{text: `GRAPHITE_PASS=` + pw, path: "conf/app.example", want: true},
		// must not catch
		{text: `      - MYSQL_ROOT_PASSWORD=${MYSQL_ROOT_PASSWORD}`, path: "docker-compose.yml", want: false},
		{text: `      - POSTGRES_PASSWORD_FILE=/run/secrets/db_password`, path: "docker-compose.yml", want: false},
		{text: `      - MYSQL_ALLOW_EMPTY_PASSWORD=yes`, path: "docker-compose.yml", want: false},
		{text: `MAILU_PASSWORD_SCHEME=SHA512-CRYPT`, path: "mailu.env.example", want: false},
		{text: `ERR_INVALID_PASSWORD=INVALID_PASSWORD`, path: "codes.properties", want: false},
		{text: `DB_PASSWORD=$(cat /run/secrets/db)`, path: "start.sh", want: false},
		{text: `DB_PASSWORD=changeme`, path: "start.sh", want: false},
		{text: `BYPASS=1 COMPASS=north make`, path: "build.sh", want: false},
		{text: `db_password=os.environ["DB_PASSWORD"]`, path: "settings.py", want: false}, // lowercase code, not env
		// borderline (pinned)
		{text: `      - MYSQL_PASSWORD=` + "bbaruf", path: "docker-compose.yml", want: false,
			why: "digit-free word-like values are dropped by the weak-password filter (labels like INVALID_PASSWORD look the same); knowingly missed"},
		{text: `#DATASOURCE_PASSWORD=` + pw, path: "docker/app", want: false,
			why: "commented-out assignments are not matched: CredData labels them both ways"},
		{text: `MYSQL_Password=` + pw, path: "conf.dist", want: false,
			why: "mixed-case names are not environment-style; password-in-config covers .env/.ini files"},
		{text: `export DB_PASSWORD=test123456`, path: "test/docker/run.sh", want: false,
			why: "test + digits: dropped by the dummy-value filter (ledger reason placeholder-vocabulary)"},
	})
}

func TestCLIPasswordArgument(t *testing.T) {
	pw := g2(alnum, 12)
	checkRule(t, "cli-password-argument", []recallCase{
		// must catch
		{text: `curl -u jacknich:` + pw + `@x1 http://localhost:9200/_cluster/health`, path: "docs/rest.asciidoc", want: true},
		{text: `curl -X PUT -u "` + g2(hexs, 32) + `:` + g2(hexs, 32) + `" \`, path: "README.md", want: true},
		{text: `curl --user admin:` + pw + ` https://jenkins/api/json`, path: "ci.sh", want: true},
		{text: `openssl pkcs12 -export -out server.p12 -name cert -password pass:` + pw, path: "certs.sh", want: true},
		{text: `RUN openssl genrsa -out key.pem -passout pass:` + pw + ` 4096`, path: "Dockerfile", want: true},
		{text: `sshpass -p '` + pw + `' ssh root@10.0.0.5`, path: "deploy.sh", want: true},
		{text: `mysql -uroot -p` + pw + ` -e "show databases"`, path: "backup.sh", want: true},
		{text: `curl -X POST -F 'username=davidwalsh' -F 'password=` + pw + `' http://domain.tld/login`, path: "notes.txt", want: true},
		{text: `curl -s https://cmdb/rest.php -d "auth_user=ops" -d "auth_pwd=` + pw + `"`, path: "notes.txt", want: true},
		{text: `body = 'version=1.2&auth_user=ops&auth_pwd=` + pw + `&json_data={}';`, path: "client.m", want: true},
		// must not catch
		{text: `curl -u "$USER:$PASS" https://h`, path: "ci.sh", want: false},
		{text: `curl -u user:password https://h`, path: "README.md", want: false},
		{text: `curl -u admin https://h`, path: "README.md", want: false}, // password prompted
		{text: `openssl rsa -passin env:KEY_PASS -in k.pem`, path: "certs.sh", want: false},
		{text: `openssl rsa -passin file:/run/secrets/pass -in k.pem`, path: "certs.sh", want: false},
		{text: `mysql -u root -p -e "show databases"`, path: "backup.sh", want: false},
		{text: `mysql -u root -p$MYSQL_ROOT_PASSWORD`, path: "backup.sh", want: false},
		{text: `// Example for binding a HTML form (user=manu&password=123)`, path: "README.md", want: false},
		{text: `https://h/login?user=alice&password={password}`, path: "README.md", want: false},
		// borderline (pinned)
		{text: `mysql -uzabbix -pzabbix zabbix < schema.sql`, path: "install.sh", want: true,
			why: "password equal to the user is weak but it is the credential the script uses"},
	})
}

func TestPasswordCallAndTokenSetter(t *testing.T) {
	pw := g2(alnum, 12)
	checkRule(t, "password-call", []recallCase{
		// must catch
		{text: `req.SetBasicAuth("deploy", "` + pw + `")`, path: "client.go", want: true},
		{text: `var cred = new GitCredential("alice", "` + pw + `");`, path: "Tests.cs", want: true},
		{text: `new NetworkCredential("svc", "` + pw + `")`, path: "Mail.cs", want: true},
		{text: `requests.get(url, auth=HTTPBasicAuth('svc', '` + pw + `'))`, path: "c.py", want: true},
		{text: `requests.get(url, auth=("svc", "` + pw + `"))`, path: "c.py", want: true},
		{text: `ksFactory.setPassword("` + pw + `");`, path: "Ks.java", want: true},
		{text: `bean.setKeyPassword("` + pw + `");`, path: "Ks.java", want: true},
		{text: `new UsernamePasswordAuthenticationToken("admin", "` + pw + `")`, path: "Auth.java", want: true},
		// must not catch
		{text: `keyring.set_password("pgcli", key, passwd)`, path: "c.py", want: false}, // first arg is the service
		{text: `ds.setPassword(System.getenv("DB_PASSWORD"));`, path: "Ds.java", want: false},
		{text: `ds.setPassword(password);`, path: "Ds.java", want: false},
		{text: `ds.setPassword("password");`, path: "Ds.java", want: false},
		{text: `ds.setPassword("${db.password}");`, path: "Ds.java", want: false},
		{text: `req.SetBasicAuth(user, pass)`, path: "client.go", want: false},
		{text: `auth("login", "submit-button")`, path: "ui.js", want: false},
		// borderline (pinned)
		{text: `user.set_password("john")`, path: "tests/test_login.py", want: true,
			why: "short name-like password in a test: reported at low confidence (CredData labels this one F); dummy classification is out of scope here"},
	})
	tok := g2(alnum, 40)
	checkRule(t, "token-setter", []recallCase{
		// must catch
		{text: `resty.SetAuthToken("` + g2("0123456789ABCDEF", 64) + `")`, path: "README.md", want: true},
		{text: `client.withToken("` + tok + `")`, path: "c.js", want: true},
		{text: `api.setApiKey('` + tok + `');`, path: "c.js", want: true},
		{text: `SetAuthToken("` + uuid() + `").`, path: "README.md", want: true},
		// must not catch
		{text: `client.SetAuthToken(os.Getenv("API_TOKEN"))`, path: "c.go", want: false},
		{text: `client.SetAuthToken("<auth-token-value-comes-here>")`, path: "c.go", want: false},
		{text: `client.setToken("YOUR_ACCESS_TOKEN_HERE")`, path: "c.js", want: false},
		{text: `ctx.setSecret("database-password-secret-name")`, path: "c.js", want: false},
		{text: `client.SetAuthToken("ghp_` + g2(alnum, 36) + `")`, path: "c.go", want: false, why: "yields to github-pat"},
		// borderline (pinned)
		{text: `StpUtil.login(10001, new SaLoginModel().setToken("sypp-lhoe-jfxa-blsz"));`, path: "T.java", want: false,
			why: "digit-free hyphenated words read as a label, not a token; knowingly missed"},
	})
}
