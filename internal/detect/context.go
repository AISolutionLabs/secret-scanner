// SPDX-License-Identifier: Apache-2.0

package detect

import (
	"net/netip"
	"regexp"
	"strings"

	"github.com/AISolutionLabs/secret-scanner/internal/config"
)

// Finding contexts. A credential for a local or development service, or in
// an example/template file, is still reported (a strict policy must see it),
// but it is capped at low confidence and does not block under balanced.
const (
	ContextLocal   = "local"   // localhost, private network, docker-compose service, .env.test
	ContextExample = "example" // .env.example / .env.sample / templates
)

var (
	// docker-compose.yml, docker-compose.override.yaml, compose.yaml, compose.dev.yml
	composePath = regexp.MustCompile(`(?i)(?:^|/)(?:docker-)?compose(?:[._-][\w.-]*)?\.ya?ml$`)
	envExample  = regexp.MustCompile(`(?i)(?:^|/)\.env\.(?:example|sample|template|tmpl|tpl|dist|defaults?|skel)$|(?:^|/)(?:example|sample|template)\.env$|\.env\.(?:example|sample|template|dist)\.[\w]+$`)
	envLocal    = regexp.MustCompile(`(?i)(?:^|/)\.env\.(?:test|testing|local|dev|development|ci)(?:\.local)?$`)
	// Single-label hosts that are docker-compose / dev-environment service names.
	serviceHosts = map[string]bool{"db": true, "database": true, "postgres": true, "postgresql": true, "pg": true, "mysql": true,
		"mariadb": true, "redis": true, "mongo": true, "mongodb": true, "rabbitmq": true, "rabbit": true, "elasticsearch": true,
		"elastic": true, "memcached": true, "minio": true, "kafka": true, "zookeeper": true, "cache": true, "mssql": true,
		"sqlserver": true, "oracle": true, "couchdb": true, "cassandra": true, "neo4j": true, "influxdb": true, "keycloak": true,
		"broker": true, "mq": true, "amqp": true, "smtp": true, "mailhog": true, "mailpit": true, "localstack": true}
	urlHost  = regexp.MustCompile(`@(\[[0-9a-fA-F:.]+\]|[A-Za-z0-9.-]+)`)
	connHost = regexp.MustCompile(`(?i)(?:\bserver|\bhost|\bhostname|data source|\baddress|\baddr)\s*=\s*(?:tcp:)?([^;,'"\s\\]+)|://(?:[^@/\s'"]*@)?(\[[0-9a-fA-F:.]+\]|[A-Za-z0-9.-]+)`)
)

// localHost reports loopback, private, link-local and unspecified addresses,
// .local/.localhost names and docker-compose service names.
func localHost(h string) bool {
	h = strings.ToLower(strings.Trim(h, "[]."))
	if h == "" {
		return false
	}
	if h == "localhost" || h == "(local)" || h == "(localdb)" || strings.HasPrefix(h, "(localdb)") ||
		strings.HasSuffix(h, ".localhost") || strings.HasSuffix(h, ".local") || h == "host.docker.internal" {
		return true
	}
	if a, err := netip.ParseAddr(h); err == nil {
		return a.IsLoopback() || a.IsPrivate() || a.IsUnspecified() || a.IsLinkLocalUnicast()
	}
	return serviceHosts[h]
}

// findingContext classifies where a contextual credential is used. It never
// applies to provider-specific formats.
func findingContext(rule *config.CompiledRule, path, match, line string) (string, string) {
	if !contextual(rule) || rule.Re == nil {
		return "", ""
	}
	switch {
	case envExample.MatchString(path):
		return ContextExample, "in an example/template env file"
	case envLocal.MatchString(path):
		return ContextLocal, "in a local/test env file"
	case composePath.MatchString(path):
		return ContextLocal, "in a docker-compose service definition (local development)"
	}
	if rule.HasTag("url") {
		if m := urlHost.FindAllStringSubmatch(match, -1); len(m) > 0 {
			if h := m[len(m)-1][1]; localHost(h) {
				return ContextLocal, "credential for a local service (" + h + ")"
			}
		}
		return "", ""
	}
	if rule.HasTag("credentials") {
		for _, m := range connHost.FindAllStringSubmatch(line, 3) {
			h := m[1]
			if h == "" {
				h = m[2]
			}
			if i := strings.LastIndexAny(h, ":,"); i > 0 && !strings.Contains(h, "]") && strings.Count(h, ":") <= 1 {
				h = h[:i] // host:port, host,port
			}
			if localHost(h) {
				return ContextLocal, "credential for a local service (" + h + ")"
			}
		}
	}
	return "", ""
}

// applyContext records the context and caps confidence at low.
func applyContext(fd *Finding, ctx, why string) {
	if ctx == "" {
		return
	}
	fd.Context = ctx
	fd.Confidence = Low
	fd.Evidence = append(append([]string(nil), fd.Evidence...), ContextCapPrefix+why)
}

// ContextCapPrefix starts the evidence line of a finding capped at low for
// its local/example context.
const ContextCapPrefix = "capped at low: "
