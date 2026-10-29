package sing

import (
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"

	"github.com/KilluaAoki/XNode/common/nlog"
	"github.com/KilluaAoki/XNode/core"
)

const localDNSTag = "local"

// buildDNS turns panel "dns" routes into sing-box DNS servers and rules.
// Domains that match no rule fall through to the system resolver ("local").
func buildDNS(routes []core.RouteRule, ruleSets *ruleSetIndex) M {
	servers := []M{{"type": "local", "tag": localDNSTag}}
	serverTags := map[string]string{}
	var rules []M

	for _, rule := range routes {
		if core.PanelRouteKind(rule.Action) != core.PanelRouteDNS {
			continue
		}
		value := strings.TrimSpace(rule.ActionValue)
		if value == "" {
			nlog.Core().Warn("sing-box: panel dns route has no server, rule skipped", "id", rule.ID)
			continue
		}
		match := core.ParsePanelRouteMatch(rule.Action, rule.Match)
		if !match.HasDomain() {
			nlog.Core().Warn("sing-box: panel dns route needs domain matches, rule skipped", "id", rule.ID)
			continue
		}

		tag, ok := serverTags[value]
		if !ok {
			tag = fmt.Sprintf("dns-%d", len(servers))
			server, err := singboxDNSServer(value, tag)
			if err != nil {
				nlog.Core().Warn("sing-box: invalid panel dns server, rule skipped", "id", rule.ID, "server", value, "error", err)
				continue
			}
			if server == nil {
				tag = localDNSTag
			} else {
				servers = append(servers, server)
			}
			serverTags[value] = tag
		}
		rules = append(rules, singboxDomainRules(match, ruleSets, "server", tag)...)
	}

	if len(rules) == 0 {
		return nil
	}
	return M{
		"servers": servers,
		"rules":   rules,
		"final":   localDNSTag,
	}
}

// singboxDNSServer parses a panel DNS address such as "1.1.1.1",
// "8.8.8.8:53", "tcp://1.1.1.1", "tls://dns.google" or
// "https://dns.google/dns-query". It returns nil for the system resolver.
func singboxDNSServer(value, tag string) (M, error) {
	lower := strings.ToLower(value)
	if lower == "localhost" || lower == "local" {
		return nil, nil
	}

	serverType := "udp"
	var host, port, path string
	if strings.Contains(value, "://") {
		u, err := url.Parse(value)
		if err != nil {
			return nil, err
		}
		serverType = strings.ToLower(u.Scheme)
		host, port, path = u.Hostname(), u.Port(), u.Path
	} else if h, p, err := net.SplitHostPort(value); err == nil {
		host, port = h, p
	} else {
		host = strings.TrimSuffix(strings.TrimPrefix(value, "["), "]")
	}

	switch serverType {
	case "udp", "tcp", "tls", "quic", "https", "h3":
	default:
		return nil, fmt.Errorf("unsupported dns scheme %q", serverType)
	}
	if host == "" {
		return nil, fmt.Errorf("missing dns server host")
	}

	server := M{"type": serverType, "tag": tag, "server": host}
	if port != "" {
		n, err := strconv.Atoi(port)
		if err != nil || n <= 0 || n > 65535 {
			return nil, fmt.Errorf("invalid dns server port %q", port)
		}
		server["server_port"] = n
	}
	if path != "" && (serverType == "https" || serverType == "h3") {
		server["path"] = path
	}
	if net.ParseIP(host) == nil {
		server["domain_resolver"] = localDNSTag
	}
	return server, nil
}
