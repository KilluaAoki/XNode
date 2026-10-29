package core

import (
	"strings"
)

func NeedsSniff(routes []RouteRule, rules []CustomRouteRule, raw []map[string]any) bool {
	for _, r := range routes {
		switch PanelRouteKind(r.Action) {
		case "", PanelRouteDNS:
			continue
		}
		m := ParsePanelRouteMatch(r.Action, r.Match)
		if m.HasDomain() || len(m.Protocols) > 0 {
			return true
		}
	}
	for _, r := range rules {
		if !r.Disabled && (len(r.Match.Domains) > 0 || len(r.Match.DomainSuffixes) > 0) {
			return true
		}
	}
	for _, r := range raw {
		for k := range r {
			if strings.Contains(k, "domain") || k == "geosite" || k == "rule_set" || k == "protocol" {
				return true
			}
		}
	}
	return false
}
