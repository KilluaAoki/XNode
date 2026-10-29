package core

import (
	"encoding/json"
	"errors"
	"net"
	"strings"
)

// Panel route action kinds after normalization.
const (
	PanelRouteBlock  = "block"
	PanelRouteDirect = "direct"
	PanelRouteProxy  = "proxy"
	PanelRouteDNS    = "dns"
	// route / route_ip: send matches to the outbound in action_value.
	PanelRouteOutbound = "outbound"
	// default_out: make the outbound in action_value the fallback.
	PanelRouteDefaultOut = "default_out"
)

// PanelRouteKind maps a panel route action to the behavior XNode implements.
// It returns "" for actions that are not supported.
func PanelRouteKind(action string) string {
	switch strings.ToLower(strings.TrimSpace(action)) {
	case "block", "block_ip", "block_port", "protocol":
		return PanelRouteBlock
	case "direct":
		return PanelRouteDirect
	case "proxy":
		return PanelRouteProxy
	case "dns":
		return PanelRouteDNS
	case "route", "route_ip":
		return PanelRouteOutbound
	case "default_out":
		return PanelRouteDefaultOut
	default:
		return ""
	}
}

// PanelRouteMatch is a panel route match list split by matcher type.
// Prefixes such as "geosite:" or "protocol:" are stripped from the values.
type PanelRouteMatch struct {
	Domains        []string
	DomainSuffixes []string
	DomainKeywords []string
	DomainRegexps  []string
	GeoSites       []string
	IPCIDRs        []string
	GeoIPs         []string
	Protocols      []string
	Ports          []string
	Invalid        []string
}

func (m PanelRouteMatch) HasDomain() bool {
	return len(m.Domains) > 0 || len(m.DomainSuffixes) > 0 || len(m.DomainKeywords) > 0 ||
		len(m.DomainRegexps) > 0 || len(m.GeoSites) > 0
}

// ParsePanelRouteMatch classifies panel match items. Prefixed items
// (full:, domain:, keyword:, regexp:, geosite:, geoip:, protocol:, port:)
// are honored for every action; unprefixed items are interpreted by action:
// IPs for block_ip, ports for block_port, protocols for protocol, and
// IP/CIDR or domain suffix otherwise.
func ParsePanelRouteMatch(action string, items []string) PanelRouteMatch {
	var m PanelRouteMatch
	action = strings.ToLower(strings.TrimSpace(action))
	for _, item := range items {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		prefix, value, hasPrefix := splitMatchPrefix(item)
		if hasPrefix {
			if value == "" {
				m.Invalid = append(m.Invalid, item)
				continue
			}
			switch prefix {
			case "full":
				m.Domains = append(m.Domains, value)
			case "domain":
				m.DomainSuffixes = append(m.DomainSuffixes, value)
			case "keyword":
				m.DomainKeywords = append(m.DomainKeywords, value)
			case "regexp":
				m.DomainRegexps = append(m.DomainRegexps, value)
			case "geosite":
				m.GeoSites = append(m.GeoSites, strings.ToLower(value))
			case "geoip":
				m.GeoIPs = append(m.GeoIPs, strings.ToLower(value))
			case "protocol":
				m.Protocols = append(m.Protocols, strings.ToLower(value))
			case "port":
				m.addPort(item, value)
			}
			continue
		}

		switch action {
		case "block_port":
			m.addPort(item, item)
			continue
		case "protocol":
			m.Protocols = append(m.Protocols, strings.ToLower(item))
			continue
		}
		if isIPOrCIDR(item) {
			m.IPCIDRs = append(m.IPCIDRs, item)
			continue
		}
		if action == "block_ip" || action == "route_ip" {
			m.Invalid = append(m.Invalid, item)
			continue
		}
		suffix := strings.TrimPrefix(strings.TrimPrefix(item, "*."), ".")
		if suffix == "" {
			m.Invalid = append(m.Invalid, item)
			continue
		}
		m.DomainSuffixes = append(m.DomainSuffixes, suffix)
	}
	return m
}

func (m *PanelRouteMatch) addPort(item, value string) {
	if validatePortSpecs([]string{value}, "") != nil {
		m.Invalid = append(m.Invalid, item)
		return
	}
	m.Ports = append(m.Ports, value)
}

var matchPrefixes = []string{"full", "domain", "keyword", "regexp", "geosite", "geoip", "protocol", "port"}

func splitMatchPrefix(item string) (prefix, value string, ok bool) {
	i := strings.Index(item, ":")
	if i <= 0 {
		return "", "", false
	}
	candidate := strings.ToLower(item[:i])
	for _, p := range matchPrefixes {
		if candidate == p {
			return p, strings.TrimSpace(item[i+1:]), true
		}
	}
	return "", "", false
}

func isIPOrCIDR(value string) bool {
	if strings.Contains(value, "/") {
		_, _, err := net.ParseCIDR(value)
		return err == nil
	}
	return net.ParseIP(value) != nil
}

// ParsePanelRouteOutbound parses the action_value of route, route_ip and
// default_out rules. The value is either an existing outbound tag or a JSON
// outbound object carrying its own "tag"; ob is nil for a plain tag.
func ParsePanelRouteOutbound(value string) (tag string, ob map[string]any, err error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", nil, errors.New("empty action_value")
	}
	if !strings.HasPrefix(value, "{") {
		return value, nil, nil
	}
	if err := json.Unmarshal([]byte(value), &ob); err != nil {
		return "", nil, err
	}
	tag, _ = ob["tag"].(string)
	if tag = strings.TrimSpace(tag); tag == "" {
		return "", nil, errors.New("outbound has no tag")
	}
	return tag, ob, nil
}

// GeoRuleNames returns the geosite and geoip names referenced by panel
// routes and custom route rules, deduplicated in first-seen order.
func GeoRuleNames(routes []RouteRule, rules []CustomRouteRule) (sites, ips []string) {
	seenSite := map[string]bool{}
	seenIP := map[string]bool{}
	addSite := func(name string) {
		if name != "" && !seenSite[name] {
			seenSite[name] = true
			sites = append(sites, name)
		}
	}
	addIP := func(name string) {
		if name != "" && !seenIP[name] {
			seenIP[name] = true
			ips = append(ips, name)
		}
	}
	for _, r := range routes {
		if PanelRouteKind(r.Action) == "" {
			continue
		}
		m := ParsePanelRouteMatch(r.Action, r.Match)
		for _, v := range m.GeoSites {
			addSite(v)
		}
		for _, v := range m.GeoIPs {
			addIP(v)
		}
	}
	for _, r := range rules {
		if r.Disabled {
			continue
		}
		for _, v := range append(append([]string{}, r.Match.Domains...), r.Match.DomainSuffixes...) {
			if name, ok := CutGeoPrefix(v, "geosite:"); ok {
				addSite(name)
			}
		}
		for _, v := range append(append([]string{}, r.Match.IPCIDRs...), r.Match.SourceCIDRs...) {
			if name, ok := CutGeoPrefix(v, "geoip:"); ok {
				addIP(name)
			}
		}
	}
	return sites, ips
}

// CutGeoPrefix strips a "geosite:" or "geoip:" style prefix, case-insensitively.
func CutGeoPrefix(value, prefix string) (string, bool) {
	value = strings.TrimSpace(value)
	if len(value) <= len(prefix) || !strings.EqualFold(value[:len(prefix)], prefix) {
		return "", false
	}
	return strings.ToLower(strings.TrimSpace(value[len(prefix):])), true
}
