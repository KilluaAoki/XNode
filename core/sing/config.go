package sing

import (
	"net"
	"strconv"
	"strings"

	"github.com/KilluaAoki/XNode/common/nlog"
	"github.com/KilluaAoki/XNode/conf"
	"github.com/KilluaAoki/XNode/core"
)

type M = map[string]interface{}

func buildConfig(kcfg conf.KernelConfig, nc *core.NodeSpec, users []core.UserSpec, tc core.TLSCert) M {
	var outbounds []M
	tags := make(map[string]bool)

	for _, co := range nc.CustomOutbounds {
		outbounds = append(outbounds, outboundConfigToSingbox(co))
		tags[strings.ToLower(co.Tag)] = true
	}

	if !tags["direct"] {
		outbounds = append([]M{{"type": "direct", "tag": "direct"}}, outbounds...)
	}
	if !tags["block"] {
		outbounds = append(outbounds, M{"type": "block", "tag": "block"})
	}
	outbounds = appendPanelOutbounds(outbounds, tags, nc.Routes)

	cfg := M{
		"log": M{
			"level":     kcfg.LogLevel,
			"timestamp": true,
		},
		"outbounds": outbounds,
	}

	inbound := buildInbound(nc, users, tc)
	if inbound != nil {
		cfg["inbounds"] = []M{inbound}
	}

	customRoutes := nc.CustomRoutes
	ruleSets := newRuleSetIndex(kcfg.GeoDataDir)
	route := buildRoutes(nc.Routes, nc.CustomRouteRules, customRoutes, ruleSets)
	if dns := buildDNS(nc.Routes, ruleSets); dns != nil {
		cfg["dns"] = dns
	}
	if defs := ruleSets.definitions(); len(defs) > 0 {
		route["rule_set"] = defs
	}
	cfg["route"] = route

	mergeCustomSingbox(cfg, kcfg)
	if core.NeedsSniff(nc.Routes, nc.CustomRouteRules, customRoutes) {
		if route, ok := cfg["route"].(M); ok {
			rules, _ := route["rules"].([]M)
			route["rules"] = append([]M{{"action": "sniff"}}, rules...)
		}
	}
	return cfg
}

func outboundConfigToSingbox(oc core.OutboundConfig) M {
	m := M{
		"type": oc.Protocol,
		"tag":  oc.Tag,
	}

	if oc.Protocol == "wireguard" {
		if sk, ok := oc.Settings["secret_key"]; ok {
			m["private_key"] = sk
		}
		if peers, ok := oc.Settings["peers"].([]any); ok {
			var wgPeers []M
			for _, p := range peers {
				if peerMap, ok := p.(map[string]any); ok {
					newPeer := M{}
					for k, v := range peerMap {
						if k == "endpoint" {
							if ep, ok := v.(string); ok {
								host, portStr, err := net.SplitHostPort(ep)
								if err == nil {
									newPeer["address"] = host
									port, _ := strconv.Atoi(portStr)
									newPeer["port"] = port
								} else {
									newPeer["address"] = ep
								}
							}
						} else {
							newPeer[k] = v
						}
					}
					wgPeers = append(wgPeers, newPeer)
				}
			}
			m["peers"] = wgPeers
		}

		for k, v := range oc.Settings {
			if k != "secret_key" && k != "peers" {
				m[k] = v
			}
		}
	} else {
		for k, v := range oc.Settings {
			m[k] = v
		}
	}

	if oc.ProxyTag != "" {
		m["proxy_tag"] = oc.ProxyTag
	}
	return m
}

func buildRoutes(panelRoutes []core.RouteRule, customRules []core.CustomRouteRule, custom []map[string]any, ruleSets *ruleSetIndex) M {
	var rules []M

	for _, rule := range customRules {
		if rule.Disabled {
			continue
		}
		rules = append(rules, compileCustomRouteRule(rule, ruleSets)...)
	}

	for _, cr := range custom {
		rules = append(rules, M(cr))
	}

	rules = append(rules,
		M{
			"outbound": "block",
			"ip_cidr": []string{
				"10.0.0.0/8",
				"100.64.0.0/10",
				"127.0.0.0/8",
				"169.254.0.0/16",
				"172.16.0.0/12",
				"192.0.0.0/24",
				"192.168.0.0/16",
				"198.18.0.0/15",
			},
		},
		M{
			"outbound": "block",
			"ip_cidr": []string{
				"fc00::/7",
				"fe80::/10",
				"::1/128",
			},
		},
	)

	for _, pr := range panelRoutes {
		rules = append(rules, compilePanelRouteRule(pr, ruleSets)...)
	}

	final := "direct"
	if tag := panelDefaultOutbound(panelRoutes); tag != "" {
		final = tag
	}
	return M{
		"final": final,
		"rules": rules,
	}
}

func compilePanelRouteRule(pr core.RouteRule, ruleSets *ruleSetIndex) []M {
	if len(pr.Match) == 0 {
		return nil
	}

	var outbound string
	switch core.PanelRouteKind(pr.Action) {
	case core.PanelRouteDNS:
		return nil
	case core.PanelRouteBlock:
		outbound = "block"
	case core.PanelRouteDirect:
		outbound = "direct"
	case core.PanelRouteProxy:
		outbound = strings.TrimSpace(pr.ActionValue)
		if outbound == "" {
			nlog.Core().Warn("sing-box: panel proxy route has no outbound tag, rule skipped", "id", pr.ID)
			return nil
		}
	case core.PanelRouteOutbound:
		tag, _, err := singPanelOutbound(pr.ActionValue)
		if err != nil {
			nlog.Core().Warn("sing-box: invalid panel route outbound, rule skipped", "id", pr.ID, "action", pr.Action, "error", err)
			return nil
		}
		outbound = tag
	case core.PanelRouteDefaultOut:
		// Applied as route.final by buildRoutes.
		return nil
	default:
		nlog.Core().Warn("sing-box: unsupported panel route action, rule skipped", "id", pr.ID, "action", pr.Action)
		return nil
	}

	match := core.ParsePanelRouteMatch(pr.Action, pr.Match)
	if len(match.Invalid) > 0 {
		nlog.Core().Warn("sing-box: invalid panel route match items ignored", "id", pr.ID, "items", match.Invalid)
	}

	compiled := singboxDomainRules(match, ruleSets, "outbound", outbound)
	if len(match.IPCIDRs) > 0 {
		compiled = append(compiled, M{
			"ip_cidr":  normalizeIPCIDRs(match.IPCIDRs),
			"outbound": outbound,
		})
	}
	if tags := ruleSets.refs("geoip", match.GeoIPs); len(tags) > 0 {
		compiled = append(compiled, M{
			"rule_set": tags,
			"outbound": outbound,
		})
	}
	if len(match.Protocols) > 0 {
		compiled = append(compiled, M{
			"protocol": copyStrings(match.Protocols),
			"outbound": outbound,
		})
	}
	if len(match.Ports) > 0 {
		ports, portRanges := splitPorts(match.Ports)
		entry := M{"outbound": outbound}
		if len(ports) > 0 {
			entry["port"] = ports
		}
		if len(portRanges) > 0 {
			entry["port_range"] = portRanges
		}
		compiled = append(compiled, entry)
	}
	return compiled
}

// singboxDomainRules emits one rule per domain matcher type, each carrying
// key: value (e.g. "outbound": "block" for route rules, "server": tag for DNS).
func singboxDomainRules(match core.PanelRouteMatch, ruleSets *ruleSetIndex, key, value string) []M {
	var compiled []M
	add := func(field string, values []string) {
		if len(values) > 0 {
			compiled = append(compiled, M{field: copyStrings(values), key: value})
		}
	}
	add("domain", match.Domains)
	add("domain_suffix", match.DomainSuffixes)
	add("domain_keyword", match.DomainKeywords)
	add("domain_regex", match.DomainRegexps)
	add("rule_set", ruleSets.refs("geosite", match.GeoSites))
	return compiled
}

// normalizeIPCIDRs turns bare IP addresses into single-host prefixes.
func normalizeIPCIDRs(values []string) []string {
	out := make([]string, 0, len(values))
	for _, v := range values {
		if !strings.Contains(v, "/") {
			if ip := net.ParseIP(v); ip != nil {
				if ip.To4() != nil {
					v += "/32"
				} else {
					v += "/128"
				}
			}
		}
		out = append(out, v)
	}
	return out
}

// splitGeoValues separates "<prefix>name" entries from plain values.
func splitGeoValues(values []string, prefix string) (plain, names []string) {
	for _, v := range values {
		if name, ok := core.CutGeoPrefix(v, prefix); ok {
			names = append(names, name)
			continue
		}
		plain = append(plain, v)
	}
	return plain, names
}

func compileCustomRouteRule(rule core.CustomRouteRule, ruleSets *ruleSetIndex) []M {
	if rule.Disabled {
		return nil
	}

	outbound := singboxOutboundForAction(rule.Action)
	var compiled []M

	domains, domainSites := splitGeoValues(rule.Match.Domains, "geosite:")
	suffixes, suffixSites := splitGeoValues(rule.Match.DomainSuffixes, "geosite:")
	cidrs, geoIPs := splitGeoValues(rule.Match.IPCIDRs, "geoip:")
	sourceCIDRs, sourceGeoIPs := splitGeoValues(rule.Match.SourceCIDRs, "geoip:")

	if len(domains) > 0 {
		compiled = append(compiled, M{
			"domain":   domains,
			"outbound": outbound,
		})
	}
	if len(suffixes) > 0 {
		compiled = append(compiled, M{
			"domain_suffix": suffixes,
			"outbound":      outbound,
		})
	}
	if tags := ruleSets.refs("geosite", append(domainSites, suffixSites...)); len(tags) > 0 {
		compiled = append(compiled, M{
			"rule_set": tags,
			"outbound": outbound,
		})
	}
	if len(cidrs) > 0 {
		compiled = append(compiled, M{
			"ip_cidr":  cidrs,
			"outbound": outbound,
		})
	}
	if tags := ruleSets.refs("geoip", geoIPs); len(tags) > 0 {
		compiled = append(compiled, M{
			"rule_set": tags,
			"outbound": outbound,
		})
	}
	if len(rule.Match.Ports) > 0 {
		ports, portRanges := splitPorts(rule.Match.Ports)
		entry := M{"outbound": outbound}
		if len(ports) > 0 {
			entry["port"] = ports
		}
		if len(portRanges) > 0 {
			entry["port_range"] = portRanges
		}
		compiled = append(compiled, entry)
	}
	if len(rule.Match.Networks) > 0 {
		compiled = append(compiled, M{
			"network":  copyStrings(rule.Match.Networks),
			"outbound": outbound,
		})
	}
	if len(sourceCIDRs) > 0 {
		compiled = append(compiled, M{
			"source_ip_cidr": sourceCIDRs,
			"outbound":       outbound,
		})
	}
	if tags := ruleSets.refs("geoip", sourceGeoIPs); len(tags) > 0 {
		compiled = append(compiled, M{
			"rule_set":                      tags,
			"rule_set_ip_cidr_match_source": true,
			"outbound":                      outbound,
		})
	}
	if len(rule.Match.SourcePorts) > 0 {
		ports, portRanges := splitPorts(rule.Match.SourcePorts)
		entry := M{"outbound": outbound}
		if len(ports) > 0 {
			entry["source_port"] = ports
		}
		if len(portRanges) > 0 {
			entry["source_port_range"] = portRanges
		}
		compiled = append(compiled, entry)
	}
	return compiled
}

func singboxOutboundForAction(action core.RouteAction) string {
	switch action.Type {
	case "direct":
		return "direct"
	case "route":
		if action.Target != "" {
			return action.Target
		}
		return "block"
	default:
		return "block"
	}
}

func splitPorts(values []string) ([]int, []string) {
	var ports []int
	var ranges []string
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if strings.ContainsAny(value, ":-") {
			ranges = append(ranges, strings.ReplaceAll(value, "-", ":"))
			continue
		}
		if port, err := strconv.Atoi(value); err == nil {
			ports = append(ports, port)
		}
	}
	return ports, ranges
}

func copyStrings(src []string) []string {
	if len(src) == 0 {
		return nil
	}
	out := make([]string, len(src))
	copy(out, src)
	return out
}

func mergeCustomSingbox(cfg M, kcfg conf.KernelConfig) {
	custom, err := core.LoadCustomConfig(kcfg.CustomConfig)
	if err != nil {
		nlog.Core().Error("failed to load custom sing-box config", "error", err)
		return
	}
	if custom == nil {
		return
	}

	if v, ok := custom["dns"]; ok {
		cfg["dns"] = v
	}

	if v, ok := custom["experimental"]; ok {
		cfg["experimental"] = v
	}

	if v, ok := custom["outbounds"]; ok {
		if existing, ok := cfg["outbounds"].([]M); ok {
			cfg["outbounds"] = core.MergeOutbounds(existing, v)
		}
	}

	if v, ok := custom["endpoints"]; ok {
		if existing, ok := cfg["endpoints"].([]M); ok {
			cfg["endpoints"] = core.MergeAppendList(existing, v)
		} else {
			if items := core.MergeAppendList(nil, v); len(items) > 0 {
				cfg["endpoints"] = items
			}
		}
	}

	if customRoute, ok := custom["route"]; ok {
		if customRouteMap, ok := customRoute.(map[string]any); ok {
			mergeCustomSingboxRoute(cfg, customRouteMap)
		}
	}
}

func mergeCustomSingboxRoute(cfg M, customRoute map[string]any) {
	route, ok := cfg["route"].(M)
	if !ok {
		route = M{}
		cfg["route"] = route
	}

	if v, ok := customRoute["rules"]; ok {
		if existing, ok := route["rules"].([]M); ok {
			route["rules"] = core.MergePrependList(existing, v)
		}
	}

	if v, ok := customRoute["rule_set"]; ok {
		if existing, ok := route["rule_set"].([]M); ok {
			route["rule_set"] = core.MergeAppendList(existing, v)
		} else {
			route["rule_set"] = core.MergeAppendList(nil, v)
		}
	}

	for k, v := range customRoute {
		if k == "rules" || k == "rule_set" {
			continue
		}
		route[k] = v
	}
}

func buildInbound(nc *core.NodeSpec, users []core.UserSpec, tc core.TLSCert) M {
	base := M{
		"tag":         nc.Protocol + "-in",
		"listen":      listenAddress(nc.ListenIP),
		"listen_port": nc.ServerPort,
		"reuse_addr":  true,
	}
	if len(nc.TrustedXForwardedFor) > 0 {
		nlog.Core().Warn("sing-box: trusted_x_forwarded_for is not supported, use xray kernel for this feature")
	}

	switch nc.Protocol {
	case "shadowsocks":
		return buildShadowsocks(base, nc, users)
	case "vmess":
		return buildVMess(base, nc, users, tc)
	case "vless":
		return buildVLESS(base, nc, users, tc)
	case "trojan":
		return buildTrojan(base, nc, users, tc)
	case "hysteria":
		return buildHysteria(base, nc, users, tc)
	case "tuic":
		return buildTUIC(base, nc, users, tc)
	case "anytls":
		return buildAnyTLS(base, nc, users, tc)
	case "naive":
		return buildNaive(base, nc, users, tc)
	case "socks":
		return buildSocks(base, users)
	case "http":
		return buildHTTP(base, nc, users, tc)
	case "mieru":
		return buildMieru(base, nc, users)
	default:
		return nil
	}
}

func buildMieru(base M, nc *core.NodeSpec, users []core.UserSpec) M {
	base["type"] = "mieru"
	if nc.Transport != "" {
		base["transport"] = nc.Transport
	}
	if nc.TrafficPattern != "" {
		base["traffic_pattern"] = nc.TrafficPattern
	}

	userList := make([]M, 0, len(users))
	for _, u := range users {
		userList = append(userList, M{
			"name":     u.UUID,
			"password": u.UUID,
		})
	}
	base["users"] = userList
	return base
}

type ss2022Config struct {
	method string
	size   int
}

var ss2022Methods = map[string]ss2022Config{
	"2022-blake3-aes-128-gcm":       {"2022-blake3-aes-128-gcm", 16},
	"2022-blake3-aes-256-gcm":       {"2022-blake3-aes-256-gcm", 32},
	"2022-blake3-chacha20-poly1305": {"2022-blake3-chacha20-poly1305", 32},
}

func buildShadowsocks(base M, nc *core.NodeSpec, users []core.UserSpec) M {
	base["type"] = "shadowsocks"
	base["method"] = nc.Cipher

	if _, isSS2022 := ss2022Methods[nc.Cipher]; isSS2022 {
		base["password"] = nc.ServerKey
	}

	userList := make([]M, len(users))
	for i := range users {
		u := &users[i]
		userList[i] = M{
			"name":     u.UUID,
			"password": ssUserPassword(nc.Cipher, u.UUID),
		}
	}
	base["users"] = userList

	if nc.Plugin != "" {
		nlog.Core().Warn("sing-box shadowsocks inbound does not support plugin, ignoring", "plugin", nc.Plugin)
	}

	return base
}

func buildVMess(base M, nc *core.NodeSpec, users []core.UserSpec, tc core.TLSCert) M {
	base["type"] = "vmess"

	userList := make([]M, 0, len(users))
	for _, u := range users {
		userList = append(userList, M{
			"name":    u.UUID,
			"uuid":    u.UUID,
			"alterId": 0,
		})
	}
	base["users"] = userList

	applyTransport(base, nc)
	applyProxyProtocol(base, nc)
	applyMultiplex(base, nc)

	if nc.TLS == 1 {
		if tls := buildTLSConfig(nc, tc); tls != nil {
			base["tls"] = tls
		}
	}

	return base
}

func buildVLESS(base M, nc *core.NodeSpec, users []core.UserSpec, tc core.TLSCert) M {
	if nc.Decryption != "" && nc.Decryption != "none" {
		nlog.Core().Warn("sing-box does not support VLESS encryption (decryption), use xray kernel for this feature")
	}

	base["type"] = "vless"

	userList := make([]M, 0, len(users))
	for _, u := range users {
		user := M{
			"name": u.UUID,
			"uuid": u.UUID,
		}
		if nc.Flow != "" {
			user["flow"] = nc.Flow
		}
		userList = append(userList, user)
	}
	base["users"] = userList

	applyTransport(base, nc)
	applyProxyProtocol(base, nc)
	applyMultiplex(base, nc)

	if nc.TLS == 1 {
		if tls := buildTLSConfig(nc, tc); tls != nil {
			base["tls"] = tls
		}
	} else if nc.TLS == 2 {
		base["tls"] = buildRealityConfig(nc)
	}

	return base
}

func buildTrojan(base M, nc *core.NodeSpec, users []core.UserSpec, tc core.TLSCert) M {
	base["type"] = "trojan"

	userList := make([]M, len(users))
	for i := range users {
		u := &users[i]
		userList[i] = M{
			"name":     u.UUID,
			"password": u.UUID,
		}
	}
	base["users"] = userList

	applyTransport(base, nc)
	applyProxyProtocol(base, nc)
	applyMultiplex(base, nc)

	if nc.TLS == 1 {
		if tls := buildTLSConfig(nc, tc); tls != nil {
			base["tls"] = tls
		}
	} else if nc.TLS == 2 {
		base["tls"] = buildRealityConfig(nc)
	}

	if _, ok := base["tls"]; !ok {
		if tls := buildTLSConfig(nc, tc); tls != nil {
			base["tls"] = tls
		}
	}

	if base["tls"] == nil {
		nlog.Core().Warn("trojan inbound has no TLS (no certificate paths and no Reality); sing-box may refuse to start until cert_mode provides cert/key or Reality is configured")
	}

	return base
}

func buildHysteria(base M, nc *core.NodeSpec, users []core.UserSpec, tc core.TLSCert) M {
	if nc.Version == 2 {
		base["type"] = "hysteria2"

		userList := make([]M, 0, len(users))
		for _, u := range users {
			userList = append(userList, M{
				"name":     u.UUID,
				"password": u.UUID,
			})
		}
		base["users"] = userList

		if nc.Obfs != "" {
			base["obfs"] = M{
				"type":     nc.Obfs,
				"password": nc.ObfsPassword,
			}
		}
		if nc.IgnoreClientBandwidth {
			base["ignore_client_bandwidth"] = true
		}
	} else {
		base["type"] = "hysteria"

		userList := make([]M, 0, len(users))
		for _, u := range users {
			userList = append(userList, M{
				"name":     u.UUID,
				"auth_str": u.UUID,
			})
		}
		base["users"] = userList
		base["up_mbps"] = nc.UpMbps
		base["down_mbps"] = nc.DownMbps

		if nc.Obfs != "" {
			base["obfs"] = nc.Obfs
		}
	}

	tls := buildTLSConfig(nc, tc)
	if tls == nil {
		nlog.Core().Warn("hysteria requires TLS certificate files on disk; configure cert_mode (self, file, http, dns, or content). Sing-box will not start this inbound without tls.")
		return base
	}
	if _, ok := tls["alpn"]; !ok {
		tls["alpn"] = []string{"h3"}
	}
	base["tls"] = tls
	return base
}

func buildTUIC(base M, nc *core.NodeSpec, users []core.UserSpec, tc core.TLSCert) M {
	base["type"] = "tuic"

	userList := make([]M, 0, len(users))
	for _, u := range users {
		userList = append(userList, M{
			"name":     u.UUID,
			"uuid":     u.UUID,
			"password": u.UUID,
		})
	}
	base["users"] = userList

	if nc.CongestionControl != "" {
		base["congestion_control"] = nc.CongestionControl
	}
	if nc.ZeroRTTHandshake {
		base["zero_rtt_handshake"] = true
	}

	tls := buildTLSConfig(nc, tc)
	if tls == nil {
		nlog.Core().Warn("tuic requires TLS certificate files on disk; configure cert_mode (self, file, http, dns, or content). Sing-box will not start this inbound without tls.")
		return base
	}
	if _, ok := tls["alpn"]; !ok {
		tls["alpn"] = []string{"h3"}
	}
	base["tls"] = tls
	return base
}

func buildAnyTLS(base M, nc *core.NodeSpec, users []core.UserSpec, tc core.TLSCert) M {
	base["type"] = "anytls"

	userList := make([]M, 0, len(users))
	for _, u := range users {
		userList = append(userList, M{
			"name":     u.UUID,
			"password": u.UUID,
		})
	}
	base["users"] = userList

	if nc.PaddingScheme != "" {
		base["padding_scheme"] = nc.PaddingScheme
	}

	if tls := buildTLSConfig(nc, tc); tls != nil {
		base["tls"] = tls
	} else {
		nlog.Core().Warn("anytls requires TLS certificate files on disk; configure cert_mode (self, file, http, dns, or content). Sing-box will not start this inbound without tls.")
	}
	return base
}

func buildNaive(base M, nc *core.NodeSpec, users []core.UserSpec, tc core.TLSCert) M {
	base["type"] = "naive"

	userList := make([]M, 0, len(users))
	for _, u := range users {
		userList = append(userList, M{
			"username": strconv.Itoa(u.ID),
			"password": u.UUID,
		})
	}
	base["users"] = userList

	if nc.TLS == 1 {
		if tls := buildTLSConfig(nc, tc); tls != nil {
			base["tls"] = tls
			return base
		}
	}
	base["network"] = "tcp"
	return base
}

func buildSocks(base M, users []core.UserSpec) M {
	base["type"] = "socks"

	userList := make([]M, 0, len(users))
	for _, u := range users {
		userList = append(userList, M{
			"username": u.UUID,
			"password": u.UUID,
		})
	}
	base["users"] = userList
	return base
}

func buildHTTP(base M, nc *core.NodeSpec, users []core.UserSpec, tc core.TLSCert) M {
	base["type"] = "http"

	userList := make([]M, 0, len(users))
	for _, u := range users {
		userList = append(userList, M{
			"username": u.UUID,
			"password": u.UUID,
		})
	}
	base["users"] = userList

	applyProxyProtocol(base, nc)
	if nc.TLS == 1 {
		if tls := buildTLSConfig(nc, tc); tls != nil {
			base["tls"] = tls
		}
	}
	return base
}

func applyTransport(base M, nc *core.NodeSpec) {
	if nc.Network == "" || nc.Network == "tcp" {
		return
	}

	transport := M{"type": nc.Network}

	if nc.NetworkSettings != nil {
		switch nc.Network {
		case "ws":
			if v, ok := nc.NetworkSettings["path"]; ok {
				transport["path"] = v
			}
			if v, ok := nc.NetworkSettings["headers"]; ok {
				transport["headers"] = v
			}
			if v, ok := nc.NetworkSettings["host"]; ok {
				if transport["headers"] == nil {
					transport["headers"] = M{"Host": v}
				}
			}
			if v, ok := nc.NetworkSettings["max_early_data"]; ok {
				transport["max_early_data"] = v
			}
			if v, ok := nc.NetworkSettings["early_data_header_name"]; ok {
				transport["early_data_header_name"] = v
			}
		case "grpc":
			if v, ok := nc.NetworkSettings["serviceName"]; ok {
				transport["service_name"] = v
			} else if v, ok := nc.NetworkSettings["service_name"]; ok {
				transport["service_name"] = v
			}
		case "httpupgrade":
			if v, ok := nc.NetworkSettings["path"]; ok {
				transport["path"] = v
			}
			if v, ok := nc.NetworkSettings["host"]; ok {
				transport["host"] = v
			}
		case "h2", "http":
			transport["type"] = "http"
			if v, ok := nc.NetworkSettings["path"]; ok {
				transport["path"] = v
			}
			if v, ok := nc.NetworkSettings["host"]; ok {
				transport["host"] = v
			}
		}
	}

	base["transport"] = transport
}

func buildTLSConfig(nc *core.NodeSpec, tc core.TLSCert) M {
	if !tc.HasCert() {
		return nil
	}

	t := M{"enabled": true}

	serverName := nc.ServerName
	if serverName == "" && nc.Host != "" {
		serverName = nc.Host
	}
	if serverName != "" {
		t["server_name"] = serverName
	}

	if nc.TLSSettings != nil {
		if sn := core.SettingString(nc.TLSSettings, "server_name"); sn != "" {
			t["server_name"] = sn
		}
		if alpn, ok := nc.TLSSettings["alpn"]; ok && alpn != nil {
			t["alpn"] = alpn
		}
		if ech := extractECHInbound(nc.TLSSettings); ech != nil {
			t["ech"] = ech
		}
		if core.SettingBool(nc.TLSSettings, "reject_unknown_sni") {
			nlog.Core().Warn("sing-box: reject_unknown_sni is not supported, use xray kernel for this feature")
		}
	}

	t["certificate"] = []string{string(tc.CertPEM)}
	t["key"] = []string{string(tc.KeyPEM)}

	return t
}

func buildRealityConfig(nc *core.NodeSpec) M {
	tls := M{"enabled": true}
	if nc.TLSSettings == nil {
		return tls
	}
	s := nc.TLSSettings

	reality := M{"enabled": true}
	if pk := core.SettingString(s, "private_key"); pk != "" {
		reality["private_key"] = pk
	}
	reality["short_id"] = core.RealityShortIDList(s)

	serverName := ""
	if names := core.RealityServerNames(s); len(names) > 0 {
		serverName = names[0]
		if len(names) > 1 {
			nlog.Core().Warn("sing-box: reality accepts a single server name, extra server_names ignored", "used", serverName, "ignored", names[1:])
		}
	}
	if core.SettingPort(s, "xver") > 0 {
		nlog.Core().Warn("sing-box: reality xver is not supported, use xray kernel for this feature")
	}
	if core.SettingString(s, "mldsa65Seed") != "" {
		nlog.Core().Warn("sing-box: reality mldsa65Seed is not supported, use xray kernel for this feature")
	}

	dest := core.SettingString(s, "dest")
	if dest == "" {
		dest = serverName
	}
	if dest != "" {
		handshake := M{"server": dest, "server_port": 443}
		if host, port, err := net.SplitHostPort(dest); err == nil {
			handshake["server"] = host
			if p, err := strconv.Atoi(port); err == nil {
				handshake["server_port"] = p
			}
		} else if p := core.SettingPort(s, "server_port"); p > 0 {
			handshake["server_port"] = p
		}
		reality["handshake"] = handshake
	}

	if serverName != "" {
		tls["server_name"] = serverName
	}

	tls["reality"] = reality
	return tls
}

func applyMultiplex(base M, nc *core.NodeSpec) {
	if nc.Multiplex == nil || !nc.Multiplex.Enabled {
		return
	}

	mux := M{
		"enabled": true,
	}
	if nc.Multiplex.Padding {
		mux["padding"] = true
	}

	if nc.Multiplex.Brutal != nil && nc.Multiplex.Brutal.Enabled {
		brutal := M{
			"enabled": true,
		}
		if nc.Multiplex.Brutal.UpMbps > 0 {
			brutal["up_mbps"] = nc.Multiplex.Brutal.UpMbps
		}
		if nc.Multiplex.Brutal.DownMbps > 0 {
			brutal["down_mbps"] = nc.Multiplex.Brutal.DownMbps
		}
		mux["brutal"] = brutal
	}

	base["multiplex"] = mux
}

func applyProxyProtocol(base M, nc *core.NodeSpec) {
}

func extractECHInbound(tlsSettings map[string]interface{}) M {
	echRaw, ok := tlsSettings["ech"]
	if !ok {
		return nil
	}
	echMap, ok := echRaw.(map[string]interface{})
	if !ok {
		return nil
	}
	enabled, _ := echMap["enabled"].(bool)
	if !enabled {
		return nil
	}
	ech := M{"enabled": true}
	hasSource := false
	if key, _ := echMap["key"].(string); key != "" {
		ech["key"] = []string{key}
		hasSource = true
	}
	if keyPath, _ := echMap["key_path"].(string); keyPath != "" {
		ech["key_path"] = keyPath
		hasSource = true
	}
	if !hasSource {
		nlog.Core().Warn("ECH enabled but no key or key_path provided")
	}
	return ech
}
