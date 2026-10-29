package xray

import (
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"net"
	"os"
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
		outbounds = append(outbounds, outboundConfigToXray(co))
		tags[strings.ToLower(co.Tag)] = true
	}

	if !tags["direct"] {
		outbounds = append([]M{{"protocol": "freedom", "tag": "direct"}}, outbounds...)
	} else {
		for i, ob := range outbounds {
			if tag, _ := ob["tag"].(string); i > 0 && strings.EqualFold(tag, "direct") {
				outbounds = append(append([]M{ob}, outbounds[:i]...), outbounds[i+1:]...)
				break
			}
		}
	}
	if !tags["block"] {
		outbounds = append(outbounds, M{"protocol": "blackhole", "tag": "block"})
	}
	outbounds = appendPanelOutbounds(outbounds, tags, nc.Routes)

	cfg := M{
		"log": M{
			"loglevel": xrayLogLevel(kcfg.LogLevel),
			"error":    "",
			"access":   "",
		},
		"stats": M{},
		"policy": M{
			"levels": M{
				"0": levelPolicy(kcfg.XrayPolicy),
			},
			"system": M{
				"statsInboundUplink":    true,
				"statsInboundDownlink":  true,
				"statsOutboundUplink":   true,
				"statsOutboundDownlink": true,
			},
		},
		"outbounds": outbounds,
	}

	customRoutes := nc.CustomRoutes
	inbound := buildInbound(nc, users, tc)
	if inbound != nil {
		if core.NeedsSniff(nc.Routes, nc.CustomRouteRules, customRoutes) {
			inbound["sniffing"] = M{
				"enabled":      true,
				"destOverride": []string{"http", "tls", "quic"},
				"routeOnly":    true,
			}
		}
		cfg["inbounds"] = []M{inbound}
	} else {
		nlog.Core().Warn("xray: unsupported protocol, no inbound configured — node will not accept connections",
			"protocol", nc.Protocol,
			"supported", "vmess, vless, trojan, shadowsocks, hysteria, socks, http")
	}

	cfg["routing"] = buildRouting(nc.Routes, nc.CustomRouteRules, customRoutes)
	if dns := buildDNS(nc.Routes); dns != nil {
		cfg["dns"] = dns
		// freedom resolves with the system resolver under AsIs; route it
		// through the xray DNS module so per-domain servers take effect.
		if !tags["direct"] {
			outbounds[0]["streamSettings"] = M{"sockopt": M{"domainStrategy": "UseIPv4v6"}}
		} else {
			nlog.Core().Warn("xray: panel dns routes need the direct outbound to use a non-AsIs domainStrategy")
		}
	}

	mergeCustomXray(cfg, kcfg)
	return cfg
}

func outboundConfigToXray(oc core.OutboundConfig) M {
	m := M{
		"protocol": oc.Protocol,
		"tag":      oc.Tag,
	}
	if len(oc.Settings) > 0 {
		m["settings"] = oc.Settings
	}
	if oc.ProxyTag != "" {
		m["proxySettings"] = M{"tag": oc.ProxyTag}
	}
	return m
}

func mergeCustomXray(cfg M, kcfg conf.KernelConfig) {
	custom, err := core.LoadCustomConfig(kcfg.CustomConfig)
	if err != nil {
		nlog.Core().Error("failed to load custom xray config", "error", err)
		return
	}
	if custom == nil {
		return
	}

	if v, ok := custom["dns"]; ok {
		cfg["dns"] = v
	}

	if v, ok := custom["outbounds"]; ok {
		if existing, ok := cfg["outbounds"].([]M); ok {
			cfg["outbounds"] = core.MergeOutbounds(existing, v)
		}
	}

	if customRouting, ok := custom["routing"]; ok {
		if customRoutingMap, ok := customRouting.(map[string]any); ok {
			mergeCustomXrayRouting(cfg, customRoutingMap)
		}
	}

	protected := map[string]bool{
		"inbounds": true, "outbounds": true, "routing": true,
		"dns": true, "log": true, "stats": true, "policy": true,
	}
	for k, v := range custom {
		if !protected[k] {
			cfg[k] = v
		}
	}
}

func levelPolicy(p *conf.XrayPolicy) M {
	level := M{
		"statsUserUplink":   true,
		"statsUserDownlink": true,
	}
	if p == nil {
		return level
	}
	for key, v := range map[string]*int{
		"handshake": p.Handshake, "connIdle": p.ConnIdle, "uplinkOnly": p.UplinkOnly,
		"downlinkOnly": p.DownlinkOnly, "bufferSize": p.BufferSize,
	} {
		if v != nil {
			level[key] = *v
		}
	}
	return level
}

func mergeCustomXrayRouting(cfg M, customRouting map[string]any) {
	routing, ok := cfg["routing"].(M)
	if !ok {
		routing = M{}
		cfg["routing"] = routing
	}

	if v, ok := customRouting["rules"]; ok {
		if existing, ok := routing["rules"].([]M); ok {
			routing["rules"] = core.MergePrependList(existing, v)
		}
	}

	for k, v := range customRouting {
		if k == "rules" {
			continue
		}
		routing[k] = v
	}
}

func xrayLogLevel(singboxLevel string) string {
	switch singboxLevel {
	case "trace", "debug":
		return "debug"
	case "info":
		return "info"
	case "warn":
		return "warning"
	case "error":
		return "error"
	case "fatal", "panic":
		return "error"
	default:
		return "warning"
	}
}

func buildInbound(nc *core.NodeSpec, users []core.UserSpec, tc core.TLSCert) M {
	listenAddr := "::"
	if nc.ListenIP != "" {
		listenAddr = nc.ListenIP
	}
	base := M{
		"tag":      nc.Protocol + "-in",
		"listen":   listenAddr,
		"port":     nc.ServerPort,
		"protocol": nc.Protocol,
		"streamSettings": M{
			"sockopt": M{
				"reusePort": true,
			},
		},
	}

	switch nc.Protocol {
	case "vmess":
		return buildVMess(base, nc, users, tc)
	case "vless":
		return buildVLESS(base, nc, users, tc)
	case "trojan":
		return buildTrojan(base, nc, users, tc)
	case "shadowsocks":
		return buildShadowsocks(base, nc, users)
	case "socks":
		return buildSocks(base, users)
	case "http":
		return buildHTTP(base, nc, users, tc)
	case "hysteria":
		return buildHysteria(base, nc, users, tc)
	default:
		return nil
	}
}

func userEmail(userID int) string {
	return fmt.Sprintf("user@%d", userID)
}

func buildVMess(base M, nc *core.NodeSpec, users []core.UserSpec, tc core.TLSCert) M {
	clients := make([]M, 0, len(users))
	for _, u := range users {
		clients = append(clients, M{
			"id":      u.UUID,
			"alterId": 0,
			"email":   userEmail(u.ID),
		})
	}
	base["settings"] = M{"clients": clients}

	applyStreamSettings(base, nc, tc)
	return base
}

func buildVLESS(base M, nc *core.NodeSpec, users []core.UserSpec, tc core.TLSCert) M {
	clients := make([]M, 0, len(users))
	for _, u := range users {
		client := M{
			"id":    u.UUID,
			"email": userEmail(u.ID),
		}
		if nc.Flow != "" {
			client["flow"] = nc.Flow
		}
		clients = append(clients, client)
	}
	decryption := "none"
	if nc.Decryption != "" {
		decryption = nc.Decryption
	}
	base["settings"] = M{
		"clients":    clients,
		"decryption": decryption,
	}

	applyStreamSettings(base, nc, tc)
	return base
}

func buildTrojan(base M, nc *core.NodeSpec, users []core.UserSpec, tc core.TLSCert) M {
	clients := make([]M, len(users))
	for i := range users {
		u := &users[i]
		clients[i] = M{
			"password": u.UUID,
			"email":    userEmail(u.ID),
		}
	}
	base["settings"] = M{"clients": clients}

	applyStreamSettings(base, nc, tc)

	ss, _ := base["streamSettings"].(M)
	if security, ok := ss["security"].(string); !ok || (security != "tls" && security != "reality") {
		nc.TLS = 1
		applyStreamSettings(base, nc, tc)
	}

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

func ss2022UserKey(size int, uuid string) []byte {
	key := make([]byte, size)
	copy(key, uuid)
	return key
}

func buildShadowsocks(base M, nc *core.NodeSpec, users []core.UserSpec) M {
	ss2022, isSS2022 := ss2022Methods[nc.Cipher]

	clients := make([]M, 0, len(users))

	if isSS2022 {
		for i := range users {
			u := &users[i]
			clients = append(clients, M{
				"password": base64.StdEncoding.EncodeToString(ss2022UserKey(ss2022.size, u.UUID)),
				"email":    userEmail(u.ID),
			})
		}
		base["settings"] = M{
			"method":   nc.Cipher,
			"password": nc.ServerKey,
			"clients":  clients,
			"network":  "tcp,udp",
		}
	} else {
		for i := range users {
			u := &users[i]
			clients = append(clients, M{
				"method":   nc.Cipher,
				"password": u.UUID,
				"email":    userEmail(u.ID),
			})
		}
		base["settings"] = M{
			"method":  nc.Cipher,
			"clients": clients,
			"network": "tcp,udp",
		}
	}
	if nc.Plugin != "" {
		nlog.Core().Warn("xray: shadowsocks plugin is not supported, ignoring", "plugin", nc.Plugin)
	}
	return base
}

func buildSocks(base M, users []core.UserSpec) M {
	base["protocol"] = "socks"
	accounts := make([]M, 0, len(users))
	for _, u := range users {
		accounts = append(accounts, M{
			"user":  u.UUID,
			"pass":  u.UUID,
			"email": userEmail(u.ID),
		})
	}
	base["settings"] = M{
		"auth":     "password",
		"accounts": accounts,
		"udp":      true,
	}
	return base
}

func buildHTTP(base M, nc *core.NodeSpec, users []core.UserSpec, tc core.TLSCert) M {
	base["protocol"] = "http"
	accounts := make([]M, 0, len(users))
	for _, u := range users {
		accounts = append(accounts, M{
			"user":  u.UUID,
			"pass":  u.UUID,
			"email": userEmail(u.ID),
		})
	}
	base["settings"] = M{
		"accounts": accounts,
	}

	if nc.TLS == 1 {
		applyStreamSettings(base, nc, tc)
	}
	return base
}

func buildHysteria(base M, nc *core.NodeSpec, users []core.UserSpec, tc core.TLSCert) M {
	if nc.Version != 2 {
		nlog.Core().Warn("xray: only supports hysteria v2, skipping v1 inbound")
		return nil
	}

	clients := make([]M, 0, len(users))
	for _, u := range users {
		clients = append(clients, M{
			"auth":  u.UUID,
			"email": userEmail(u.ID),
		})
	}
	base["settings"] = M{"version": nc.Version, "clients": clients}

	ss := M{
		"network": "hysteria",
		"hysteriaSettings": M{
			"version":        nc.Version,
			"udpIdleTimeout": 60,
		},
	}

	finalMask := M{}
	if !nc.IgnoreClientBandwidth && (nc.UpMbps > 0 || nc.DownMbps > 0) {
		quicParams := M{}
		if nc.UpMbps > 0 {
			quicParams["brutalUp"] = fmt.Sprintf("%d mbps", nc.UpMbps)
		}
		if nc.DownMbps > 0 {
			quicParams["brutalDown"] = fmt.Sprintf("%d mbps", nc.DownMbps)
		}
		finalMask["quicParams"] = quicParams
	}
	if obfs := strings.ToLower(strings.TrimSpace(nc.Obfs)); obfs != "" {
		if obfs == "salamander" && nc.ObfsPassword != "" {
			finalMask["udp"] = []M{{
				"type":     "salamander",
				"settings": M{"password": nc.ObfsPassword},
			}}
		} else {
			nlog.Core().Warn("xray: hysteria2 obfs ignored; only salamander with a password is supported", "obfs", nc.Obfs)
		}
	}
	if len(finalMask) > 0 {
		ss["finalMask"] = finalMask
	}

	if tc.HasCert() {
		ss["security"] = "tls"
		tlsCert := M{
			"certificate": []string{string(tc.CertPEM)},
			"key":         []string{string(tc.KeyPEM)},
		}
		ss["tlsSettings"] = M{
			"certificates": []M{tlsCert},
			"alpn":         []string{"h3"},
		}
		if core.SettingBool(nc.TLSSettings, "reject_unknown_sni") {
			ss["tlsSettings"].(M)["rejectUnknownSni"] = true
		}
	} else {
		nlog.Core().Warn("hysteria requires TLS certificate files; configure cert_mode (self, file, http, dns, or content)")
	}

	if nc.GetProxyProtocol() {
		ss["sockopt"] = M{"acceptProxyProtocol": true}
	}

	base["streamSettings"] = ss
	return base
}

func applyStreamSettings(base M, nc *core.NodeSpec, tc core.TLSCert) {
	ss := M{}

	network := nc.Network
	if network == "" {
		network = "tcp"
	}
	ss["network"] = network

	switch network {
	case "ws":
		wsSettings := M{}
		if nc.NetworkSettings != nil {
			if v, ok := nc.NetworkSettings["path"]; ok {
				wsSettings["path"] = v
			}
			headers := M{}
			if v, ok := nc.NetworkSettings["headers"]; ok {
				if headersMap, ok := v.(map[string]interface{}); ok {
					for k, val := range headersMap {
						headers[k] = val
					}
				}
			}
			if v, ok := nc.NetworkSettings["host"]; ok {
				headers["Host"] = v
			}
			if len(headers) > 0 {
				wsSettings["headers"] = headers
			}
		}
		ss["wsSettings"] = wsSettings

	case "grpc":
		grpcSettings := M{}
		if nc.NetworkSettings != nil {
			if v, ok := nc.NetworkSettings["serviceName"]; ok {
				grpcSettings["serviceName"] = v
			} else if v, ok := nc.NetworkSettings["service_name"]; ok {
				grpcSettings["serviceName"] = v
			}
		}
		ss["grpcSettings"] = grpcSettings

	case "httpupgrade":
		huSettings := M{}
		if nc.NetworkSettings != nil {
			if v, ok := nc.NetworkSettings["path"]; ok {
				huSettings["path"] = v
			}
			if v, ok := nc.NetworkSettings["host"]; ok {
				huSettings["host"] = v
			}
		}
		ss["httpupgradeSettings"] = huSettings

	case "h2", "http":
		ss["network"] = "h2"
		h2Settings := M{}
		if nc.NetworkSettings != nil {
			if v, ok := nc.NetworkSettings["path"]; ok {
				h2Settings["path"] = v
			}
			if v, ok := nc.NetworkSettings["host"]; ok {
				h2Settings["host"] = []interface{}{v}
			}
		}
		ss["httpSettings"] = h2Settings

	case "xhttp", "splithttp":
		ss["network"] = "xhttp"
		xhttpSettings := M{}
		if nc.NetworkSettings != nil {
			if v, ok := nc.NetworkSettings["path"]; ok {
				xhttpSettings["path"] = v
			}
			if v, ok := nc.NetworkSettings["host"]; ok {
				xhttpSettings["host"] = v
			}
			if v, ok := nc.NetworkSettings["mode"]; ok {
				xhttpSettings["mode"] = v
			}
			if v, ok := nc.NetworkSettings["extra"]; ok {
				if m, ok := v.(map[string]interface{}); ok && len(m) > 0 {
					sanitizeEmptyArrays(m)
					xhttpSettings["extra"] = m
				}
			}
		}
		ss["xhttpSettings"] = xhttpSettings

	case "tcp":
	}

	if nc.TLS == 1 {
		tlsSettings := M{}
		serverName := nc.ServerName
		if serverName == "" && nc.Host != "" {
			serverName = nc.Host
		}
		if serverName != "" {
			tlsSettings["serverName"] = serverName
		}
		if nc.TLSSettings != nil {
			if sn := core.SettingString(nc.TLSSettings, "server_name"); sn != "" {
				tlsSettings["serverName"] = sn
			}
			if echKeys := extractECHServerKeys(nc.TLSSettings); echKeys != "" {
				tlsSettings["echServerKeys"] = echKeys
			}
			if core.SettingBool(nc.TLSSettings, "reject_unknown_sni") {
				tlsSettings["rejectUnknownSni"] = true
			}
		}
		if tc.HasCert() {
			tlsCert := M{
				"certificate": []string{string(tc.CertPEM)},
				"key":         []string{string(tc.KeyPEM)},
			}
			tlsSettings["certificates"] = []M{tlsCert}
		} else {
		}
		ss["security"] = "tls"
		ss["tlsSettings"] = tlsSettings
	} else if nc.TLS == 2 {
		ss["security"] = "reality"
		ss["realitySettings"] = buildRealitySettings(nc)
	}

	sockopt, _ := ss["sockopt"].(M)
	if sockopt == nil {
		sockopt = M{}
	}
	if nc.GetProxyProtocol() {
		sockopt["acceptProxyProtocol"] = true
	}
	if len(nc.TrustedXForwardedFor) > 0 {
		sockopt["trustedXForwardedFor"] = nc.TrustedXForwardedFor
	}
	if len(sockopt) > 0 {
		ss["sockopt"] = sockopt
	}

	base["streamSettings"] = ss
}

func buildRealitySettings(nc *core.NodeSpec) M {
	reality := M{"show": false}

	if nc.TLSSettings == nil {
		return reality
	}

	if pk := core.SettingString(nc.TLSSettings, "private_key"); pk != "" {
		reality["privateKey"] = pk
	}
	reality["shortIds"] = core.RealityShortIDList(nc.TLSSettings)
	if xver := core.SettingPort(nc.TLSSettings, "xver"); xver == 1 || xver == 2 {
		reality["xver"] = xver
	}
	if seed := core.SettingString(nc.TLSSettings, "mldsa65Seed"); seed != "" {
		reality["mldsa65Seed"] = seed
	}

	port := core.SettingPort(nc.TLSSettings, "server_port")
	if port == 0 {
		port = 443
	}
	serverNames := core.RealityServerNames(nc.TLSSettings)
	sn := ""
	if len(serverNames) > 0 {
		sn = serverNames[0]
	}
	dest := core.SettingString(nc.TLSSettings, "dest")
	if sn == "" && dest != "" {
		host := dest
		if h, _, err := net.SplitHostPort(dest); err == nil {
			host = h
		}
		if net.ParseIP(host) == nil {
			if _, err := strconv.Atoi(host); err != nil {
				sn = host
			}
		}
	}
	if len(serverNames) > 0 {
		reality["serverNames"] = serverNames
	} else if sn != "" {
		reality["serverNames"] = []string{sn}
	}
	if dest == "" {
		dest = sn
	}
	if dest != "" {
		if _, _, err := net.SplitHostPort(dest); err != nil {
			if _, err := strconv.Atoi(dest); err != nil {
				dest = net.JoinHostPort(dest, strconv.Itoa(port))
			}
		}
		reality["dest"] = dest
	}

	return reality
}

func buildRouting(rules []core.RouteRule, customRouteRules []core.CustomRouteRule, customRules []map[string]any) M {
	var xrayRules []M

	for _, rule := range customRouteRules {
		if rule.Disabled {
			continue
		}
		xrayRules = append(xrayRules, compileCustomRouteRule(rule)...)
	}

	for _, cr := range customRules {
		xrayRules = append(xrayRules, M(cr))
	}

	xrayRules = append(xrayRules, M{
		"type": "field",
		"ip": []string{
			"10.0.0.0/8",
			"100.64.0.0/10",
			"127.0.0.0/8",
			"169.254.0.0/16",
			"172.16.0.0/12",
			"192.0.0.0/24",
			"192.168.0.0/16",
			"198.18.0.0/15",
			"fc00::/7",
			"fe80::/10",
			"::1/128",
		},
		"outboundTag": "block",
	})

	for _, rule := range rules {
		xrayRules = append(xrayRules, compilePanelRouteRule(rule)...)
	}
	if tag := panelDefaultOutbound(rules); tag != "" {
		xrayRules = append(xrayRules, M{
			"type":        "field",
			"network":     "tcp,udp",
			"outboundTag": tag,
		})
	}

	return M{
		"domainStrategy": "AsIs",
		"rules":          xrayRules,
	}
}

func compilePanelRouteRule(rule core.RouteRule) []M {
	if len(rule.Match) == 0 {
		return nil
	}
	var outbound string
	switch core.PanelRouteKind(rule.Action) {
	case core.PanelRouteDNS:
		return nil
	case core.PanelRouteBlock:
		outbound = "block"
	case core.PanelRouteDirect:
		outbound = "direct"
	case core.PanelRouteProxy:
		outbound = strings.TrimSpace(rule.ActionValue)
		if outbound == "" {
			nlog.Core().Warn("xray: panel proxy route has no outbound tag, rule skipped", "id", rule.ID)
			return nil
		}
	case core.PanelRouteOutbound:
		tag, _, err := xrayPanelOutbound(rule.ActionValue)
		if err != nil {
			nlog.Core().Warn("xray: invalid panel route outbound, rule skipped", "id", rule.ID, "action", rule.Action, "error", err)
			return nil
		}
		outbound = tag
	case core.PanelRouteDefaultOut:
		// Emitted after all panel rules by buildRouting.
		return nil
	default:
		nlog.Core().Warn("xray: unsupported panel route action, rule skipped", "id", rule.ID, "action", rule.Action)
		return nil
	}

	match := core.ParsePanelRouteMatch(rule.Action, rule.Match)
	if len(match.Invalid) > 0 {
		nlog.Core().Warn("xray: invalid panel route match items ignored", "id", rule.ID, "items", match.Invalid)
	}

	var compiled []M
	if domains := xrayDomainList(match); len(domains) > 0 {
		compiled = append(compiled, M{
			"type":        "field",
			"domain":      domains,
			"outboundTag": outbound,
		})
	}
	ips := copyStrings(match.IPCIDRs)
	for _, name := range match.GeoIPs {
		ips = append(ips, "geoip:"+name)
	}
	if len(ips) > 0 {
		compiled = append(compiled, M{
			"type":        "field",
			"ip":          ips,
			"outboundTag": outbound,
		})
	}
	if len(match.Protocols) > 0 {
		compiled = append(compiled, M{
			"type":        "field",
			"protocol":    copyStrings(match.Protocols),
			"outboundTag": outbound,
		})
	}
	if len(match.Ports) > 0 {
		compiled = append(compiled, M{
			"type":        "field",
			"port":        strings.Join(match.Ports, ","),
			"outboundTag": outbound,
		})
	}
	return compiled
}

func xrayDomainList(match core.PanelRouteMatch) []string {
	var domains []string
	for _, v := range match.Domains {
		domains = append(domains, "full:"+v)
	}
	for _, v := range match.DomainSuffixes {
		domains = append(domains, "domain:"+v)
	}
	for _, v := range match.DomainKeywords {
		domains = append(domains, "keyword:"+v)
	}
	for _, v := range match.DomainRegexps {
		domains = append(domains, "regexp:"+v)
	}
	for _, v := range match.GeoSites {
		domains = append(domains, "geosite:"+v)
	}
	return domains
}

// buildDNS turns panel "dns" routes into xray DNS servers bound to the matched
// domains. Unmatched domains keep using the system resolver ("localhost").
func buildDNS(rules []core.RouteRule) M {
	var servers []any
	index := map[string]M{}
	for _, rule := range rules {
		if core.PanelRouteKind(rule.Action) != core.PanelRouteDNS {
			continue
		}
		value := strings.TrimSpace(rule.ActionValue)
		if value == "" {
			nlog.Core().Warn("xray: panel dns route has no server, rule skipped", "id", rule.ID)
			continue
		}
		match := core.ParsePanelRouteMatch(rule.Action, rule.Match)
		domains := xrayDomainList(match)
		if len(domains) == 0 {
			nlog.Core().Warn("xray: panel dns route needs domain matches, rule skipped", "id", rule.ID)
			continue
		}
		if server, ok := index[value]; ok {
			server["domains"] = append(server["domains"].([]string), domains...)
			continue
		}
		server := M{"domains": domains, "skipFallback": true}
		address, port := splitDNSAddress(value)
		server["address"] = address
		if port > 0 {
			server["port"] = port
		}
		index[value] = server
		servers = append(servers, server)
	}
	if len(servers) == 0 {
		return nil
	}
	return M{"servers": append([]any{"localhost"}, servers...)}
}

// splitDNSAddress splits a plain "host:port" DNS address. URL forms such as
// "tcp://1.1.1.1:53" or "https://dns.google/dns-query" are returned unchanged.
func splitDNSAddress(value string) (string, int) {
	if strings.Contains(value, "://") {
		return value, 0
	}
	host, portStr, err := net.SplitHostPort(value)
	if err != nil {
		return value, 0
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port <= 0 || port > 65535 {
		return value, 0
	}
	return host, port
}

func compileCustomRouteRule(rule core.CustomRouteRule) []M {
	outbound := xrayOutboundForAction(rule.Action)
	var compiled []M

	if len(rule.Match.Domains) > 0 || len(rule.Match.DomainSuffixes) > 0 {
		domains := make([]string, 0, len(rule.Match.Domains)+len(rule.Match.DomainSuffixes))
		for _, value := range rule.Match.Domains {
			value = strings.TrimSpace(value)
			if value == "" {
				continue
			}
			domains = append(domains, value)
		}
		for _, value := range rule.Match.DomainSuffixes {
			value = strings.TrimSpace(value)
			if value == "" {
				continue
			}
			domains = append(domains, "domain:"+value)
		}
		if len(domains) > 0 {
			compiled = append(compiled, M{
				"type":        "field",
				"domain":      domains,
				"outboundTag": outbound,
			})
		}
	}
	if len(rule.Match.IPCIDRs) > 0 {
		compiled = append(compiled, M{
			"type":        "field",
			"ip":          copyStrings(rule.Match.IPCIDRs),
			"outboundTag": outbound,
		})
	}
	if len(rule.Match.Ports) > 0 {
		compiled = append(compiled, M{
			"type":        "field",
			"port":        strings.Join(rule.Match.Ports, ","),
			"outboundTag": outbound,
		})
	}
	if len(rule.Match.Networks) > 0 {
		compiled = append(compiled, M{
			"type":        "field",
			"network":     strings.Join(rule.Match.Networks, ","),
			"outboundTag": outbound,
		})
	}
	if len(rule.Match.SourceCIDRs) > 0 {
		compiled = append(compiled, M{
			"type":        "field",
			"source":      copyStrings(rule.Match.SourceCIDRs),
			"outboundTag": outbound,
		})
	}
	if len(rule.Match.SourcePorts) > 0 {
		compiled = append(compiled, M{
			"type":        "field",
			"sourcePort":  strings.Join(rule.Match.SourcePorts, ","),
			"outboundTag": outbound,
		})
	}
	return compiled
}

func xrayOutboundForAction(action core.RouteAction) string {
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

func copyStrings(src []string) []string {
	if len(src) == 0 {
		return nil
	}
	out := make([]string, len(src))
	copy(out, src)
	return out
}

func sanitizeEmptyArrays(m map[string]interface{}) {
	for k, v := range m {
		switch val := v.(type) {
		case []interface{}:
			if len(val) == 0 {
				delete(m, k)
			}
		case map[string]interface{}:
			sanitizeEmptyArrays(val)
		}
	}
}

func extractECHServerKeys(tlsSettings map[string]interface{}) string {
	echRaw, ok := tlsSettings["ech"]
	if !ok {
		return ""
	}
	echMap, ok := echRaw.(map[string]interface{})
	if !ok {
		return ""
	}
	enabled, _ := echMap["enabled"].(bool)
	if !enabled {
		return ""
	}

	var pemData []byte
	if key, _ := echMap["key"].(string); key != "" {
		pemData = []byte(key)
	} else if keyPath, _ := echMap["key_path"].(string); keyPath != "" {
		data, err := os.ReadFile(keyPath)
		if err != nil {
			nlog.Core().Warn("ECH enabled but key_path read failed", "error", err)
			return ""
		}
		pemData = data
	} else {
		nlog.Core().Warn("ECH enabled but no key or key_path provided")
		return ""
	}

	return echPEMToBase64(pemData)
}

func echPEMToBase64(data []byte) string {
	trimmed := strings.TrimSpace(string(data))
	if !strings.Contains(trimmed, "-----") {
		return trimmed
	}
	block, _ := pem.Decode(data)
	if block == nil {
		nlog.Core().Warn("ECH key: invalid PEM data")
		return ""
	}
	if block.Type != "ECH KEYS" {
		nlog.Core().Warn("ECH key: unexpected PEM type", "expected", "ECH KEYS", "got", block.Type)
		return ""
	}
	return base64.StdEncoding.EncodeToString(block.Bytes)
}
