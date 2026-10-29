package xray

import (
	"errors"
	"strings"

	"github.com/KilluaAoki/XNode/common/nlog"
	"github.com/KilluaAoki/XNode/core"
)

// xrayPanelOutbound parses a route/route_ip/default_out action_value. A JSON
// value must be an xray outbound object with "protocol" and "tag".
func xrayPanelOutbound(value string) (string, M, error) {
	tag, ob, err := core.ParsePanelRouteOutbound(value)
	if err != nil || ob == nil {
		return tag, nil, err
	}
	if p, _ := ob["protocol"].(string); strings.TrimSpace(p) == "" {
		return "", nil, errors.New("xray outbound has no protocol")
	}
	return tag, M(ob), nil
}

// appendPanelOutbounds adds the JSON outbounds declared by panel routes.
// Tags that already exist keep their current definition.
func appendPanelOutbounds(outbounds []M, tags map[string]bool, routes []core.RouteRule) []M {
	used := map[string]bool{"direct": true, "block": true}
	for tag := range tags {
		used[tag] = true
	}
	for _, rule := range routes {
		switch core.PanelRouteKind(rule.Action) {
		case core.PanelRouteOutbound, core.PanelRouteDefaultOut:
		default:
			continue
		}
		tag, ob, err := xrayPanelOutbound(rule.ActionValue)
		if err != nil || ob == nil || used[strings.ToLower(tag)] {
			continue
		}
		used[strings.ToLower(tag)] = true
		outbounds = append(outbounds, ob)
	}
	return outbounds
}

// panelDefaultOutbound returns the outbound tag of the first valid
// default_out rule.
func panelDefaultOutbound(routes []core.RouteRule) string {
	var chosen string
	for _, rule := range routes {
		if core.PanelRouteKind(rule.Action) != core.PanelRouteDefaultOut {
			continue
		}
		tag, _, err := xrayPanelOutbound(rule.ActionValue)
		switch {
		case err != nil:
			nlog.Core().Warn("xray: invalid panel default_out outbound, rule skipped", "id", rule.ID, "error", err)
		case chosen != "":
			nlog.Core().Warn("xray: multiple panel default_out rules, extra rule ignored", "id", rule.ID)
		default:
			chosen = tag
		}
	}
	return chosen
}
