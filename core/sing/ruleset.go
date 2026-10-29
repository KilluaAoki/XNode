package sing

import (
	"os"
	"strings"

	"github.com/KilluaAoki/XNode/common/nlog"
	"github.com/KilluaAoki/XNode/core/geodata"
)

// ruleSetIndex resolves geosite/geoip names to local binary rule-sets under
// geo_data_dir and records which ones the generated config references.
type ruleSetIndex struct {
	dir     string
	used    map[string]bool
	order   []string
	skipped map[string]bool
}

func newRuleSetIndex(dir string) *ruleSetIndex {
	return &ruleSetIndex{
		dir:     dir,
		used:    map[string]bool{},
		skipped: map[string]bool{},
	}
}

// refs returns the rule-set tags for names whose files exist locally.
// Missing or invalid names are logged once and left out.
func (r *ruleSetIndex) refs(kind string, names []string) []string {
	var tags []string
	for _, name := range names {
		if tag := r.ref(kind, name); tag != "" {
			tags = append(tags, tag)
		}
	}
	return tags
}

func (r *ruleSetIndex) ref(kind, name string) string {
	label := kind + ":" + name
	if r == nil || r.dir == "" {
		nlog.Core().Warn("sing-box: geo rule-set directory not configured, matcher skipped", "match", label)
		return ""
	}
	tag := geodata.RuleSetTag(kind, name)
	if tag == "" {
		r.skip(label, "sing-box: invalid geo rule-set name, matcher skipped")
		return ""
	}
	if r.used[tag] {
		return tag
	}
	if _, err := os.Stat(geodata.RuleSetPath(r.dir, tag)); err != nil {
		r.skip(label, "sing-box: geo rule-set file missing, matcher skipped")
		return ""
	}
	r.used[tag] = true
	r.order = append(r.order, tag)
	return tag
}

func (r *ruleSetIndex) skip(label, msg string) {
	if r.skipped[label] {
		return
	}
	r.skipped[label] = true
	nlog.Core().Warn(msg, "match", label, "dir", r.dir)
}

func (r *ruleSetIndex) definitions() []M {
	if r == nil || len(r.order) == 0 {
		return nil
	}
	defs := make([]M, 0, len(r.order))
	for _, tag := range r.order {
		defs = append(defs, M{
			"type":   "local",
			"tag":    tag,
			"format": "binary",
			"path":   geodata.RuleSetPath(r.dir, tag),
		})
	}
	return defs
}

func listenAddress(ip string) string {
	if ip = strings.TrimSpace(ip); ip != "" {
		return ip
	}
	return "::"
}
