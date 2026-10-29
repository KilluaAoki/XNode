package core

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/KilluaAoki/XNode/common/nlog"
	"gopkg.in/yaml.v3"
)

func LoadCustomConfig(path string) (map[string]any, error) {
	if path == "" {
		return nil, nil
	}

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			nlog.Core().Warn("custom config file not found, skipping", "path", path)
			return nil, nil
		}
		return nil, fmt.Errorf("read custom config %s: %w", path, err)
	}

	result, err := parseCustomConfig(data)
	if err != nil || result == nil {
		return nil, err
	}
	nlog.Core().Info("loaded custom config", "path", path, "keys", mapKeys(result))
	return result, nil
}

func parseCustomConfig(data []byte) (map[string]any, error) {
	trimmed := strings.TrimSpace(string(data))
	if trimmed == "" {
		return nil, nil
	}
	result := make(map[string]any)
	if strings.HasPrefix(trimmed, "{") {
		if err := json.Unmarshal(data, &result); err != nil {
			return nil, fmt.Errorf("parse custom config as JSON: %w", err)
		}
	} else {
		if err := yaml.Unmarshal(data, &result); err != nil {
			return nil, fmt.Errorf("parse custom config as YAML: %w", err)
		}
	}
	return result, nil
}

func MergeAppendList(dst []map[string]any, srcRaw any) []map[string]any {
	srcList, ok := toSliceOfMaps(srcRaw)
	if !ok {
		return dst
	}
	return append(dst, srcList...)
}

// MergeOutbounds appends custom outbounds, except that one sharing a tag with
// an existing outbound replaces it in place. This lets custom_config redefine
// the built-in direct and block outbounds while keeping direct the default.
func MergeOutbounds(dst []map[string]any, srcRaw any) []map[string]any {
	srcList, ok := toSliceOfMaps(srcRaw)
	if !ok {
		return dst
	}
	index := make(map[string]int, len(dst))
	for i, ob := range dst {
		if tag, _ := ob["tag"].(string); tag != "" {
			index[strings.ToLower(tag)] = i
		}
	}
	for _, ob := range srcList {
		tag, _ := ob["tag"].(string)
		if i, ok := index[strings.ToLower(tag)]; ok && tag != "" {
			dst[i] = ob
			continue
		}
		dst = append(dst, ob)
	}
	return dst
}

func MergePrependList(dst []map[string]any, srcRaw any) []map[string]any {
	srcList, ok := toSliceOfMaps(srcRaw)
	if !ok {
		return dst
	}
	return append(srcList, dst...)
}

func toSliceOfMaps(v any) ([]map[string]any, bool) {
	if v == nil {
		return nil, false
	}
	switch items := v.(type) {
	case []any:
		result := make([]map[string]any, 0, len(items))
		for _, item := range items {
			if m, ok := toMap(item); ok {
				result = append(result, m)
			}
		}
		return result, len(result) > 0
	case []map[string]any:
		return items, len(items) > 0
	default:
		return nil, false
	}
}

func toMap(v any) (map[string]any, bool) {
	switch m := v.(type) {
	case map[string]any:
		return m, true
	case map[any]any:
		result := make(map[string]any, len(m))
		for k, val := range m {
			result[fmt.Sprint(k)] = val
		}
		return result, true
	default:
		return nil, false
	}
}

func mapKeys(m map[string]any) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}

type outboundTagSource struct {
	Tag    string
	Source string
}

func collectCustomConfigOutboundTagSources(path string) ([]outboundTagSource, error) {
	if strings.TrimSpace(path) == "" {
		return nil, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("read custom config %q: %w", path, err)
	}
	decoded, err := parseCustomConfig(data)
	if err != nil {
		return nil, err
	}
	items, ok := toSliceOfMaps(decoded["outbounds"])
	if !ok {
		return nil, nil
	}
	sources := make([]outboundTagSource, 0, len(items))
	for i, item := range items {
		tag, _ := item["tag"].(string)
		tag = strings.TrimSpace(tag)
		if tag == "" {
			continue
		}
		sources = append(sources, outboundTagSource{Tag: tag, Source: fmt.Sprintf("kernel.custom_config.outbounds[%d]", i)})
	}
	return sources, nil
}

func validateOutboundTagCollisions(structured []OutboundConfig, additional []outboundTagSource) error {
	seen := make(map[string]string, len(additional))
	for _, source := range additional {
		key := strings.ToLower(strings.TrimSpace(source.Tag))
		if key == "" {
			continue
		}
		if prev, exists := seen[key]; exists {
			return fmt.Errorf("%s.tag duplicates %q from %s", source.Source, source.Tag, prev)
		}
		seen[key] = source.Source
	}
	for i, outbound := range structured {
		key := strings.ToLower(strings.TrimSpace(outbound.Tag))
		if key == "" {
			continue
		}
		if prev, exists := seen[key]; exists {
			return fmt.Errorf("custom_outbounds[%d].tag duplicates %q from %s", i, outbound.Tag, prev)
		}
	}
	return nil
}

func additionalTagNames(sources []outboundTagSource) []string {
	if len(sources) == 0 {
		return nil
	}
	tags := make([]string, 0, len(sources))
	for _, source := range sources {
		tags = append(tags, source.Tag)
	}
	return tags
}
