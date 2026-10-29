package dnsproviders

import (
	"strings"
	"testing"
)

func TestRegistryHasMainstreamProviders(t *testing.T) {
	cases := map[string][]string{
		"cloudflare":     {"cf"},
		"alidns":         {"aliyun"},
		"tencentcloud":   {"tencent"},
		"route53":        {"aws"},
		"godaddy":        nil,
		"namecheap":      nil,
		"namesilo":       nil,
		"digitalocean":   {"do"},
		"linode":         nil,
		"hetzner":        nil,
		"gandi":          nil,
		"porkbun":        nil,
		"netlify":        nil,
		"azure":          nil,
		"googleclouddns": {"gcp", "gcloud"},
		"huaweicloud":    {"huawei"},
		"bunny":          nil,
		"duckdns":        nil,
		"ovh":            nil,
		"vultr":          nil,
		"desec":          nil,
	}
	for canonical, aliases := range cases {
		if _, ok := Get(canonical); !ok {
			t.Errorf("provider %q not registered", canonical)
		}
		if _, ok := Get(strings.ToUpper(canonical)); !ok {
			t.Errorf("provider %q not found case-insensitively", canonical)
		}
		for _, a := range aliases {
			if _, ok := Get(a); !ok {
				t.Errorf("alias %q for %q not registered", a, canonical)
			}
		}
	}
}

func TestRegistryRejectsUnknown(t *testing.T) {
	if _, ok := Get("definitely-not-a-real-provider"); ok {
		t.Fatal("Get returned ok for unknown provider")
	}
}

func TestProvidersValidateMissingEnv(t *testing.T) {
	excluded := map[string]bool{
		"route53":        true,
		"azure":          true,
		"googleclouddns": true,
	}
	for _, p := range List() {
		canonical := p.Names[0]
		if excluded[canonical] {
			continue
		}
		t.Run(canonical, func(t *testing.T) {
			_, err := p.Build(map[string]string{})
			if err == nil {
				t.Errorf("provider %q built successfully with empty env; expected missing-credential error", canonical)
			}
		})
	}
}

func TestCanonicalNamesSorted(t *testing.T) {
	names := CanonicalNames()
	for i := 1; i < len(names); i++ {
		if names[i-1] > names[i] {
			t.Fatalf("CanonicalNames not sorted: %v", names)
		}
	}
}
