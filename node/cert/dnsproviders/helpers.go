package dnsproviders

import (
	"fmt"
	"strings"
)

func firstOf(env map[string]string, keys ...string) string {
	for _, k := range keys {
		if v := strings.TrimSpace(env[k]); v != "" {
			return v
		}
	}
	return ""
}

func missingEnvErr(provider string, keys ...string) error {
	return fmt.Errorf("dns provider %q requires one of %s in dns_env", provider, strings.Join(keys, ", "))
}
