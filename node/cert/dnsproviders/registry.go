package dnsproviders

import (
	"fmt"
	"sort"
	"strings"
	"sync"

	"github.com/caddyserver/certmagic"
)

type Builder func(env map[string]string) (certmagic.DNSProvider, error)

type Provider struct {
	Names   []string
	EnvVars []string
	Build   Builder
}

var (
	mu       sync.RWMutex
	registry = map[string]*Provider{}
	ordered  []*Provider
)

func Register(p *Provider) {
	if p == nil || len(p.Names) == 0 || p.Build == nil {
		panic("dnsproviders: invalid provider registration")
	}
	mu.Lock()
	defer mu.Unlock()
	for _, n := range p.Names {
		key := strings.ToLower(strings.TrimSpace(n))
		if key == "" {
			panic("dnsproviders: empty provider name")
		}
		if _, exists := registry[key]; exists {
			panic(fmt.Sprintf("dnsproviders: duplicate name %q", key))
		}
		registry[key] = p
	}
	ordered = append(ordered, p)
}

func Get(name string) (*Provider, bool) {
	mu.RLock()
	defer mu.RUnlock()
	p, ok := registry[strings.ToLower(strings.TrimSpace(name))]
	return p, ok
}

func CanonicalNames() []string {
	mu.RLock()
	defer mu.RUnlock()
	names := make([]string, 0, len(ordered))
	for _, p := range ordered {
		names = append(names, p.Names[0])
	}
	sort.Strings(names)
	return names
}

func List() []*Provider {
	mu.RLock()
	defer mu.RUnlock()
	out := make([]*Provider, len(ordered))
	copy(out, ordered)
	sort.Slice(out, func(i, j int) bool { return out[i].Names[0] < out[j].Names[0] })
	return out
}
