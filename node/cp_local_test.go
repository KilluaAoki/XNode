package node

import (
	"context"
	"testing"

	"github.com/KilluaAoki/XNode/conf"
)

func TestLocalControlPlaneInitial(t *testing.T) {
	cp := NewLocalControlPlane(&conf.Config{
		Kernel: conf.KernelConfig{Type: "singbox", LogLevel: "warn"},
		Standalone: &conf.StandaloneConfig{
			Enabled: true,
			Node:    conf.StandaloneNodeConfig{Protocol: "shadowsocks", ServerPort: 8388, Cipher: "aes-128-gcm"},
			Users:   []conf.StandaloneUser{{ID: 1, UUID: "secret"}},
		},
	})
	bootstrap, err := cp.Initial(context.Background(), nil, nil, nil)
	if err != nil {
		t.Fatalf("Initial: %v", err)
	}
	if bootstrap.Push != nil {
		t.Fatal("local control plane should not create push client")
	}
	if bootstrap.Config == nil || bootstrap.Config.Protocol != "shadowsocks" {
		t.Fatalf("config: %#v", bootstrap.Config)
	}
	if len(bootstrap.Users) != 1 || bootstrap.Users[0].UUID != "secret" {
		t.Fatalf("users: %#v", bootstrap.Users)
	}
}
