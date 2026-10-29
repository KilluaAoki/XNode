//go:build with_quic

package sing

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/protocol/socks"

	"github.com/KilluaAoki/XNode/api/panel"
	"github.com/KilluaAoki/XNode/conf"
	"github.com/KilluaAoki/XNode/core"
)

func testCert(t *testing.T) core.TLSCert {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "localhost"},
		DNSNames:     []string{"localhost"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return core.TLSCert{
		CertPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		KeyPEM:  pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}),
	}
}

func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

func reloadUsers(ids ...int) []core.UserSpec {
	all := []panel.User{
		{ID: 1, UUID: "aaaaaaaa-1111-2222-3333-444444444444"},
		{ID: 2, UUID: "bbbbbbbb-5555-6666-7777-888888888888"},
		{ID: 3, UUID: "cccccccc-9999-aaaa-bbbb-cccccccccccc"},
	}
	var picked []panel.User
	for _, id := range ids {
		picked = append(picked, all[id-1])
	}
	return core.UserSpecsFromPanel(picked)
}

func TestSingBoxUserUpdatesStayInPlace(t *testing.T) {
	cert := testCert(t)
	cases := []struct {
		name string
		nc   panel.NodeConfig
	}{
		{"vmess", panel.NodeConfig{Protocol: "vmess"}},
		{"vless", panel.NodeConfig{Protocol: "vless"}},
		{"trojan", panel.NodeConfig{Protocol: "trojan"}},
		{"shadowsocks", panel.NodeConfig{Protocol: "shadowsocks", Cipher: "aes-128-gcm"}},
		{"shadowsocks2022", panel.NodeConfig{Protocol: "shadowsocks", Cipher: "2022-blake3-aes-128-gcm", ServerKey: "AAAAAAAAAAAAAAAAAAAAAA=="}},
		{"hysteria", panel.NodeConfig{Protocol: "hysteria", Version: 1, UpMbps: 100, DownMbps: 100}},
		{"hysteria2", panel.NodeConfig{Protocol: "hysteria", Version: 2}},
		{"tuic", panel.NodeConfig{Protocol: "tuic"}},
		{"anytls", panel.NodeConfig{Protocol: "anytls"}},
		{"naive", panel.NodeConfig{Protocol: "naive", TLS: 1}},
		{"naive_plain", panel.NodeConfig{Protocol: "naive"}},
		{"socks", panel.NodeConfig{Protocol: "socks"}},
		{"http", panel.NodeConfig{Protocol: "http"}},
		{"mieru", panel.NodeConfig{Protocol: "mieru", Transport: "TCP"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			nc := tc.nc
			nc.ServerPort = freePort(t)
			spec := core.NodeSpecFromPanel(&nc)
			s := New(conf.KernelConfig{LogLevel: "error"})
			if err := s.Start(spec, reloadUsers(1), cert); err != nil {
				t.Fatalf("start: %v", err)
			}
			defer s.Stop()
			first := s.box

			if _, _, err := s.UpdateUsers(reloadUsers(1, 2, 3)); err != nil {
				t.Fatalf("update users: %v", err)
			}
			if s.box != first {
				t.Fatal("adding users restarted the box")
			}
			if _, err := s.RemoveUsers(reloadUsers(2)); err != nil {
				t.Fatalf("remove users: %v", err)
			}
			if s.box != first {
				t.Fatal("removing users restarted the box")
			}
			if len(s.users) != 2 {
				t.Fatalf("users: got %d, want 2", len(s.users))
			}

			if err := s.Reload(spec, reloadUsers(3), cert); err != nil {
				t.Fatalf("reload same structure: %v", err)
			}
			if s.box != first {
				t.Fatal("reload with only user changes restarted the box")
			}

			newCert := testCert(t)
			_, usesTLS := buildInbound(spec, nil, newCert)["tls"]
			if err := s.Reload(spec, reloadUsers(3), newCert); err != nil {
				t.Fatalf("reload new cert: %v", err)
			}
			if restarted := s.box != first; restarted != usesTLS {
				t.Fatalf("certificate change: restarted=%v, inbound uses tls=%v", restarted, usesTLS)
			}
		})
	}
}

func TestSingBoxSocksAuthFollowsUpdates(t *testing.T) {
	echo, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echo.Close()
	go func() {
		for {
			c, err := echo.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				io.Copy(c, c)
			}()
		}
	}()

	nc := panel.NodeConfig{Protocol: "socks", ServerPort: freePort(t)}
	s := New(conf.KernelConfig{LogLevel: "error", CustomRoute: []map[string]any{{"ip_cidr": []string{"127.0.0.1/32"}, "outbound": "direct"}}})
	if err := s.Start(core.NodeSpecFromPanel(&nc), reloadUsers(1), core.TLSCert{}); err != nil {
		t.Fatalf("start: %v", err)
	}
	defer s.Stop()

	server := metadata.ParseSocksaddrHostPort("127.0.0.1", uint16(nc.ServerPort))
	target := metadata.SocksaddrFromNet(echo.Addr())
	try := func(u core.UserSpec) error {
		client := socks.NewClient(N.SystemDialer, server, socks.Version5, u.UUID, u.UUID)
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		conn, err := client.DialContext(ctx, N.NetworkTCP, target)
		if err != nil {
			return err
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(3 * time.Second))
		if _, err := conn.Write([]byte("ping")); err != nil {
			return err
		}
		buf := make([]byte, 4)
		_, err = io.ReadFull(conn, buf)
		return err
	}

	a, b := reloadUsers(1)[0], reloadUsers(2)[0]
	if err := try(a); err != nil {
		t.Fatalf("user 1 before update: %v", err)
	}
	if err := try(b); err == nil {
		t.Fatal("user 2 accepted before being added")
	}
	if _, _, err := s.UpdateUsers(reloadUsers(2)); err != nil {
		t.Fatal(err)
	}
	if err := try(b); err != nil {
		t.Fatalf("user 2 after update: %v", err)
	}
	if err := try(a); err == nil {
		t.Fatal("user 1 still accepted after removal")
	}
}
