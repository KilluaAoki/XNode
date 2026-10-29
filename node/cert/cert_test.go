package cert

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"path/filepath"
	"testing"
	"time"

	"github.com/caddyserver/certmagic"

	"github.com/KilluaAoki/XNode/conf"
)

func generateSelfSignedPair(t *testing.T, domain string) (certPEM, keyPEM []byte) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: domain},
		DNSNames:     []string{domain},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	return
}

func TestLoadPEMFromStorage_RestartScenario(t *testing.T) {
	dir := t.TempDir()
	storage := &certmagic.FileStorage{Path: dir}
	const domain = "example.test"
	const issuerKey = "test-issuer"

	certPEM, keyPEM := generateSelfSignedPair(t, domain)

	ctx := context.Background()
	if err := storage.Store(ctx, certmagic.StorageKeys.SiteCert(issuerKey, domain), certPEM); err != nil {
		t.Fatalf("seed cert: %v", err)
	}
	if err := storage.Store(ctx, certmagic.StorageKeys.SitePrivateKey(issuerKey, domain), keyPEM); err != nil {
		t.Fatalf("seed key: %v", err)
	}

	m := NewManager(conf.CertConfig{})
	if m.HasCert() {
		t.Fatal("manager should start with no cert in memory")
	}

	if err := m.loadPEMFromStorage(ctx, storage, issuerKey, domain); err != nil {
		t.Fatalf("loadPEMFromStorage: %v", err)
	}
	if !m.HasCert() {
		t.Fatal("expected HasCert() == true after explicit load")
	}
	got := m.TLSCert()
	if string(got.CertPEM) != string(certPEM) {
		t.Errorf("certPEM mismatch")
	}
	if string(got.KeyPEM) != string(keyPEM) {
		t.Errorf("keyPEM mismatch")
	}
}

func TestLoadPEMFromStorage_RenewalRefresh(t *testing.T) {
	dir := t.TempDir()
	storage := &certmagic.FileStorage{Path: dir}
	const domain = "example.test"
	const issuerKey = "test-issuer"
	ctx := context.Background()

	certV1, keyV1 := generateSelfSignedPair(t, domain)
	if err := storage.Store(ctx, certmagic.StorageKeys.SiteCert(issuerKey, domain), certV1); err != nil {
		t.Fatalf("seed v1 cert: %v", err)
	}
	if err := storage.Store(ctx, certmagic.StorageKeys.SitePrivateKey(issuerKey, domain), keyV1); err != nil {
		t.Fatalf("seed v1 key: %v", err)
	}

	m := NewManager(conf.CertConfig{})
	if err := m.loadPEMFromStorage(ctx, storage, issuerKey, domain); err != nil {
		t.Fatalf("initial load: %v", err)
	}

	certV2, keyV2 := generateSelfSignedPair(t, domain)
	if err := storage.Store(ctx, certmagic.StorageKeys.SiteCert(issuerKey, domain), certV2); err != nil {
		t.Fatalf("seed v2 cert: %v", err)
	}
	if err := storage.Store(ctx, certmagic.StorageKeys.SitePrivateKey(issuerKey, domain), keyV2); err != nil {
		t.Fatalf("seed v2 key: %v", err)
	}

	if err := m.loadPEMFromStorage(ctx, storage, issuerKey, domain); err != nil {
		t.Fatalf("refresh load: %v", err)
	}
	got := m.TLSCert()
	if string(got.CertPEM) != string(certV2) {
		t.Error("expected v2 cert after refresh")
	}
	if string(got.KeyPEM) != string(keyV2) {
		t.Error("expected v2 key after refresh")
	}
}

func TestLoadPEMFromStorage_MissingFiles(t *testing.T) {
	dir := t.TempDir()
	storage := &certmagic.FileStorage{Path: dir}
	m := NewManager(conf.CertConfig{})
	err := m.loadPEMFromStorage(context.Background(), storage, "test-issuer", "example.test")
	if err == nil {
		t.Fatal("expected error when storage is empty")
	}
}

func TestLoadPEMFromStorage_RejectsMismatchedPair(t *testing.T) {
	dir := t.TempDir()
	storage := &certmagic.FileStorage{Path: dir}
	const domain = "example.test"
	const issuerKey = "test-issuer"
	ctx := context.Background()

	certA, _ := generateSelfSignedPair(t, domain)
	_, keyB := generateSelfSignedPair(t, domain)
	if err := storage.Store(ctx, certmagic.StorageKeys.SiteCert(issuerKey, domain), certA); err != nil {
		t.Fatalf("seed cert: %v", err)
	}
	if err := storage.Store(ctx, certmagic.StorageKeys.SitePrivateKey(issuerKey, domain), keyB); err != nil {
		t.Fatalf("seed key: %v", err)
	}

	m := NewManager(conf.CertConfig{})
	err := m.loadPEMFromStorage(ctx, storage, issuerKey, domain)
	if err == nil {
		t.Fatal("expected error for mismatched cert/key pair")
	}
	if m.HasCert() {
		t.Error("manager should not store invalid pair")
	}
	_ = filepath.Join(dir, "stub")
}

func TestACMEFingerprint(t *testing.T) {
	base := conf.CertConfig{
		CertMode:    "dns",
		Domain:      "a.example.com",
		Email:       "ops@example.com",
		DNSProvider: "cloudflare",
		DNSEnv:      map[string]string{"CLOUDFLARE_API_TOKEN": "tok"},
	}

	cases := []struct {
		name    string
		mutate  func(*conf.CertConfig)
		differs bool
	}{
		{"same", func(*conf.CertConfig) {}, false},
		{"domain", func(c *conf.CertConfig) { c.Domain = "b.example.com" }, true},
		{"mode", func(c *conf.CertConfig) { c.CertMode = "http" }, true},
		{"email", func(c *conf.CertConfig) { c.Email = "other@example.com" }, true},
		{"provider", func(c *conf.CertConfig) { c.DNSProvider = "alidns" }, true},
		{"env_value", func(c *conf.CertConfig) { c.DNSEnv = map[string]string{"CLOUDFLARE_API_TOKEN": "other"} }, true},
		{"env_key_only", func(c *conf.CertConfig) { c.DNSEnv = map[string]string{"OTHER": "tok"} }, true},
	}

	baseFp := acmeFingerprint(base)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := base
			if tc.mutate != nil {
				cfg.DNSEnv = map[string]string{}
				for k, v := range base.DNSEnv {
					cfg.DNSEnv[k] = v
				}
				tc.mutate(&cfg)
			}
			got := acmeFingerprint(cfg)
			if (got != baseFp) != tc.differs {
				t.Errorf("differs=%v but got==base=%v", tc.differs, got == baseFp)
			}
		})
	}
}

func TestACMEFingerprintEnvOrderStable(t *testing.T) {
	a := conf.CertConfig{
		CertMode: "dns", Domain: "x", DNSProvider: "p",
		DNSEnv: map[string]string{"A": "1", "B": "2", "C": "3"},
	}
	b := conf.CertConfig{
		CertMode: "dns", Domain: "x", DNSProvider: "p",
		DNSEnv: map[string]string{"C": "3", "A": "1", "B": "2"},
	}
	if acmeFingerprint(a) != acmeFingerprint(b) {
		t.Fatal("fingerprint not order-independent")
	}
}
