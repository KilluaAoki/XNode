package cmd

import (
	"crypto/mlkem"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"os"
	"runtime"
	"strings"

	"golang.org/x/crypto/curve25519"
	"lukechampine.com/blake3"
)

func runX25519(args []string) error {
	fs := flag.NewFlagSet("x25519", flag.ContinueOnError)
	input := fs.String("i", "", "derive the public key from this private key")
	if err := fs.Parse(args); err != nil {
		return err
	}
	priv := make([]byte, curve25519.ScalarSize)
	if *input != "" {
		decoded, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(strings.TrimSpace(*input), "="))
		if err != nil || len(decoded) != curve25519.ScalarSize {
			return errors.New("private key must be 32 bytes of base64url")
		}
		copy(priv, decoded)
	} else if _, err := rand.Read(priv); err != nil {
		return err
	}
	priv[0] &= 248
	priv[31] &= 127
	priv[31] |= 64
	pub, err := curve25519.X25519(priv, curve25519.Basepoint)
	if err != nil {
		return err
	}
	fmt.Printf(tr("Private key: %s\n", "私钥：%s\n"), base64.RawURLEncoding.EncodeToString(priv))
	fmt.Printf(tr("Public key:  %s\n", "公钥：%s\n"), base64.RawURLEncoding.EncodeToString(pub))
	return nil
}

// runMLKEM768 generates an ML-KEM-768 key pair for VLESS encryption, with
// the same output as "xray mlkem768": the seed goes into the server
// decryption, the client key into the client encryption.
func runMLKEM768(args []string) error {
	fs := flag.NewFlagSet("mlkem768", flag.ContinueOnError)
	input := fs.String("i", "", "derive the client key from this seed")
	if err := fs.Parse(args); err != nil {
		return err
	}
	seed := make([]byte, mlkem.SeedSize)
	if *input != "" {
		decoded, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(strings.TrimSpace(*input), "="))
		if err != nil || len(decoded) != mlkem.SeedSize {
			return errors.New("seed must be 64 bytes of base64url")
		}
		copy(seed, decoded)
	} else if _, err := rand.Read(seed); err != nil {
		return err
	}
	key, err := mlkem.NewDecapsulationKey768(seed)
	if err != nil {
		return err
	}
	client := key.EncapsulationKey().Bytes()
	hash := blake3.Sum256(client)
	fmt.Printf(tr("Seed:   %s\n", "私钥（Seed）：%s\n"), base64.RawURLEncoding.EncodeToString(seed))
	fmt.Printf(tr("Client: %s\n", "公钥（Client）：%s\n"), base64.RawURLEncoding.EncodeToString(client))
	fmt.Printf(tr("Hash32: %s\n", "Hash32：%s\n"), base64.RawURLEncoding.EncodeToString(hash[:]))
	return nil
}

const bbrSysctlPath = "/etc/sysctl.d/99-xnode-bbr.conf"

func runBBR() error {
	if runtime.GOOS != "linux" {
		return errors.New(tr("BBR is only available on Linux", "BBR 仅支持 Linux"))
	}
	if err := ensureRoot("bbr"); err != nil {
		return err
	}
	if current, _ := os.ReadFile("/proc/sys/net/ipv4/tcp_congestion_control"); strings.TrimSpace(string(current)) == "bbr" {
		fmt.Println(tr("BBR is already enabled", "BBR 已开启"))
		return nil
	}
	runCommand("modprobe", "tcp_bbr")
	available, _ := os.ReadFile("/proc/sys/net/ipv4/tcp_available_congestion_control")
	if !strings.Contains(string(available), "bbr") {
		return errors.New(tr("kernel does not support BBR (requires Linux 4.9+)", "系统内核不支持 BBR（需要 Linux 4.9+）"))
	}
	content := "net.core.default_qdisc=fq\nnet.ipv4.tcp_congestion_control=bbr\n"
	if err := os.WriteFile(bbrSysctlPath, []byte(content), 0o644); err != nil {
		return err
	}
	if err := runCommand("sysctl", "-p", bbrSysctlPath); err != nil {
		return err
	}
	fmt.Println(tr("BBR enabled", "BBR 开启成功"))
	return nil
}
