package conf

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadEnvFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "credentials.env")
	content := "# comment\n\nXNODE_TEST_A=plain\nexport XNODE_TEST_B=\"quoted value\"\nXNODE_TEST_C='single'\nXNODE_TEST_D=a=b\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"XNODE_TEST_A", "XNODE_TEST_B", "XNODE_TEST_C", "XNODE_TEST_D"} {
		t.Setenv(k, "")
	}
	if err := LoadEnvFile(path); err != nil {
		t.Fatalf("LoadEnvFile() error = %v", err)
	}
	want := map[string]string{
		"XNODE_TEST_A": "plain",
		"XNODE_TEST_B": "quoted value",
		"XNODE_TEST_C": "single",
		"XNODE_TEST_D": "a=b",
	}
	for k, v := range want {
		if got := os.Getenv(k); got != v {
			t.Fatalf("%s = %q, want %q", k, got, v)
		}
	}
}

func TestLoadEnvFileMissing(t *testing.T) {
	if err := LoadEnvFile(filepath.Join(t.TempDir(), "missing.env")); err != nil {
		t.Fatalf("LoadEnvFile() missing error = %v", err)
	}
}

func TestLoadEnvFileInvalid(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bad.env")
	if err := os.WriteFile(path, []byte("NOEQUALS\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := LoadEnvFile(path); err == nil {
		t.Fatal("expected error for invalid line")
	}
}
