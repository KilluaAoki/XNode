package cmd

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
)

var langZH bool

func langPath() string {
	return filepath.Join(defaultInstallRoot, "lang")
}

func initLang() {
	langZH = isChineseTag(detectLang())
}

func detectLang() string {
	if v := strings.TrimSpace(os.Getenv("XNODE_LANG")); v != "" {
		return v
	}
	if data, err := os.ReadFile(langPath()); err == nil {
		if v := strings.TrimSpace(string(data)); v != "" {
			return v
		}
	}
	for _, key := range []string{"LC_ALL", "LC_MESSAGES", "LANG"} {
		if v := os.Getenv(key); v != "" {
			return v
		}
	}
	return systemLanguage()
}

func isChineseTag(tag string) bool {
	return strings.HasPrefix(strings.ToLower(strings.TrimSpace(tag)), "zh")
}

func saveLang() error {
	if !isElevated() {
		return errors.New(tr(elevationHint, elevationHintZH))
	}
	value := "en"
	if langZH {
		value = "zh"
	}
	if err := os.MkdirAll(defaultInstallRoot, 0o700); err != nil {
		return err
	}
	return os.WriteFile(langPath(), []byte(value+"\n"), 0o644)
}

func tr(en, zh string) string {
	if langZH {
		return zh
	}
	return en
}
