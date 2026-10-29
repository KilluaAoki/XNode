package geodata

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"time"

	"github.com/KilluaAoki/XNode/common/nlog"
)

const (
	xrayGeoIPURL   = "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geoip.dat"
	xrayGeoSiteURL = "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geosite.dat"

	singboxGeoSiteRuleSetURL = "https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-%s.srs"
	singboxGeoIPRuleSetURL   = "https://raw.githubusercontent.com/SagerNet/sing-geoip/rule-set/geoip-%s.srs"
)

var httpClient = &http.Client{Timeout: 10 * time.Minute}

var ruleSetClient = &http.Client{Timeout: time.Minute}

var ruleSetNamePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9!_.-]*$`)

// Ensure downloads the xray geoip.dat / geosite.dat files when missing.
func Ensure(dir string, needGeoIP, needGeoSite bool) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("create geo_data_dir %q: %w", dir, err)
	}

	type entry struct {
		name string
		url  string
	}

	var files []entry
	if needGeoIP {
		files = append(files, entry{"geoip.dat", xrayGeoIPURL})
	}
	if needGeoSite {
		files = append(files, entry{"geosite.dat", xrayGeoSiteURL})
	}

	var firstErr error
	for _, f := range files {
		if err := ensureFile(httpClient, dir, f.name, f.url); err != nil {
			nlog.Core().Warn("geo database auto-download failed", "file", f.name, "error", err)
			if firstErr == nil {
				firstErr = err
			}
		}
	}
	return firstErr
}

// RuleSetTag returns the sing-box rule-set tag for a geosite/geoip name,
// or "" when the name is not a valid rule-set name.
func RuleSetTag(kind, name string) string {
	if (kind != "geosite" && kind != "geoip") || !ruleSetNamePattern.MatchString(name) {
		return ""
	}
	return kind + "-" + name
}

// RuleSetPath returns where a sing-box rule-set file is stored under dir.
func RuleSetPath(dir, tag string) string {
	return filepath.Join(dir, "rule-set", tag+".srs")
}

// EnsureRuleSets downloads missing sing-box binary rule-sets for the given
// geosite and geoip names. Failures are logged and do not stop other downloads.
func EnsureRuleSets(dir string, geoSites, geoIPs []string) {
	if len(geoSites) == 0 && len(geoIPs) == 0 {
		return
	}
	ruleSetDir := filepath.Join(dir, "rule-set")
	if err := os.MkdirAll(ruleSetDir, 0o755); err != nil {
		nlog.Core().Warn("create rule-set dir failed", "dir", ruleSetDir, "error", err)
		return
	}
	download := func(kind, urlFormat string, names []string) {
		for _, name := range names {
			tag := RuleSetTag(kind, name)
			if tag == "" {
				nlog.Core().Warn("invalid rule-set name, skipped", "kind", kind, "name", name)
				continue
			}
			if err := ensureFile(ruleSetClient, ruleSetDir, tag+".srs", fmt.Sprintf(urlFormat, name)); err != nil {
				nlog.Core().Warn("rule-set auto-download failed", "tag", tag, "error", err)
			}
		}
	}
	download("geosite", singboxGeoSiteRuleSetURL, geoSites)
	download("geoip", singboxGeoIPRuleSetURL, geoIPs)
}

func ensureFile(client *http.Client, dir, name, url string) error {
	dst := filepath.Join(dir, name)
	if _, err := os.Stat(dst); err == nil {
		return nil
	}
	nlog.Core().Info("geo database missing, downloading automatically", "file", name, "url", url)
	if err := atomicDownload(client, dst, url); err != nil {
		return err
	}
	if fi, err := os.Stat(dst); err == nil {
		nlog.Core().Info("geo database ready", "file", name, "size_kb", fi.Size()/1024)
	}
	return nil
}

func atomicDownload(client *http.Client, dst, url string) error {
	resp, err := client.Get(url)
	if err != nil {
		return fmt.Errorf("http get %s: %w", url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected HTTP status from %s: %s", url, resp.Status)
	}

	tmp := dst + ".tmp"
	f, err := os.Create(tmp)
	if err != nil {
		return fmt.Errorf("create temp file: %w", err)
	}
	defer os.Remove(tmp)

	if _, err := io.Copy(f, resp.Body); err != nil {
		f.Close()
		return fmt.Errorf("write geo database: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("close temp file: %w", err)
	}
	if err := os.Rename(tmp, dst); err != nil {
		return fmt.Errorf("rename to destination: %w", err)
	}
	return nil
}
