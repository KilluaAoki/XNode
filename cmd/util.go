package cmd

import (
	"archive/zip"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func copyFile(src, dst string) error {
	info, err := os.Stat(src)
	if err != nil {
		return err
	}
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return os.WriteFile(dst, data, info.Mode().Perm())
}

func replaceFile(src, dst string) error {
	tmp := filepath.Join(filepath.Dir(dst), "."+filepath.Base(dst)+".tmp")
	if err := copyFile(src, tmp); err != nil {
		os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, dst); err != nil {
		if e := swapInUseFile(tmp, dst); e != nil {
			os.Remove(tmp)
			return err
		}
	}
	return nil
}

func swapInUseFile(tmp, dst string) error {
	stale, _ := filepath.Glob(dst + ".*old")
	for _, p := range stale {
		os.Remove(p)
	}
	old := dst + ".old"
	if fileExists(old) {
		old = dst + "." + strconv.FormatInt(time.Now().UnixNano(), 10) + ".old"
	}
	if err := os.Rename(dst, old); err != nil {
		return err
	}
	if err := os.Rename(tmp, dst); err != nil {
		os.Rename(old, dst)
		return err
	}
	os.Remove(old)
	return nil
}

func runCommand(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin
	return cmd.Run()
}

func downloadFile(url, dest string) error {
	client := &http.Client{Timeout: 120 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("HTTP %d from %s", resp.StatusCode, url)
	}
	f, err := os.Create(dest)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = io.Copy(f, resp.Body)
	return err
}

func releaseAsset(goos, goarch string) (string, error) {
	osName := map[string]string{"linux": "linux", "darwin": "macos", "windows": "windows"}[goos]
	if osName == "" {
		return "", fmt.Errorf("unsupported os: %s", goos)
	}
	archName := map[string]string{"amd64": "64", "arm64": "arm64-v8a"}[goarch]
	if goos == "linux" && goarch == "arm" {
		archName = "arm32-v7a"
	}
	if archName == "" {
		return "", fmt.Errorf("unsupported architecture: %s/%s", goos, goarch)
	}
	return "xnode-" + osName + "-" + archName + ".zip", nil
}

func extractZipFile(archive, name, dest string) error {
	r, err := zip.OpenReader(archive)
	if err != nil {
		return err
	}
	defer r.Close()
	for _, f := range r.File {
		if f.Name != name && f.Name != "./"+name {
			continue
		}
		src, err := f.Open()
		if err != nil {
			return err
		}
		defer src.Close()
		out, err := os.OpenFile(dest, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o755)
		if err != nil {
			return err
		}
		if _, err := io.Copy(out, src); err != nil {
			out.Close()
			return err
		}
		return out.Close()
	}
	return fmt.Errorf("%s not found in %s", name, filepath.Base(archive))
}

// checksumAsset is the sha256sum manifest published with every release.
const checksumAsset = "sha256sums.txt"

// verifyChecksum checks archive against the entry for asset in the
// sha256sum-format manifest at sumsPath.
func verifyChecksum(archive, sumsPath, asset string) error {
	manifest, err := os.ReadFile(sumsPath)
	if err != nil {
		return err
	}
	var want string
	for _, line := range strings.Split(string(manifest), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 2 && strings.TrimPrefix(fields[1], "*") == asset {
			want = strings.ToLower(fields[0])
			break
		}
	}
	if want == "" {
		return fmt.Errorf("%s has no entry for %s", checksumAsset, asset)
	}
	f, err := os.Open(archive)
	if err != nil {
		return err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return err
	}
	if got := hex.EncodeToString(h.Sum(nil)); got != want {
		return fmt.Errorf("checksum mismatch for %s: got %s, want %s", asset, got, want)
	}
	return nil
}

func resolveDownloadURL(artifact, version string) string {
	if version == "latest" {
		return downloadBase + "/latest/download/" + artifact
	}
	return downloadBase + "/download/" + version + "/" + artifact
}

func editPathList(list, dir string, add bool) string {
	entries := strings.Split(list, ";")
	kept := make([]string, 0, len(entries))
	found := false
	for _, e := range entries {
		if samePathEntry(e, dir) {
			found = true
			continue
		}
		kept = append(kept, e)
	}
	if add {
		if found {
			return list
		}
		if strings.TrimSpace(list) == "" {
			return dir
		}
		return strings.TrimSuffix(list, ";") + ";" + dir
	}
	return strings.Join(kept, ";")
}

func samePathEntry(a, b string) bool {
	norm := func(s string) string {
		return strings.ToLower(strings.TrimRight(strings.Trim(strings.TrimSpace(s), `"`), `\/`))
	}
	return norm(a) != "" && norm(a) == norm(b)
}

func parseTailArgs(args []string) (int, bool, error) {
	if len(args) == 0 {
		return 100, true, nil
	}
	lines, follow := 100, false
	for i := 0; i < len(args); i++ {
		switch a := args[i]; {
		case a == "-f" || a == "--follow":
			follow = true
		case a == "-n" || a == "--lines":
			if i+1 >= len(args) {
				return 0, false, fmt.Errorf("%s requires a value", a)
			}
			i++
			n, err := strconv.Atoi(args[i])
			if err != nil || n < 0 {
				return 0, false, fmt.Errorf("invalid line count: %s", args[i])
			}
			lines = n
		default:
			return 0, false, fmt.Errorf("unknown log option: %s", a)
		}
	}
	return lines, follow, nil
}

const tailWindow = 1 << 20

func tailFile(path string, lines int, follow bool, w io.Writer, stop <-chan os.Signal) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return err
	}
	start := max(info.Size()-tailWindow, 0)
	if _, err := f.Seek(start, io.SeekStart); err != nil {
		return err
	}
	data, err := io.ReadAll(f)
	if err != nil {
		return err
	}
	offset := start + int64(len(data))
	w.Write(lastLines(data, lines))
	for follow {
		select {
		case <-stop:
			return nil
		case <-time.After(500 * time.Millisecond):
		}
		info, err := os.Stat(path)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			return err
		}
		if info.Size() < offset {
			if _, err := f.Seek(0, io.SeekStart); err != nil {
				return err
			}
			offset = 0
		}
		n, err := io.Copy(w, f)
		offset += n
		if err != nil {
			return err
		}
	}
	return nil
}

func lastLines(data []byte, n int) []byte {
	if n <= 0 {
		return nil
	}
	i := len(data)
	if i > 0 && data[i-1] == '\n' {
		i--
	}
	for count := 0; i > 0; i-- {
		if data[i-1] == '\n' {
			count++
			if count == n {
				break
			}
		}
	}
	return data[i:]
}
