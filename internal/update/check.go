package update

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"runtime"
	"strings"
	"time"
)

const (
	// GitHubReleasesAPI is the endpoint to check for new releases.
	// Uses the GitHub API to get the latest release tag.
	GitHubReleasesAPI = "https://api.github.com/repos/charlieseay/stdout-scanner/releases/latest"

	// CheckTimeout is the maximum time to wait for the update check.
	CheckTimeout = 5 * time.Second
)

// ReleaseInfo holds information about the latest available release.
type ReleaseInfo struct {
	TagName    string `json:"tag_name"`
	HTMLURL    string `json:"html_url"`
	Body       string `json:"body"`
	Published  string `json:"published_at"`
	HasUpdate  bool   `json:"-"`
	CurrentVer string `json:"-"`
}

// Check queries GitHub for the latest release and compares it to the current version.
// Returns nil if the check fails (network error, rate limit, etc.) — never blocks the user.
func Check(currentVersion string) *ReleaseInfo {
	if currentVersion == "dev" || currentVersion == "" {
		return nil // Don't check in dev builds
	}

	ctx, cancel := context.WithTimeout(context.Background(), CheckTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "GET", GitHubReleasesAPI, nil)
	if err != nil {
		return nil
	}
	req.Header.Set("User-Agent", "stdout-scanner/"+currentVersion)
	req.Header.Set("Accept", "application/vnd.github+json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil // Network error — silently skip
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil // Rate limited or repo not found — silently skip
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 16384))
	if err != nil {
		return nil
	}

	var release ReleaseInfo
	if err := json.Unmarshal(body, &release); err != nil {
		return nil
	}

	release.CurrentVer = currentVersion
	release.HasUpdate = isNewer(release.TagName, currentVersion)

	if !release.HasUpdate {
		return nil
	}

	return &release
}

// PrintUpdateNotice prints a one-liner if an update is available.
// Designed to be non-intrusive — one line at the end of output.
func PrintUpdateNotice(info *ReleaseInfo) {
	if info == nil || !info.HasUpdate {
		return
	}

	latestClean := strings.TrimPrefix(info.TagName, "v")
	currentClean := strings.TrimPrefix(info.CurrentVer, "v")

	fmt.Fprintf(
		os.Stderr,
		"\nUpdate available: %s → %s\n  %s\n  Run: stdout-scanner update\n\n",
		currentClean, latestClean, info.HTMLURL,
	)
}

// SelfUpdate downloads the latest release binary and replaces the current executable.
func SelfUpdate(info *ReleaseInfo) error {
	if info == nil || !info.HasUpdate {
		return fmt.Errorf("no update available")
	}

	// Get the current executable path
	execPath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("cannot determine executable path: %w", err)
	}

	// Resolve symlinks
	execPath, err = evalSymlinks(execPath)
	if err != nil {
		return fmt.Errorf("cannot resolve executable path: %w", err)
	}

	// Determine platform binary name
	goos := runtime.GOOS
	goarch := runtime.GOARCH
	assetName := fmt.Sprintf("stdout-scanner-%s-%s", goos, goarch)
	if goos == "windows" {
		assetName += ".exe"
	}

	// Find the download URL from release assets
	downloadURL, err := findAssetURL(info, assetName)
	if err != nil {
		return err
	}

	// Download to a temp file
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "GET", downloadURL, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("User-Agent", "stdout-scanner/"+info.CurrentVer)
	req.Header.Set("Accept", "application/octet-stream")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("download failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return fmt.Errorf("download returned HTTP %d", resp.StatusCode)
	}

	// Write to temp file next to the executable
	tmpPath := execPath + ".tmp"
	tmpFile, err := os.OpenFile(tmpPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0755)
	if err != nil {
		return fmt.Errorf("cannot create temp file: %w", err)
	}

	_, err = io.Copy(tmpFile, resp.Body)
	tmpFile.Close()
	if err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("download incomplete: %w", err)
	}

	// Atomic replace: rename old → .bak, rename new → current
	bakPath := execPath + ".bak"
	os.Remove(bakPath) // remove previous backup if exists

	if err := os.Rename(execPath, bakPath); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("cannot backup current binary: %w", err)
	}

	if err := os.Rename(tmpPath, execPath); err != nil {
		// Try to restore backup
		os.Rename(bakPath, execPath)
		return fmt.Errorf("cannot replace binary: %w", err)
	}

	// Clean up backup
	os.Remove(bakPath)

	return nil
}

// findAssetURL looks through release assets for the platform-specific binary.
func findAssetURL(info *ReleaseInfo, assetName string) (string, error) {
	// Fetch the full release to get assets
	ctx, cancel := context.WithTimeout(context.Background(), CheckTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "GET", GitHubReleasesAPI, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", "stdout-scanner/"+info.CurrentVer)
	req.Header.Set("Accept", "application/vnd.github+json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("cannot fetch release: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 65536))
	if err != nil {
		return "", err
	}

	var release struct {
		Assets []struct {
			Name               string `json:"name"`
			BrowserDownloadURL string `json:"browser_download_url"`
		} `json:"assets"`
	}
	if err := json.Unmarshal(body, &release); err != nil {
		return "", fmt.Errorf("cannot parse release: %w", err)
	}

	for _, asset := range release.Assets {
		if strings.Contains(strings.ToLower(asset.Name), strings.ToLower(assetName)) {
			return asset.BrowserDownloadURL, nil
		}
	}

	return "", fmt.Errorf("no binary found for %s in release %s — download manually from %s", assetName, info.TagName, info.HTMLURL)
}

// evalSymlinks resolves symlinks in a path.
func evalSymlinks(path string) (string, error) {
	resolved, err := os.Readlink(path)
	if err != nil {
		return path, nil // Not a symlink
	}
	if !strings.HasPrefix(resolved, "/") {
		// Relative symlink — resolve against parent dir
		dir := path[:strings.LastIndex(path, "/")+1]
		resolved = dir + resolved
	}
	return resolved, nil
}

// isNewer compares two semver-like strings and returns true if latest > current.
// Handles "v" prefix and simple x.y.z comparison.
func isNewer(latest, current string) bool {
	latest = strings.TrimPrefix(latest, "v")
	current = strings.TrimPrefix(current, "v")

	if latest == current {
		return false
	}

	latestParts := splitVersion(latest)
	currentParts := splitVersion(current)

	for i := 0; i < 3; i++ {
		l, c := 0, 0
		if i < len(latestParts) {
			l = latestParts[i]
		}
		if i < len(currentParts) {
			c = currentParts[i]
		}
		if l > c {
			return true
		}
		if l < c {
			return false
		}
	}

	return false
}

// splitVersion parses "1.2.3" into [1, 2, 3].
func splitVersion(v string) []int {
	// Strip pre-release suffix (e.g., "1.2.3-beta")
	if idx := strings.Index(v, "-"); idx != -1 {
		v = v[:idx]
	}

	parts := strings.Split(v, ".")
	result := make([]int, 0, len(parts))
	for _, p := range parts {
		n := 0
		for _, c := range p {
			if c >= '0' && c <= '9' {
				n = n*10 + int(c-'0')
			}
		}
		result = append(result, n)
	}
	return result
}
