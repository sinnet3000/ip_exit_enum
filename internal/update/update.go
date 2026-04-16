package update

import (
	"archive/tar"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"

	"ip_exit_enum/internal/version"
)

const (
	githubAPIURL = "https://api.github.com/repos/sinnet3000/ip_exit_enum/releases/latest"
	binaryName   = "ip_exit_enum"
)

type Version string
type DownloadURL string
type AssetName string
type Checksum string

type releaseResponse struct {
	TagName string         `json:"tag_name"`
	Assets  []releaseAsset `json:"assets"`
}

type releaseAsset struct {
	Name               string `json:"name"`
	Size               int64  `json:"size"`
	BrowserDownloadURL string `json:"browser_download_url"`
}

type UpdateInfo struct {
	CurrentVersion Version
	LatestVersion  Version
	DownloadURL    DownloadURL
	AssetName      AssetName
	Size           int64
	Checksum       Checksum
}

func CheckForUpdate() (*UpdateInfo, error) {
	currentVersion := Version(strings.TrimPrefix(version.Version, "v"))

	release, err := fetchLatestRelease()
	if err != nil {
		return nil, fmt.Errorf("check for updates: %w", err)
	}

	latestVersion := Version(strings.TrimPrefix(release.TagName, "v"))

	if !isNewer(latestVersion, currentVersion) {
		return nil, nil
	}

	assetName := AssetName(fmt.Sprintf("%s_%s_%s_%s.tar.gz", binaryName, latestVersion, runtime.GOOS, runtime.GOARCH))
	var asset *releaseAsset
	var checksumsAsset *releaseAsset
	for i := range release.Assets {
		a := &release.Assets[i]
		if a.Name == string(assetName) {
			asset = a
		}
		if a.Name == "SHA256SUMS" {
			checksumsAsset = a
		}
	}

	if asset == nil {
		return nil, fmt.Errorf("no release asset found for %s/%s", runtime.GOOS, runtime.GOARCH)
	}

	var checksum Checksum
	if checksumsAsset != nil {
		checksum, _ = fetchChecksumFromFile(checksumsAsset.BrowserDownloadURL, string(assetName))
	}

	return &UpdateInfo{
		CurrentVersion: Version(version.Version),
		LatestVersion:  Version(release.TagName),
		DownloadURL:    DownloadURL(asset.BrowserDownloadURL),
		AssetName:      AssetName(asset.Name),
		Size:           asset.Size,
		Checksum:       checksum,
	}, nil
}

func PerformUpdate(info *UpdateInfo) error {
	if info.Checksum == "" {
		return fmt.Errorf("no checksum available for %s — refusing to install unverified binary", info.AssetName)
	}

	tmpDir, err := os.MkdirTemp("", "ip_exit_enum-update-*")
	if err != nil {
		return fmt.Errorf("create temp dir: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	archivePath := filepath.Join(tmpDir, string(info.AssetName))

	fmt.Printf("Downloading %s...\n", info.AssetName)
	checksum, err := downloadFile(string(info.DownloadURL), archivePath)
	if err != nil {
		return fmt.Errorf("download: %w", err)
	}

	fmt.Print("Verifying checksum... ")
	if !strings.EqualFold(checksum, string(info.Checksum)) {
		fmt.Println("FAILED")
		return fmt.Errorf("checksum mismatch: expected %s, got %s", info.Checksum, checksum)
	}
	fmt.Println("OK")

	fmt.Print("Extracting... ")
	extractDir := filepath.Join(tmpDir, "extracted")
	if err := extractTarGz(archivePath, extractDir); err != nil {
		return fmt.Errorf("extract: %w", err)
	}
	fmt.Println("OK")

	currentExe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("find current executable: %w", err)
	}
	currentExe, err = filepath.EvalSymlinks(currentExe)
	if err != nil {
		return fmt.Errorf("resolve symlinks: %w", err)
	}

	srcBinary := binaryName
	if runtime.GOOS == "windows" {
		srcBinary += ".exe"
	}
	srcPath := filepath.Join(extractDir, srcBinary)
	backupPath := currentExe + ".old"

	os.Remove(backupPath)

	if err := os.Rename(currentExe, backupPath); err != nil {
		return fmt.Errorf("backup current binary: %w", err)
	}

	if err := copyFile(srcPath, currentExe); err != nil {
		os.Rename(backupPath, currentExe)
		return fmt.Errorf("install new binary: %w", err)
	}

	if runtime.GOOS != "windows" {
		if err := os.Chmod(currentExe, 0755); err != nil {
			return fmt.Errorf("chmod: %w", err)
		}
	}

	os.Remove(backupPath)

	return nil
}

func fetchLatestRelease() (*releaseResponse, error) {
	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Get(githubAPIURL)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GitHub API returned %s", resp.Status)
	}

	var release releaseResponse
	if err := json.NewDecoder(resp.Body).Decode(&release); err != nil {
		return nil, err
	}
	return &release, nil
}

func downloadFile(url, dest string) (string, error) {
	client := &http.Client{Timeout: 120 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("download returned %s", resp.Status)
	}

	out, err := os.Create(dest)
	if err != nil {
		return "", err
	}
	defer out.Close()

	hasher := sha256.New()
	if _, err := io.Copy(out, io.TeeReader(resp.Body, hasher)); err != nil {
		return "", err
	}

	return hex.EncodeToString(hasher.Sum(nil)), nil
}

func extractTarGz(archive, destDir string) error {
	if err := os.MkdirAll(destDir, 0755); err != nil {
		return err
	}

	f, err := os.Open(archive)
	if err != nil {
		return err
	}
	defer f.Close()

	gz, err := gzip.NewReader(f)
	if err != nil {
		return err
	}
	defer gz.Close()

	tr := tar.NewReader(gz)
	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}

		if header.Typeflag != tar.TypeReg {
			continue
		}

		target, err := sanitizeTarPath(destDir, header.Name)
		if err != nil {
			return fmt.Errorf("invalid tar entry %q: %w", header.Name, err)
		}

		outFile, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, os.FileMode(header.Mode))
		if err != nil {
			return err
		}
		if _, err := io.Copy(outFile, tr); err != nil {
			outFile.Close()
			return err
		}
		outFile.Close()
	}

	return nil
}

func sanitizeTarPath(destDir, name string) (string, error) {
	if strings.HasPrefix(name, "/") {
		return "", fmt.Errorf("absolute path not allowed")
	}

	cleanName := filepath.Clean(name)

	if filepath.IsAbs(cleanName) {
		return "", fmt.Errorf("absolute path not allowed")
	}

	if strings.HasPrefix(cleanName, "..") || strings.Contains(cleanName, string(filepath.Separator)+"..") {
		return "", fmt.Errorf("path traversal not allowed")
	}

	target := filepath.Join(destDir, cleanName)

	absTarget, err := filepath.Abs(target)
	if err != nil {
		return "", err
	}
	absDestDir, err := filepath.Abs(destDir)
	if err != nil {
		return "", err
	}
	if !strings.HasPrefix(absTarget, absDestDir+string(filepath.Separator)) && absTarget != absDestDir {
		return "", fmt.Errorf("path escapes destination directory")
	}

	return target, nil
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer out.Close()

	if _, err := io.Copy(out, in); err != nil {
		return err
	}
	return out.Close()
}

func fetchChecksumFromFile(url, assetName string) (Checksum, error) {
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("failed to fetch checksums: %s", resp.Status)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	re := regexp.MustCompile(`(?i)[a-f0-9]{64}`)
	for _, line := range strings.Split(string(body), "\n") {
		if strings.Contains(line, assetName) {
			if match := re.FindString(line); match != "" {
				return Checksum(strings.ToLower(match)), nil
			}
		}
	}
	return "", nil
}

func isNewer(v1, v2 Version) bool {
	v1s := strings.TrimPrefix(string(v1), "v")
	v2s := strings.TrimPrefix(string(v2), "v")

	// Dev builds always have an update available
	if !isSemver(v2s) {
		return isSemver(v1s)
	}
	if !isSemver(v1s) {
		return false
	}

	parts1 := strings.Split(v1s, ".")
	parts2 := strings.Split(v2s, ".")

	for i := range 3 {
		var n1, n2 int
		if i < len(parts1) {
			n1, _ = strconv.Atoi(parts1[i])
		}
		if i < len(parts2) {
			n2, _ = strconv.Atoi(parts2[i])
		}
		if n1 > n2 {
			return true
		}
		if n1 < n2 {
			return false
		}
	}
	return false
}

func isSemver(v string) bool {
	v = strings.TrimPrefix(v, "v")
	parts := strings.Split(v, ".")
	if len(parts) < 2 {
		return false
	}
	for _, p := range parts {
		if _, err := strconv.Atoi(p); err != nil {
			return false
		}
	}
	return true
}

func FormatSize(bytes int64) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}
	div, exp := int64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(bytes)/float64(div), "KMGTPE"[exp])
}
