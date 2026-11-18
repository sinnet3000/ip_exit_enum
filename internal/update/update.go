package update

import (
	"archive/tar"
	"bytes"
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

	// maxReleaseJSONSize bounds the GitHub release metadata response. The
	// document is only a few KiB today, so 1 MiB leaves ample room while
	// preventing an untrusted endpoint from streaming an unbounded body into
	// memory.
	maxReleaseJSONSize int64 = 1 << 20

	// maxChecksumFileSize bounds the SHA256SUMS metadata response. Checksum
	// manifests are short text lists that stay far below 1 MiB.
	maxChecksumFileSize int64 = 1 << 20

	// maxArchiveSize is the hard cap for the compressed release archive. It
	// applies to the actual response body and is independent of the size
	// advertised in release metadata. Current archives are well under this;
	// 256 MiB leaves room for growth without allowing an unbounded download.
	maxArchiveSize int64 = 256 << 20
)

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
	CurrentVersion string
	LatestVersion  string
	DownloadURL    string
	AssetName      string
	Size           int64
	Checksum       string
}

func CheckForUpdate() (*UpdateInfo, error) {
	currentVersion := strings.TrimPrefix(version.Version, "v")

	release, err := fetchLatestRelease()
	if err != nil {
		return nil, fmt.Errorf("check for updates: %w", err)
	}

	latestVersion := strings.TrimPrefix(release.TagName, "v")

	if !isNewer(latestVersion, currentVersion) {
		return nil, nil
	}

	assetName := fmt.Sprintf("%s_%s_%s_%s.tar.gz", binaryName, latestVersion, runtime.GOOS, runtime.GOARCH)
	var asset *releaseAsset
	var checksumsAsset *releaseAsset
	for i := range release.Assets {
		a := &release.Assets[i]
		if a.Name == assetName {
			asset = a
		}
		if a.Name == "SHA256SUMS" {
			checksumsAsset = a
		}
	}

	if asset == nil {
		return nil, fmt.Errorf("no release asset found for %s/%s", runtime.GOOS, runtime.GOARCH)
	}

	if err := validateAssetSizes(asset, checksumsAsset); err != nil {
		return nil, err
	}

	var checksum string
	if checksumsAsset != nil {
		checksum, err = fetchChecksumFromFile(checksumsAsset.BrowserDownloadURL, assetName)
		if err != nil {
			return nil, fmt.Errorf("read release checksums: %w", err)
		}
	}

	return &UpdateInfo{
		CurrentVersion: version.Version,
		LatestVersion:  release.TagName,
		DownloadURL:    asset.BrowserDownloadURL,
		AssetName:      asset.Name,
		Size:           asset.Size,
		Checksum:       checksum,
	}, nil
}

// validateAssetSizes rejects clearly oversized assets using the sizes
// advertised in untrusted release metadata. This is only an early rejection
// hint; downloadFile and fetchChecksumFromFile enforce the hard limits against
// the actual response bodies regardless of what the metadata claims.
func validateAssetSizes(asset, checksumsAsset *releaseAsset) error {
	if asset.Size > maxArchiveSize {
		return fmt.Errorf("release asset %s is too large: advertised size %d bytes exceeds maximum allowed size of %d bytes", asset.Name, asset.Size, maxArchiveSize)
	}
	if checksumsAsset != nil && checksumsAsset.Size > maxChecksumFileSize {
		return fmt.Errorf("checksum asset %s is too large: advertised size %d bytes exceeds maximum allowed size of %d bytes", checksumsAsset.Name, checksumsAsset.Size, maxChecksumFileSize)
	}
	return nil
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

	archivePath := filepath.Join(tmpDir, info.AssetName)

	fmt.Printf("Downloading %s...\n", info.AssetName)
	checksum, err := downloadFile(info.DownloadURL, archivePath)
	if err != nil {
		return fmt.Errorf("download: %w", err)
	}

	fmt.Print("Verifying checksum... ")
	if !strings.EqualFold(checksum, info.Checksum) {
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

	if err := copyFile(srcPath, currentExe, 0755); err != nil {
		os.Rename(backupPath, currentExe)
		return fmt.Errorf("install new binary: %w", err)
	}

	os.Remove(backupPath)

	return nil
}

func fetchLatestRelease() (*releaseResponse, error) {
	return fetchLatestReleaseFrom(githubAPIURL)
}

func fetchLatestReleaseFrom(url string) (*releaseResponse, error) {
	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GitHub API returned %s", resp.Status)
	}

	if err := checkDeclaredSize(resp.ContentLength, maxReleaseJSONSize, "release metadata"); err != nil {
		return nil, err
	}

	body, err := readAllLimited(resp.Body, maxReleaseJSONSize, "release metadata")
	if err != nil {
		return nil, err
	}

	var release releaseResponse
	if err := json.NewDecoder(bytes.NewReader(body)).Decode(&release); err != nil {
		return nil, err
	}
	return &release, nil
}

func downloadFile(url, dest string) (string, error) {
	return downloadFileWithLimit(url, dest, maxArchiveSize)
}

func downloadFileWithLimit(url, dest string, limit int64) (string, error) {
	client := &http.Client{Timeout: 120 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("download returned %s", resp.Status)
	}

	// Reject an over-limit declared size before creating the destination.
	// Content-Length is not trusted: unknown (-1) or understated values still
	// go through the body limit below.
	if err := checkDeclaredSize(resp.ContentLength, limit, "archive"); err != nil {
		return "", err
	}

	out, err := os.Create(dest)
	if err != nil {
		return "", err
	}

	hasher := sha256.New()
	if _, err := writeAllLimited(io.MultiWriter(out, hasher), resp.Body, limit, "archive"); err != nil {
		out.Close()
		os.Remove(dest)
		return "", err
	}

	if err := out.Close(); err != nil {
		os.Remove(dest)
		return "", err
	}

	return hex.EncodeToString(hasher.Sum(nil)), nil
}

// checkDeclaredSize rejects a response whose declared Content-Length already
// exceeds limit. Unknown lengths (-1) and non-positive values are not trusted;
// the body limit remains authoritative for those responses.
func checkDeclaredSize(declared, limit int64, what string) error {
	if declared > limit {
		return fmt.Errorf("%s is too large: declared size %d bytes exceeds maximum allowed size of %d bytes", what, declared, limit)
	}
	return nil
}

// readAllLimited reads r in full while rejecting payloads larger than limit.
// It reads at most limit+1 bytes so a payload exactly at the limit succeeds
// and a payload one byte over is detected explicitly.
func readAllLimited(r io.Reader, limit int64, what string) ([]byte, error) {
	var buf bytes.Buffer
	if _, err := writeAllLimited(&buf, r, limit, what); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// writeAllLimited copies src to dst while writing at most limit bytes. Once
// exactly limit bytes have been copied it reads one additional byte to
// distinguish an exact-limit payload from an oversized one, so dst never
// receives more than limit bytes.
func writeAllLimited(dst io.Writer, src io.Reader, limit int64, what string) (int64, error) {
	n, err := io.Copy(dst, io.LimitReader(src, limit))
	if err != nil {
		return n, err
	}

	if n == limit {
		var extra [1]byte
		m, err := io.ReadFull(src, extra[:])
		if m > 0 {
			return n, fmt.Errorf("%s exceeds maximum allowed size of %d bytes", what, limit)
		}
		if err != nil && err != io.EOF {
			return n, err
		}
	}

	return n, nil
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

func copyFile(src, dst string, perm os.FileMode) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, perm)
	if err != nil {
		return err
	}
	defer out.Close()

	if _, err := io.Copy(out, in); err != nil {
		return err
	}
	return out.Close()
}

func fetchChecksumFromFile(url, assetName string) (string, error) {
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("failed to fetch checksums: %s", resp.Status)
	}

	if err := checkDeclaredSize(resp.ContentLength, maxChecksumFileSize, "checksum file"); err != nil {
		return "", err
	}

	body, err := readAllLimited(resp.Body, maxChecksumFileSize, "checksum file")
	if err != nil {
		return "", err
	}

	re := regexp.MustCompile(`(?i)^[a-f0-9]{64}$`)
	for _, line := range strings.Split(string(body), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 2 && strings.TrimPrefix(fields[1], "*") == assetName && re.MatchString(fields[0]) {
			return strings.ToLower(fields[0]), nil
		}
	}
	return "", nil
}

func isNewer(v1, v2 string) bool {
	v1s := strings.TrimPrefix(v1, "v")
	v2s := strings.TrimPrefix(v2, "v")

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
