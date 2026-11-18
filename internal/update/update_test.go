package update

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestIsNewer(t *testing.T) {
	for _, tc := range []struct {
		latest, current string
		want            bool
	}{
		{"1.2.4", "1.2.3", true},
		{"1.3.0", "1.2.9", true},
		{"2.0.0", "1.9.9", true},
		{"1.2.3", "1.2.3", false},
		{"1.2.2", "1.2.3", false},
		{"1.10.0", "1.9.0", true}, // numeric, not lexicographic
		{"v1.2.4", "v1.2.3", true},
		{"1.2", "1.1.9", true},
		{"1.2.3", "dev", true}, // dev builds always see an update
		{"garbage", "1.2.3", false},
		{"garbage", "dev", false},
	} {
		if got := isNewer(tc.latest, tc.current); got != tc.want {
			t.Errorf("isNewer(%q, %q) = %v, want %v", tc.latest, tc.current, got, tc.want)
		}
	}
}

func TestFormatSize(t *testing.T) {
	for in, want := range map[int64]string{0: "0 B", 1023: "1023 B", 1024: "1.0 KB", 1536: "1.5 KB", 5 << 20: "5.0 MB"} {
		if got := FormatSize(in); got != want {
			t.Errorf("FormatSize(%d) = %q, want %q", in, got, want)
		}
	}
}

func TestSanitizeTarPath(t *testing.T) {
	dir := t.TempDir()
	for name, wantErr := range map[string]bool{
		"ip_exit_enum":      false,
		"sub/ip_exit_enum":  false,
		"/etc/passwd":       true,
		"../evil":           true,
		"a/../../evil":      true,
		"sub/../../../evil": true,
	} {
		_, err := sanitizeTarPath(dir, name)
		if (err != nil) != wantErr {
			t.Errorf("sanitizeTarPath(%q) error = %v, wantErr %v", name, err, wantErr)
		}
	}
}

func writeTarGz(t *testing.T, path string, entries []tar.Header, body string) {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	gz := gzip.NewWriter(f)
	tw := tar.NewWriter(gz)
	for _, h := range entries {
		h := h
		if h.Typeflag == tar.TypeReg {
			h.Size = int64(len(body))
		}
		if err := tw.WriteHeader(&h); err != nil {
			t.Fatal(err)
		}
		if h.Typeflag == tar.TypeReg {
			tw.Write([]byte(body))
		}
	}
	tw.Close()
	gz.Close()
}

func TestExtractTarGz(t *testing.T) {
	tmp := t.TempDir()
	archive := filepath.Join(tmp, "a.tar.gz")
	writeTarGz(t, archive, []tar.Header{
		{Name: "ip_exit_enum", Mode: 0755, Typeflag: tar.TypeReg},
		{Name: "link", Linkname: "/etc/passwd", Typeflag: tar.TypeSymlink}, // must be skipped
	}, "binary")

	dest := filepath.Join(tmp, "out")
	if err := extractTarGz(archive, dest); err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(filepath.Join(dest, "ip_exit_enum")); string(got) != "binary" {
		t.Fatalf("extracted content = %q", got)
	}
	if _, err := os.Lstat(filepath.Join(dest, "link")); err == nil {
		t.Fatal("symlink entry should not be extracted")
	}

	evil := filepath.Join(tmp, "evil.tar.gz")
	writeTarGz(t, evil, []tar.Header{{Name: "../escape", Mode: 0644, Typeflag: tar.TypeReg}}, "x")
	if err := extractTarGz(evil, filepath.Join(tmp, "out2")); err == nil {
		t.Fatal("expected path traversal entry to be rejected")
	}
	if _, err := os.Stat(filepath.Join(tmp, "escape")); err == nil {
		t.Fatal("traversal entry was written outside destination")
	}
}

func TestFetchChecksumFromFile(t *testing.T) {
	const sum = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789ABCDEF"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/missing" {
			http.NotFound(w, r)
			return
		}
		w.Write([]byte(strings.Repeat("f", 64) + "  other.tar.gz\n" + strings.Repeat("e", 64) + "  wanted.tar.gz.sig\n" + sum + "  wanted.tar.gz\n"))
	}))
	defer srv.Close()

	if got, err := fetchChecksumFromFile(srv.URL, "wanted.tar.gz"); err != nil || got != strings.ToLower(sum) {
		t.Fatalf("got %q, %v", got, err)
	}
	if got, err := fetchChecksumFromFile(srv.URL, "absent.tar.gz"); err != nil || got != "" {
		t.Fatalf("absent asset: got %q, %v", got, err)
	}
	if _, err := fetchChecksumFromFile(srv.URL+"/missing", "wanted.tar.gz"); err == nil {
		t.Fatal("expected error on non-200")
	}
}

func TestPerformUpdateRefusesWithoutChecksum(t *testing.T) {
	if err := PerformUpdate(&UpdateInfo{AssetName: "x.tar.gz"}); err == nil {
		t.Fatal("expected refusal without checksum")
	}
}

func TestPerformUpdateRejectsChecksumMismatch(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("tampered")) }))
	defer srv.Close()

	err := PerformUpdate(&UpdateInfo{AssetName: "x.tar.gz", DownloadURL: srv.URL, Checksum: strings.Repeat("0", 64)})
	if err == nil || !strings.Contains(err.Error(), "checksum mismatch") {
		t.Fatalf("expected checksum mismatch, got %v", err)
	}
}

func writeChunked(w http.ResponseWriter, body []byte) {
	w.WriteHeader(http.StatusOK)
	if f, ok := w.(http.Flusher); ok {
		f.Flush()
	}
	_, _ = w.Write(body)
}

func TestWriteAllLimited(t *testing.T) {
	const limit = 8
	for _, tc := range []struct {
		name    string
		body    string
		wantErr bool
	}{
		{"empty", "", false},
		{"under limit", "1234567", false},
		{"exact limit", "12345678", false},
		{"one over limit", "123456789", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var dst bytes.Buffer
			n, err := writeAllLimited(&dst, strings.NewReader(tc.body), limit, "test payload")
			if (err != nil) != tc.wantErr {
				t.Fatalf("writeAllLimited() error = %v, wantErr %v", err, tc.wantErr)
			}
			if tc.wantErr && !strings.Contains(err.Error(), "test payload exceeds maximum allowed size of 8 bytes") {
				t.Fatalf("unexpected error: %v", err)
			}

			wantLen := int64(len(tc.body))
			if wantLen > limit {
				wantLen = limit
			}
			if int64(dst.Len()) != wantLen || n != wantLen {
				t.Fatalf("wrote %d bytes (reported %d), want %d", dst.Len(), n, wantLen)
			}
			if int64(dst.Len()) > limit {
				t.Fatalf("destination received %d bytes, exceeds limit %d", dst.Len(), limit)
			}
		})
	}
}

func TestReadAllLimited(t *testing.T) {
	const limit = 5
	if got, err := readAllLimited(strings.NewReader("12345"), limit, "payload"); err != nil || string(got) != "12345" {
		t.Fatalf("exact limit: got %q, %v", got, err)
	}
	if _, err := readAllLimited(strings.NewReader("123456"), limit, "payload"); err == nil || !strings.Contains(err.Error(), "payload exceeds maximum allowed size of 5 bytes") {
		t.Fatalf("expected explicit oversized error, got %v", err)
	}
}

func TestFetchLatestReleaseLimitsMetadata(t *testing.T) {
	const payload = `{"tag_name":"v1.2.3","assets":[]}`
	exact := append([]byte(payload), bytes.Repeat([]byte(" "), int(maxReleaseJSONSize)-len(payload))...)
	over := append(append([]byte(nil), exact...), ' ')

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/exact":
			_, _ = w.Write(exact)
		case "/over":
			writeChunked(w, over)
		case "/declared":
			w.Header().Set("Content-Length", strconv.FormatInt(maxReleaseJSONSize+1, 10))
			_, _ = w.Write(over)
		}
	}))
	defer srv.Close()

	release, err := fetchLatestReleaseFrom(srv.URL + "/exact")
	if err != nil {
		t.Fatalf("exact limit: %v", err)
	}
	if release.TagName != "v1.2.3" {
		t.Fatalf("tag = %q, want v1.2.3", release.TagName)
	}

	if _, err := fetchLatestReleaseFrom(srv.URL + "/over"); err == nil || !strings.Contains(err.Error(), "release metadata exceeds maximum allowed size") {
		t.Fatalf("unknown-length oversized body: got %v", err)
	}
	if _, err := fetchLatestReleaseFrom(srv.URL + "/declared"); err == nil || !strings.Contains(err.Error(), "release metadata is too large") {
		t.Fatalf("declared oversized body: got %v", err)
	}
}

func TestFetchChecksumFromFileLimitsMetadata(t *testing.T) {
	const sum = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	line := sum + "  wanted.tar.gz\n"
	exact := line + strings.Repeat("\n", int(maxChecksumFileSize)-len(line))
	over := bytes.Repeat([]byte("x"), int(maxChecksumFileSize)+1)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/exact":
			_, _ = w.Write([]byte(exact))
		case "/over":
			writeChunked(w, over)
		case "/declared":
			w.Header().Set("Content-Length", strconv.FormatInt(maxChecksumFileSize+1, 10))
			_, _ = w.Write(over)
		}
	}))
	defer srv.Close()

	if got, err := fetchChecksumFromFile(srv.URL+"/exact", "wanted.tar.gz"); err != nil || got != sum {
		t.Fatalf("exact limit: got %q, %v", got, err)
	}
	if _, err := fetchChecksumFromFile(srv.URL+"/over", "wanted.tar.gz"); err == nil || !strings.Contains(err.Error(), "checksum file exceeds maximum allowed size") {
		t.Fatalf("unknown-length oversized body: got %v", err)
	}
	if _, err := fetchChecksumFromFile(srv.URL+"/declared", "wanted.tar.gz"); err == nil || !strings.Contains(err.Error(), "checksum file is too large") {
		t.Fatalf("declared oversized body: got %v", err)
	}
}

func TestDownloadFileWithLimit(t *testing.T) {
	const limit = 64
	body := bytes.Repeat([]byte("a"), limit)
	over := append(append([]byte(nil), body...), 'a')

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/exact":
			_, _ = w.Write(body)
		case "/over":
			writeChunked(w, over)
		case "/declared":
			w.Header().Set("Content-Length", strconv.FormatInt(limit+1, 10))
			_, _ = w.Write(over)
		}
	}))
	defer srv.Close()

	t.Run("exact limit", func(t *testing.T) {
		dest := filepath.Join(t.TempDir(), "archive.tar.gz")
		got, err := downloadFileWithLimit(srv.URL+"/exact", dest, limit)
		if err != nil {
			t.Fatalf("exact limit: %v", err)
		}
		data, err := os.ReadFile(dest)
		if err != nil {
			t.Fatal(err)
		}
		if len(data) != limit {
			t.Fatalf("downloaded %d bytes, want %d", len(data), limit)
		}
		if want := fmt.Sprintf("%x", sha256.Sum256(body)); got != want {
			t.Fatalf("checksum = %q, want %q", got, want)
		}
	})

	for _, tc := range []struct {
		name    string
		path    string
		wantErr string
	}{
		{"unknown length over limit", "/over", fmt.Sprintf("archive exceeds maximum allowed size of %d bytes", limit)},
		{"declared over limit", "/declared", "archive is too large: declared size"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dest := filepath.Join(t.TempDir(), "archive.tar.gz")
			_, err := downloadFileWithLimit(srv.URL+tc.path, dest, limit)
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("expected %q, got %v", tc.wantErr, err)
			}
			if _, statErr := os.Stat(dest); !os.IsNotExist(statErr) {
				t.Fatalf("partial archive should be removed, stat error = %v", statErr)
			}
		})
	}
}

func TestValidateAssetSizes(t *testing.T) {
	for _, tc := range []struct {
		name      string
		asset     releaseAsset
		checksums *releaseAsset
		wantErr   string
	}{
		{"assets at limits", releaseAsset{Name: "a", Size: maxArchiveSize}, &releaseAsset{Name: "SHA256SUMS", Size: maxChecksumFileSize}, ""},
		{"unknown sizes", releaseAsset{Name: "a", Size: -1}, &releaseAsset{Name: "SHA256SUMS", Size: 0}, ""},
		{"archive over limit", releaseAsset{Name: "a", Size: maxArchiveSize + 1}, nil, "release asset a is too large"},
		{"checksums over limit", releaseAsset{Name: "a"}, &releaseAsset{Name: "SHA256SUMS", Size: maxChecksumFileSize + 1}, "checksum asset SHA256SUMS is too large"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := validateAssetSizes(&tc.asset, tc.checksums)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("expected %q, got %v", tc.wantErr, err)
			}
		})
	}
}
