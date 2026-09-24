package update

import (
	"archive/tar"
	"compress/gzip"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
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
		w.Write([]byte(strings.Repeat("f", 64) + "  other.tar.gz\n" + sum + "  wanted.tar.gz\n"))
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
