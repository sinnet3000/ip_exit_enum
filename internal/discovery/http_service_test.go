package discovery

import (
	"context"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"
	"time"
)

func TestExtractIPs(t *testing.T) {
	tests := []struct {
		input   string
		wantIPs []string
	}{
		{"public 8.8.8.8 and 2001:4860:4860::8888", []string{"8.8.8.8", "2001:4860:4860::8888"}},
		{"10.0.0.1 127.0.0.1 169.254.0.1 224.0.0.1 ::1 fe80::1", nil},
		{"time 2026-09-21T22:58:35 content-type:text/html ip 203.0.113.10", []string{"203.0.113.10"}},
	}
	for _, tt := range tests {
		if got := extractIPs(tt.input); !slices.Equal(got, tt.wantIPs) {
			t.Errorf("extractIPs(%q) = %v, want %v", tt.input, got, tt.wantIPs)
		}
	}
}

func TestHTTPServiceExecution(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/timeout":
			time.Sleep(100 * time.Millisecond)
		case "/error":
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte("server error mentioning 203.0.113.99"))
		case "/ok":
			_, _ = w.Write([]byte("203.0.113.5"))
		}
	}))
	defer server.Close()

	cases := []struct {
		path    string
		timeout time.Duration
		wantOK  bool
		wantIP  string
	}{
		{"/ok", time.Second, true, "203.0.113.5"},
		{"/error", time.Second, false, ""},
		{"/timeout", 20 * time.Millisecond, false, ""},
		{"/ok", 0, true, "203.0.113.5"},
	}
	for _, tc := range cases {
		res := TestHTTPService(context.Background(), ServiceConfig{
			Name: "test", URL: server.URL + tc.path, Protocol: "HTTP", Timeout: tc.timeout,
		}, 1)
		if res.Success != tc.wantOK || (tc.wantIP != "" && !slices.Equal(res.IPs, []string{tc.wantIP})) {
			t.Fatalf("path %s (timeout %v): got success=%v, ips=%v; want success=%v, ip=%s",
				tc.path, tc.timeout, res.Success, res.IPs, tc.wantOK, tc.wantIP)
		}
	}
}

func TestGetHTTPClient(t *testing.T) {
	if getHTTPClient("IPv4") != clientIPv4 || getHTTPClient("IPv6") != clientIPv6 || getHTTPClient("") != clientDual {
		t.Fatal("unexpected client mapping")
	}
}
