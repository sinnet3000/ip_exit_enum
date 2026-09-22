package discovery

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestExtractIPs(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantIPs []string
	}{
		{
			name:    "valid public v4 and v6",
			input:   "public 8.8.8.8 and 2001:4860:4860::8888",
			wantIPs: []string{"8.8.8.8", "2001:4860:4860::8888"},
		},
		{
			name:    "rejects private, loopback, and multicast",
			input:   "10.0.0.1 127.0.0.1 169.254.0.1 224.0.0.1 ::1 fe80::1",
			wantIPs: nil,
		},
		{
			name:    "ignores timestamps, css, and headers",
			input:   "time 2026-09-21T22:58:35 content-type:text/html ip 203.0.113.10",
			wantIPs: []string{"203.0.113.10"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractIPs(tt.input)
			if len(got) != len(tt.wantIPs) {
				t.Fatalf("extractIPs() = %v, want %v", got, tt.wantIPs)
			}
			for i, ip := range tt.wantIPs {
				if got[i] != ip {
					t.Errorf("extractIPs()[%d] = %s, want %s", i, got[i], ip)
				}
			}
		})
	}
}

func TestHTTPServiceExecution(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/timeout":
			time.Sleep(100 * time.Millisecond)
			w.WriteHeader(http.StatusOK)
		case "/error":
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte("server error mentioning 203.0.113.99"))
		case "/ok":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("203.0.113.5"))
		}
	}))
	defer server.Close()

	// Test 1: Successful probe
	res := TestHTTPService(context.Background(), ServiceConfig{
		Name: "ok-test", URL: server.URL + "/ok", Protocol: "HTTP", Timeout: time.Second,
	}, 1)
	if !res.Success || len(res.IPs) != 1 || res.IPs[0] != "203.0.113.5" {
		t.Fatalf("expected success with 203.0.113.5, got %v", res)
	}

	// Test 2: Status error rejected even if body has an IP
	res = TestHTTPService(context.Background(), ServiceConfig{
		Name: "err-test", URL: server.URL + "/error", Protocol: "HTTP", Timeout: time.Second,
	}, 1)
	if res.Success {
		t.Fatalf("expected failure on 500 status, got success: %v", res.IPs)
	}

	// Test 3: Respects timeout
	res = TestHTTPService(context.Background(), ServiceConfig{
		Name: "timeout-test", URL: server.URL + "/timeout", Protocol: "HTTP", Timeout: 20 * time.Millisecond,
	}, 1)
	if res.Success {
		t.Fatalf("expected timeout failure, got %v", res)
	}
}
