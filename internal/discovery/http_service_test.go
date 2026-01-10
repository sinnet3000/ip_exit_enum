package discovery

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestHTTPServiceRespectsTimeout(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(200 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("203.0.113.7"))
	}))
	defer server.Close()

	service := ServiceConfig{
		Name:     "timeout-test",
		URL:      server.URL,
		Protocol: "HTTP",
		Timeout:  50 * time.Millisecond,
	}

	start := time.Now()
	res := TestHTTPService(context.Background(), service, 1)
	elapsed := time.Since(start)

	if res.Success {
		t.Fatalf("expected timeout failure, got success with IPs=%v", res.IPs)
	}
	if res.Error == nil {
		t.Fatalf("expected timeout error, got nil")
	}
	if elapsed > 300*time.Millisecond {
		t.Fatalf("expected timeout within 300ms, took %s", elapsed)
	}
}
