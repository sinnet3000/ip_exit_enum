package discovery

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"slices"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pion/stun/v3"
	"ip_exit_enum/internal/ui"
)

func TestExtractIPs(t *testing.T) {
	if got := extractIPs("8.8.8.8 2001:4860:4860::8888 10.0.0.1 127.0.0.1 invalid"); !slices.Equal(got, []string{"8.8.8.8", "2001:4860:4860::8888"}) {
		t.Fatalf("unexpected extracted IPs: %v", got)
	}
}

func TestHTTPServiceExecution(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/ok" {
			w.Write([]byte("203.0.113.5"))
		} else {
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte("error 203.0.113.99"))
		}
	}))
	defer s.Close()

	// Valid endpoint succeeds
	res := TestHTTPService(context.Background(), ServiceConfig{URL: s.URL + "/ok", Protocol: "HTTP"}, 1)
	if !res.Success || !slices.Equal(res.IPs, []string{"203.0.113.5"}) {
		t.Fatalf("expected 203.0.113.5, got: %v", res)
	}

	// 500 status fails even if body has an IP
	if res := TestHTTPService(context.Background(), ServiceConfig{URL: s.URL + "/err", Protocol: "HTTP"}, 1); res.Success {
		t.Fatal("expected failure on 500 status")
	}

	// Client routing
	if getHTTPClient("IPv4") != clientIPv4 || getHTTPClient("IPv6") != clientIPv6 || getHTTPClient("") != clientDual {
		t.Fatal("unexpected client mapping")
	}
}

func TestSTUNServiceExecution(t *testing.T) {
	conn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer conn.Close()

	var sendOther atomic.Bool
	go func() {
		buf := make([]byte, 1500)
		for {
			n, addr, err := conn.ReadFrom(buf)
			if err != nil {
				return
			}
			req := new(stun.Message)
			req.Raw = buf[:n]
			if err := req.Decode(); err != nil {
				continue
			}
			var resp *stun.Message
			if sendOther.Load() {
				resp = stun.MustBuild(stun.TransactionID, stun.BindingSuccess, &stun.OtherAddress{IP: net.ParseIP("198.51.100.99"), Port: 3478})
			} else {
				resp = stun.MustBuild(stun.TransactionID, stun.BindingSuccess, &stun.XORMappedAddress{IP: net.ParseIP("203.0.113.50"), Port: 54321})
			}
			resp.TransactionID = req.TransactionID
			resp.Encode()
			conn.WriteTo(resp.Raw, addr)
		}
	}()

	svc := ServiceConfig{URL: conn.LocalAddr().String(), Protocol: "UDP-STUN", Timeout: 200 * time.Millisecond}

	// Valid XOR-MAPPED-ADDRESS
	res := TestSTUNService(context.Background(), svc, 1)
	if !res.Success || !slices.Equal(res.IPs, []string{"203.0.113.50"}) {
		t.Fatalf("expected 203.0.113.50, got: %v", res)
	}

	// Reject OTHER-ADDRESS
	sendOther.Store(true)
	if res := TestSTUNService(context.Background(), svc, 1); res.Success {
		t.Fatal("expected failure on OTHER-ADDRESS")
	}
}

func TestEngine(t *testing.T) {
	e := NewEngine(nil, nil)

	// Confidence & consensus
	if label, _ := e.CalculateConfidence(); label != "Unknown" {
		t.Fatalf("expected Unknown, got %s", label)
	}
	e.testsCompleted, e.testsSuccessful = 10, 9
	e.results = []TestResult{{Protocol: "HTTP", Success: true}, {Protocol: "UDP-STUN", Success: true}}
	e.familyIPs["IPv4"]["203.0.113.1"] = 9
	if _, consensus := e.CalculateConfidence(); consensus != "Strong Consensus" {
		t.Fatalf("expected Strong Consensus, got %s", consensus)
	}
	e.familyIPs["IPv4"] = map[string]int{"203.0.113.1": 7, "203.0.113.2": 3}
	if _, consensus := e.CalculateConfidence(); consensus != "Weak Consensus (IPv4)" {
		t.Fatalf("expected Weak Consensus, got %s", consensus)
	}

	// Ranking
	ranked := ui.RankIPs(map[string]int{"203.0.113.1": 1, "203.0.113.2": 3})
	if len(ranked) != 2 || ranked[0].IP != "203.0.113.2" || ranked[0].Percentage != 75.0 {
		t.Fatalf("unexpected ranking: %v", ranked)
	}

	// Circuit breaker
	e.deadServices["dead"] = fmt.Errorf("timeout")
	called := false
	e.runBatch(context.Background(), []ServiceConfig{{Name: "dead"}}, func(context.Context, ServiceConfig, int) TestResult {
		called = true
		return TestResult{}
	}, 2, true)
	if called {
		t.Fatal("expected dead service to be skipped")
	}
}
