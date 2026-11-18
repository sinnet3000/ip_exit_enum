package discovery

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"slices"
	"testing"
	"time"

	"github.com/pion/stun/v3"
)

func TestNormalizeEgressAddr(t *testing.T) {
	tests := []struct {
		name   string
		input  string
		want   string
		wantOK bool
	}{
		{name: "public IPv4", input: "8.8.8.8", want: "8.8.8.8", wantOK: true},
		{name: "documentation IPv4", input: "203.0.113.10", want: "203.0.113.10", wantOK: true},
		{name: "documentation IPv6", input: "2001:db8::1", want: "2001:db8::1", wantOK: true},
		{name: "public IPv6", input: "2001:4860:4860::8888", want: "2001:4860:4860::8888", wantOK: true},
		{name: "mapped public IPv4", input: "::ffff:8.8.8.8", want: "8.8.8.8", wantOK: true},
		{name: "below CGNAT range", input: "100.63.255.255", want: "100.63.255.255", wantOK: true},
		{name: "above CGNAT range", input: "100.128.0.0", want: "100.128.0.0", wantOK: true},
		{name: "private 10/8", input: "10.0.0.1", wantOK: false},
		{name: "private 172.16/12", input: "172.16.5.4", wantOK: false},
		{name: "private 192.168/16", input: "192.168.1.1", wantOK: false},
		{name: "mapped private IPv4", input: "::ffff:192.168.1.1", wantOK: false},
		{name: "CGNAT lower bound", input: "100.64.0.0", wantOK: false},
		{name: "CGNAT middle", input: "100.100.100.100", wantOK: false},
		{name: "CGNAT upper bound", input: "100.127.255.255", wantOK: false},
		{name: "mapped CGNAT", input: "::ffff:100.64.0.1", wantOK: false},
		{name: "loopback IPv4", input: "127.0.0.1", wantOK: false},
		{name: "loopback IPv6", input: "::1", wantOK: false},
		{name: "link-local IPv4", input: "169.254.1.1", wantOK: false},
		{name: "link-local IPv6", input: "fe80::1", wantOK: false},
		{name: "unique-local IPv6", input: "fd00::1", wantOK: false},
		{name: "multicast", input: "224.0.0.1", wantOK: false},
		{name: "unspecified", input: "0.0.0.0", wantOK: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := normalizeEgressAddr(netip.MustParseAddr(tt.input))
			if ok != tt.wantOK {
				t.Fatalf("normalizeEgressAddr(%q) ok = %v, want %v", tt.input, ok, tt.wantOK)
			}
			if ok && got.String() != tt.want {
				t.Fatalf("normalizeEgressAddr(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestNormalizeEgressAddrFromNetIP(t *testing.T) {
	// STUN decodes addresses into net.IP, so exercise the same conversion path.
	tests := []struct {
		name   string
		input  string
		want   string
		wantOK bool
	}{
		{name: "mapped public IPv4", input: "::ffff:8.8.8.8", want: "8.8.8.8", wantOK: true},
		{name: "documentation IPv4", input: "198.51.100.7", want: "198.51.100.7", wantOK: true},
		{name: "CGNAT", input: "100.64.0.1", wantOK: false},
		{name: "mapped CGNAT", input: "::ffff:100.64.0.1", wantOK: false},
		{name: "mapped private IPv4", input: "::ffff:10.0.0.1", wantOK: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			addr, ok := netip.AddrFromSlice(net.ParseIP(tt.input))
			if !ok {
				t.Fatalf("AddrFromSlice(%q) failed", tt.input)
			}
			got, ok := normalizeEgressAddr(addr)
			if ok != tt.wantOK {
				t.Fatalf("normalizeEgressAddr(%q) ok = %v, want %v", tt.input, ok, tt.wantOK)
			}
			if ok && got.String() != tt.want {
				t.Fatalf("normalizeEgressAddr(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestExtractIPsRejectsNonPublicAddresses(t *testing.T) {
	input := "CGNAT 100.64.0.1 mapped-CGNAT ::ffff:100.64.0.1 private 10.0.0.1 " +
		"mapped-public ::ffff:8.8.8.8 docs 203.0.113.10 198.51.100.7 2001:db8::1"
	want := []string{"8.8.8.8", "203.0.113.10", "198.51.100.7", "2001:db8::1"}
	if got := extractIPs(input); !slices.Equal(got, want) {
		t.Fatalf("extractIPs() = %v, want %v", got, want)
	}
}

func TestHTTPServiceUsesEgressValidator(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("100.64.0.1 10.0.0.1 ::ffff:8.8.8.8 203.0.113.10"))
	}))
	defer s.Close()

	res := TestHTTPService(context.Background(), ServiceConfig{URL: s.URL, Protocol: "HTTP"}, 1)
	want := []string{"8.8.8.8", "203.0.113.10"}
	if !res.Success || !slices.Equal(res.IPs, want) {
		t.Fatalf("expected %v, got: %+v", want, res)
	}
}

func TestSTUNServiceRejectsCGNAT(t *testing.T) {
	conn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer conn.Close()

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
			resp := stun.MustBuild(stun.TransactionID, stun.BindingSuccess, &stun.XORMappedAddress{IP: net.ParseIP("100.64.0.1"), Port: 54321})
			resp.TransactionID = req.TransactionID
			resp.Encode()
			conn.WriteTo(resp.Raw, addr)
		}
	}()

	svc := ServiceConfig{URL: conn.LocalAddr().String(), Protocol: "UDP-STUN", Timeout: 200 * time.Millisecond}
	if res := TestSTUNService(context.Background(), svc, 1); res.Success {
		t.Fatalf("expected CGNAT address to be rejected, got: %+v", res)
	}
}
