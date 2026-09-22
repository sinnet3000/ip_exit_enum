package discovery

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/pion/stun/v3"
)

func TestSTUNServiceExecution(t *testing.T) {
	conn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen udp4: %v", err)
	}
	defer conn.Close()

	sendOtherAddr := false
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
			if sendOtherAddr {
				resp = stun.MustBuild(stun.TransactionID, stun.BindingSuccess, &stun.OtherAddress{
					IP: net.ParseIP("198.51.100.99"), Port: 3478,
				})
			} else {
				resp = stun.MustBuild(stun.TransactionID, stun.BindingSuccess, &stun.XORMappedAddress{
					IP: net.ParseIP("203.0.113.50"), Port: 54321,
				})
			}
			resp.TransactionID = req.TransactionID
			resp.Encode()
			_, _ = conn.WriteTo(resp.Raw, addr)
		}
	}()

	svc := ServiceConfig{
		Name:     "stun-test",
		URL:      conn.LocalAddr().String(),
		Protocol: "UDP-STUN",
		Timeout:  200 * time.Millisecond,
	}

	// 1. Success with XOR-MAPPED-ADDRESS
	res := TestSTUNService(context.Background(), svc, 1)
	if !res.Success || len(res.IPs) != 1 || res.IPs[0] != "203.0.113.50" {
		t.Fatalf("expected success with 203.0.113.50, got: %v (err: %v)", res.IPs, res.Error)
	}

	// 2. Reject when only OTHER-ADDRESS is present
	sendOtherAddr = true
	res = TestSTUNService(context.Background(), svc, 1)
	if res.Success {
		t.Fatalf("expected failure when only OTHER-ADDRESS is present, got success: %v", res.IPs)
	}
}
