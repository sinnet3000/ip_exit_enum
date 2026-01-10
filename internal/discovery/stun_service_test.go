package discovery

import (
	"context"
	"net"
	"testing"
	"time"
)

func TestSTUNServiceRespectsTimeout(t *testing.T) {
	conn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen udp4: %v", err)
	}
	defer conn.Close()

	// Drain packets without responding.
	go func() {
		buf := make([]byte, 1500)
		for {
			if _, _, err := conn.ReadFrom(buf); err != nil {
				return
			}
		}
	}()

	service := ServiceConfig{
		Name:     "stun-timeout-test",
		URL:      conn.LocalAddr().String(),
		Protocol: "UDP-STUN",
		Timeout:  50 * time.Millisecond,
	}

	start := time.Now()
	res := TestSTUNService(context.Background(), service, 1)
	elapsed := time.Since(start)

	if res.Success {
		t.Fatalf("expected timeout failure, got success with IPs=%v", res.IPs)
	}
	if res.Error == nil {
		t.Fatalf("expected timeout error, got nil")
	}
	if elapsed > 500*time.Millisecond {
		t.Fatalf("expected timeout within 500ms, took %s", elapsed)
	}
}
