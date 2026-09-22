package discovery

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"time"

	"github.com/pion/stun/v3"
)

func TestSTUNService(ctx context.Context, service ServiceConfig, attempt int) TestResult {
	start := time.Now()

	fail := func(err error) TestResult {
		lat := time.Since(start)
		return TestResult{
			Service:   service.Name,
			Protocol:  service.Protocol,
			Timestamp: start,
			Attempt:   attempt,
			Success:   false,
			Error:     err,
			Latency:   lat,
			LatencyMs: float64(lat.Milliseconds()),
		}
	}

	timeout := service.Timeout
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	network := "udp"
	if service.Protocol == "UDP-STUN6" {
		network = "udp6"
	} else if service.Protocol == "UDP-STUN" {
		network = "udp4"
	}

	udpDialer := net.Dialer{Timeout: timeout}
	conn, err := udpDialer.DialContext(ctx, network, service.URL)
	if err != nil {
		return fail(fmt.Errorf("stun dial failed: %w", err))
	}
	defer conn.Close()

	if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		return fail(fmt.Errorf("stun set deadline failed: %w", err))
	}

	c, err := stun.NewClient(conn)
	if err != nil {
		return fail(fmt.Errorf("stun client init failed: %w", err))
	}
	defer c.Close()

	message := stun.MustBuild(stun.TransactionID, stun.BindingRequest)

	var xorAddr stun.XORMappedAddress
	var mappedAddr stun.MappedAddress
	var eventErr error

	err = c.Do(message, func(res stun.Event) {
		if res.Error != nil {
			eventErr = res.Error
			return
		}

		if getErr := xorAddr.GetFrom(res.Message); getErr == nil {
			return
		}
		if getErr := mappedAddr.GetFrom(res.Message); getErr == nil {
			xorAddr.IP = mappedAddr.IP
			xorAddr.Port = mappedAddr.Port
			return
		}
	})

	if err != nil {
		return fail(fmt.Errorf("stun request failed: %w", err))
	}
	if eventErr != nil {
		return fail(fmt.Errorf("stun request failed: %w", eventErr))
	}
	if xorAddr.IP == nil {
		return fail(fmt.Errorf("no IP address attribute in STUN response"))
	}

	addr, ok := netip.AddrFromSlice(xorAddr.IP)
	if !ok || !addr.IsGlobalUnicast() {
		return fail(fmt.Errorf("stun returned non-public IP: %s", xorAddr.IP.String()))
	}

	lat := time.Since(start)
	return TestResult{
		Service:   service.Name,
		Protocol:  service.Protocol,
		Timestamp: start,
		Attempt:   attempt,
		Success:   true,
		IPs:       []string{xorAddr.IP.String()},
		Latency:   lat,
		LatencyMs: float64(lat.Milliseconds()),
	}
}
