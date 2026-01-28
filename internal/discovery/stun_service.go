package discovery

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"time"

	"github.com/pion/stun/v2"
)

func TestSTUNService(ctx context.Context, service ServiceConfig, attempt int) TestResult {
	start := time.Now()

	if service.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, service.Timeout)
		defer cancel()
	}

	// Determine network based on protocol/name
	network := "udp"
	if service.Protocol == "UDP-STUN6" {
		network = "udp6"
	} else if service.Protocol == "UDP-STUN" {
		// Strictly force v4 if requested, though "udp" usually tries v4 first or both
		// To match Python's strict separation:
		network = "udp4"
	}

	dialer := net.Dialer{}
	if service.Timeout > 0 {
		dialer.Timeout = service.Timeout
	}

	conn, err := dialer.DialContext(ctx, network, service.URL)
	if err != nil {
		return TestResult{
			Service:   service.Name,
			Protocol:  service.Protocol,
			Timestamp: start,
			Attempt:   attempt,
			Success:   false,
			Error:     fmt.Errorf("stun dial failed: %w", err),
			Latency:   time.Since(start),
		}
	}
	if service.Timeout > 0 {
		if err := conn.SetDeadline(time.Now().Add(service.Timeout)); err != nil {
			conn.Close()
			return TestResult{
				Service:   service.Name,
				Protocol:  service.Protocol,
				Timestamp: start,
				Attempt:   attempt,
				Success:   false,
				Error:     fmt.Errorf("stun set deadline failed: %w", err),
				Latency:   time.Since(start),
			}
		}
	}

	// Create STUN client (this connects to the server)
	c, err := stun.NewClient(conn)
	if err != nil {
		conn.Close()
		return TestResult{
			Service:   service.Name,
			Protocol:  service.Protocol,
			Timestamp: start,
			Attempt:   attempt,
			Success:   false,
			Error:     fmt.Errorf("stun client init failed: %w", err),
			Latency:   time.Since(start),
		}
	}
	defer c.Close()

	message := stun.MustBuild(stun.TransactionID, stun.BindingRequest)

	var xorAddr stun.XORMappedAddress
	var otherAddr stun.OtherAddress
	var mappedAddr stun.MappedAddress

	err = c.Do(message, func(res stun.Event) {
		if res.Error != nil {
			// Don't return here, just let the outer error handler catch it if needed,
			// or we capture it to variable.
			// In pion/stun, Do blocks until success or timeout/error
			return
		}

		// Try to find ANY address attribute
		if getErr := xorAddr.GetFrom(res.Message); getErr == nil {
			return
		}
		if getErr := otherAddr.GetFrom(res.Message); getErr == nil {
			// Convert OtherAddress to XORMappedAddress logic for IP extraction
			xorAddr.IP = otherAddr.IP
			xorAddr.Port = otherAddr.Port
			return
		}
		if getErr := mappedAddr.GetFrom(res.Message); getErr == nil {
			xorAddr.IP = mappedAddr.IP
			xorAddr.Port = mappedAddr.Port
			return
		}
	})

	latency := time.Since(start)

	if err != nil {
		return TestResult{
			Service:   service.Name,
			Protocol:  service.Protocol,
			Timestamp: start,
			Attempt:   attempt,
			Success:   false,
			Error:     fmt.Errorf("stun request failed: %w", err),
			Latency:   latency,
		}
	}

	if xorAddr.IP == nil {
		return TestResult{
			Service:   service.Name,
			Protocol:  service.Protocol,
			Timestamp: start,
			Attempt:   attempt,
			Success:   false,
			Error:     fmt.Errorf("no IP address attribute in STUN response"),
			Latency:   latency,
		}
	}

	addr, ok := netip.AddrFromSlice(xorAddr.IP)
	if !ok || !addr.IsGlobalUnicast() {
		return TestResult{
			Service:   service.Name,
			Protocol:  service.Protocol,
			Timestamp: start,
			Attempt:   attempt,
			Success:   false,
			Error:     fmt.Errorf("stun returned non-public IP: %s", xorAddr.IP.String()),
			Latency:   latency,
		}
	}

	return TestResult{
		Service:   service.Name,
		Protocol:  service.Protocol,
		Timestamp: start,
		Attempt:   attempt,
		Success:   true,
		IPs:       []string{xorAddr.IP.String()},
		Latency:   latency,
	}
}
