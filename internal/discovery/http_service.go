package discovery

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"regexp"
	"time"
)

var (
	httpDialer = &net.Dialer{KeepAlive: 30 * time.Second}

	// Echo services are untrusted; never follow their redirects.
	noRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }

	clientDual = &http.Client{
		CheckRedirect: noRedirect,
		Transport:     &http.Transport{DisableKeepAlives: true},
	}
	clientIPv4 = &http.Client{
		CheckRedirect: noRedirect,
		Transport: &http.Transport{
			DisableKeepAlives: true,
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return httpDialer.DialContext(ctx, "tcp4", addr)
			},
		},
	}
	clientIPv6 = &http.Client{
		CheckRedirect: noRedirect,
		Transport: &http.Transport{
			DisableKeepAlives: true,
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return httpDialer.DialContext(ctx, "tcp6", addr)
			},
		},
	}

	ipv4Regex = regexp.MustCompile(`\b\d{1,3}(?:\.\d{1,3}){3}\b`)
	ipv6Regex = regexp.MustCompile(`(?i)\b(?:[0-9a-f]{1,4}:)*[0-9a-f]{1,4}::(?:[0-9a-f]{1,4}(?::[0-9a-f]{1,4})*)?\b|\b::(?:[0-9a-f]{1,4}(?::[0-9a-f]{1,4})*)?\b|\b(?:[0-9a-f]{1,4}:){7}[0-9a-f]{1,4}\b`)
)

func getHTTPClient(family string) *http.Client {
	switch family {
	case "IPv4":
		return clientIPv4
	case "IPv6":
		return clientIPv6
	default:
		return clientDual
	}
}

func extractIPs(content string) []string {
	var valid []string
	seen := make(map[string]bool)
	addCandidate := func(candidate string) {
		addr, err := netip.ParseAddr(candidate)
		if err != nil || !addr.IsGlobalUnicast() || addr.IsPrivate() {
			return
		}
		cleanIP := addr.String()
		if !seen[cleanIP] {
			valid = append(valid, cleanIP)
			seen[cleanIP] = true
		}
	}

	for _, c := range ipv4Regex.FindAllString(content, -1) {
		addCandidate(c)
	}
	for _, c := range ipv6Regex.FindAllString(content, -1) {
		addCandidate(c)
	}
	return valid
}

func TestHTTPService(ctx context.Context, service ServiceConfig, attempt int) TestResult {
	start := time.Now()

	fail := func(err error) TestResult {
		return TestResult{
			Service:   service.Name,
			Protocol:  service.Protocol,
			Timestamp: start,
			Attempt:   attempt,
			Success:   false,
			Error:     err,
			LatencyMs: float64(time.Since(start).Microseconds()) / 1000.0,
		}
	}

	timeout := service.Timeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	reqCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	client := getHTTPClient(service.Family)

	req, err := http.NewRequestWithContext(reqCtx, "GET", service.URL, nil)
	if err != nil {
		return fail(err)
	}

	resp, err := client.Do(req)
	if err != nil {
		return fail(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fail(fmt.Errorf("unexpected HTTP status: %s", resp.Status))
	}

	const maxBodySize = 64 * 1024
	bodyBytes, err := io.ReadAll(io.LimitReader(resp.Body, maxBodySize))
	if err != nil {
		return fail(err)
	}

	contentToScan := string(bodyBytes)
	if service.ExtractMethod == "json" && service.ExtractField != "" {
		var payload map[string]interface{}
		if err := json.Unmarshal(bodyBytes, &payload); err == nil {
			if val, ok := payload[service.ExtractField]; ok {
				contentToScan = fmt.Sprintf("%v", val)
			}
		}
	}

	ips := extractIPs(contentToScan)
	return TestResult{
		Service:   service.Name,
		Protocol:  service.Protocol,
		Timestamp: start,
		Attempt:   attempt,
		Success:   len(ips) > 0,
		IPs:       ips,
		LatencyMs: float64(time.Since(start).Microseconds()) / 1000.0,
	}
}
