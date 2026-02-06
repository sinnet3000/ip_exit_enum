package discovery

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/netip"
	"net/http"
	"regexp"
	"strings"
	"time"
)

type ServiceConfig struct {
	Name          string
	URL           string
	Protocol      string
	Timeout       time.Duration
	ExtractMethod string // 'text', 'json', 'headers'
	ExtractField  string // for JSON
}

type TestResult struct {
	Service   string
	Protocol  string
	IPs       []string
	Timestamp time.Time
	Latency   time.Duration
	Success   bool
	Attempt   int
	Error     error
}

func newHTTPClient(family string, timeout time.Duration) *http.Client {
	dialTimeout := 5 * time.Second
	clientTimeout := 10 * time.Second
	if timeout > 0 {
		dialTimeout = timeout
		clientTimeout = timeout
	}

	transport := &http.Transport{
		DisableKeepAlives: true,
	}

	// Restrict dialer to specific address family if needed
	dialer := &net.Dialer{
		Timeout:   dialTimeout,
		KeepAlive: 30 * time.Second,
	}

	if family == "IPv4" {
		transport.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
			return dialer.DialContext(ctx, "tcp4", addr)
		}
	} else if family == "IPv6" {
		transport.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
			return dialer.DialContext(ctx, "tcp6", addr)
		}
	}

	return &http.Client{
		Transport: transport,
		Timeout:   clientTimeout,
	}
}

// Regexes for candidate extraction; validation uses netip.ParseAddr.
var ipv4Regex = regexp.MustCompile(`\b\d{1,3}(?:\.\d{1,3}){3}\b`)
var ipv6Regex = regexp.MustCompile(`\b[0-9a-fA-F:]*:[0-9a-fA-F:]*\b`)

func extractIPs(content string) []string {
	var valid []string
	seen := make(map[string]bool)
	addCandidate := func(candidate string) {
		if candidate == "" {
			return
		}
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

	reqCtx := ctx
	if service.Timeout > 0 {
		var cancel context.CancelFunc
		reqCtx, cancel = context.WithTimeout(ctx, service.Timeout)
		defer cancel()
	}

	// Determine family hint from service name or config
	// Ideally ServiceConfig would have a 'Family' field, but for now we infer or use default
	family := "dual"
	if strings.Contains(service.Name, "ipv4") || strings.Contains(service.Name, "v4") {
		family = "IPv4"
	}
	if strings.Contains(service.Name, "ipv6") || strings.Contains(service.Name, "v6") {
		family = "IPv6"
	}

	client := newHTTPClient(family, service.Timeout)

	req, err := http.NewRequestWithContext(reqCtx, "GET", service.URL, nil)
	if err != nil {
		return TestResult{
			Service:   service.Name,
			Protocol:  service.Protocol,
			Timestamp: start,
			Attempt:   attempt,
			Success:   false,
			Error:     err,
			Latency:   time.Since(start),
		}
	}

	resp, err := client.Do(req)
	if err != nil {
		return TestResult{
			Service:   service.Name,
			Protocol:  service.Protocol,
			Timestamp: start,
			Attempt:   attempt,
			Success:   false,
			Error:     err,
			Latency:   time.Since(start),
		}
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return TestResult{
			Service:   service.Name,
			Protocol:  service.Protocol,
			Timestamp: start,
			Attempt:   attempt,
			Success:   false,
			Error:     err,
			Latency:   time.Since(start),
		}
	}

	bodyStr := string(bodyBytes)
	var contentToScan string

	if service.ExtractMethod == "json" && service.ExtractField != "" {
		var payload map[string]interface{}
		if err := json.Unmarshal(bodyBytes, &payload); err == nil {
			if val, ok := payload[service.ExtractField]; ok {
				contentToScan = fmt.Sprintf("%v", val)
			}
		}
	} else {
		contentToScan = bodyStr
	}

	ips := extractIPs(contentToScan)

	return TestResult{
		Service:   service.Name,
		Protocol:  service.Protocol,
		Timestamp: start,
		Attempt:   attempt,
		Success:   len(ips) > 0,
		IPs:       ips,
		Latency:   time.Since(start),
	}
}
