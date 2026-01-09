package discovery

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"
)

// ServiceConfig defines a testable service endpoint
type ServiceConfig struct {
	Name          string
	URL           string
	Protocol      string
	Timeout       time.Duration
	ExtractMethod string // 'text', 'json', 'headers'
	ExtractField  string // for JSON
}

// TestResult holds the outcome of a single service test
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

// HTTPClientFactory creates clients with specific transport configurations
// This is crucial for forcing IPv4 vs IPv6 connections
type HTTPClientFactory interface {
	CreateClient(family string) *http.Client
}

type defaultHTTPClientFactory struct{}

func (f *defaultHTTPClientFactory) CreateClient(family string) *http.Client {
	transport := &http.Transport{
		DisableKeepAlives: true,
	}

	// Restrict dialer to specific address family if needed
	dialer := &net.Dialer{
		Timeout:   5 * time.Second,
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
		Timeout:   10 * time.Second,
	}
}

// Global regex for IP extraction
var ipRegex = regexp.MustCompile(`\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b|([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)`)

// extractIPs finds all public IPs in a string
func extractIPs(content string) []string {
	// Simple wrapper for now, can be robustified later
	// Note: The python version had specific logic to filter private IPs
	// We should replicate basic filtering here.

	candidates := ipRegex.FindAllString(content, -1)
	var valid []string
	seen := make(map[string]bool)

	for _, c := range candidates {
		ip := net.ParseIP(c)
		if ip == nil || ip.IsLoopback() || ip.IsPrivate() || ip.IsUnspecified() {
			continue
		}
		// Additional check for link-local
		if ip.IsLinkLocalMulticast() || ip.IsLinkLocalUnicast() {
			continue
		}

		cleanIP := ip.String()
		if !seen[cleanIP] {
			valid = append(valid, cleanIP)
			seen[cleanIP] = true
		}
	}
	return valid
}

// HTTPTester handles HTTP testing with cached clients
type HTTPTester struct {
	clients map[string]*http.Client
	mu      sync.Mutex
}

func NewHTTPTester() *HTTPTester {
	return &HTTPTester{
		clients: make(map[string]*http.Client),
	}
}

func (t *HTTPTester) getClient(family string) *http.Client {
	t.mu.Lock()
	defer t.mu.Unlock()

	if client, ok := t.clients[family]; ok {
		return client
	}

	factory := &defaultHTTPClientFactory{}
	client := factory.CreateClient(family)
	t.clients[family] = client
	return client
}

func (t *HTTPTester) Test(ctx context.Context, service ServiceConfig, attempt int) TestResult {
	start := time.Now()

	// Determine family hint from service name or config
	// Ideally ServiceConfig would have a 'Family' field, but for now we infer or use default
	family := "dual"
	if strings.Contains(service.Name, "ipv4") || strings.Contains(service.Name, "v4") {
		family = "IPv4"
	}
	if strings.Contains(service.Name, "ipv6") || strings.Contains(service.Name, "v6") {
		family = "IPv6"
	}

	client := t.getClient(family)

	req, err := http.NewRequestWithContext(ctx, "GET", service.URL, nil)
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
