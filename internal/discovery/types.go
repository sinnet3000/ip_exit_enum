package discovery

import (
	"time"

	"ip_exit_enum/internal/ui"
)

type ServiceConfig struct {
	Name          string
	URL           string
	Protocol      string
	Family        string // "IPv4", "IPv6", or "" (dual)
	Timeout       time.Duration
	ExtractMethod string // "json" extracts ExtractField; anything else scans the raw body
	ExtractField  string // for JSON
}

type TestResult struct {
	Service   string    `json:"service"`
	Protocol  string    `json:"protocol"`
	Attempt   int       `json:"attempt"`
	Success   bool      `json:"success"`
	IPs       []string  `json:"ips,omitempty"`
	LatencyMs float64   `json:"latency_ms"`
	Timestamp time.Time `json:"timestamp"`
	Error     error     `json:"-"`
	ErrorMsg  string    `json:"error,omitempty"`
}

type RunOptions struct {
	Verbose  bool
	JSON     bool
	Samples  int
	Interval time.Duration
	Timeout  time.Duration
}

type JSONOutput struct {
	Timestamp       time.Time                  `json:"timestamp"`
	DurationMs      float64                    `json:"duration_ms"`
	Confidence      string                     `json:"confidence"`
	Consensus       string                     `json:"consensus"`
	CompletedTests  int                        `json:"completed_tests"`
	SuccessfulTests int                        `json:"successful_tests"`
	ProtocolStats   map[string]ui.ProtocolStat `json:"protocol_stats"`
	DiscoveredIPs   map[string][]ui.IPEntry    `json:"discovered_ips"`
	DetailedResults []TestResult               `json:"detailed_results,omitempty"`
}
