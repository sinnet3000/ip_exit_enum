package discovery

import (
	"time"

	"ip_exit_enum/internal/ui"
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

type RunOptions struct {
	Verbose  bool
	JSON     bool
	Samples  int
	Interval time.Duration
	Timeout  time.Duration
}

type JSONIPEntry struct {
	IP         string  `json:"ip"`
	Hits       int     `json:"hits"`
	Percentage float64 `json:"percentage"`
}

type JSONResultItem struct {
	Service   string   `json:"service"`
	Protocol  string   `json:"protocol"`
	Attempt   int      `json:"attempt"`
	Success   bool     `json:"success"`
	IPs       []string `json:"ips,omitempty"`
	LatencyMs float64  `json:"latency_ms"`
	Error     string   `json:"error,omitempty"`
}

type JSONOutput struct {
	Timestamp       time.Time                  `json:"timestamp"`
	DurationMs      float64                    `json:"duration_ms"`
	Confidence      string                     `json:"confidence"`
	Consensus       string                     `json:"consensus"`
	CompletedTests  int                        `json:"completed_tests"`
	SuccessfulTests int                        `json:"successful_tests"`
	ProtocolStats   map[string]ui.ProtocolStat `json:"protocol_stats"`
	DiscoveredIPs   map[string][]JSONIPEntry   `json:"discovered_ips"`
	DetailedResults []JSONResultItem           `json:"detailed_results,omitempty"`
}
