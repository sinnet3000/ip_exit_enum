package discovery

import "time"

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
