package discovery

import (
	"context"
	"fmt"
	"testing"

	"ip_exit_enum/internal/ui"
)

func TestCalculateConfidence(t *testing.T) {
	e := NewEngine(nil, nil)

	// Case 1: No completed tests
	if label, _ := e.CalculateConfidence(); label != "Unknown" {
		t.Fatalf("expected Unknown label, got %s", label)
	}

	// Case 2: Low success rate (1/10)
	e.testsCompleted, e.testsSuccessful = 10, 1
	if label, _ := e.CalculateConfidence(); label != "Low" {
		t.Fatalf("expected Low, got %s", label)
	}

	// Case 3: High success rate with single IP
	e.testsSuccessful = 9
	e.results = []TestResult{{Protocol: "HTTP", Success: true}, {Protocol: "UDP-STUN", Success: true}}
	e.familyIPs["IPv4"]["203.0.113.1"] = 9
	if label, consensus := e.CalculateConfidence(); (label != "High" && label != "Very High") || consensus != "Strong Consensus" {
		t.Fatalf("expected High/Very High and Strong Consensus, got %s / %s", label, consensus)
	}

	// Case 4: Weak Consensus (dominance in [0.6, 0.8))
	e.familyIPs["IPv4"] = map[string]int{"203.0.113.1": 7, "203.0.113.2": 3}
	if _, consensus := e.CalculateConfidence(); consensus != "Weak Consensus (IPv4)" {
		t.Fatalf("expected Weak Consensus (IPv4), got %s", consensus)
	}

	// Case 5: Multiple Mappings (dominance < 0.6)
	e.familyIPs["IPv4"] = map[string]int{"203.0.113.1": 5, "203.0.113.2": 5}
	if _, consensus := e.CalculateConfidence(); consensus != "Multiple Mappings (IPv4)" {
		t.Fatalf("expected Multiple Mappings (IPv4), got %s", consensus)
	}
}

func TestRankIPs(t *testing.T) {
	counts := map[string]int{"203.0.113.1": 1, "203.0.113.2": 3}
	ranked := ui.RankIPs(counts)
	if len(ranked) != 2 || ranked[0].IP != "203.0.113.2" || ranked[0].Hits != 3 || ranked[0].Percentage != 75.0 {
		t.Fatalf("unexpected ranking output: %v", ranked)
	}
}

func TestCircuitBreakerSkipsDeadService(t *testing.T) {
	e := NewEngine(nil, nil)
	e.deadServices["dead-service"] = fmt.Errorf("i/o timeout")

	callCount := 0
	dummyTester := func(ctx context.Context, cfg ServiceConfig, attempt int) TestResult {
		callCount++
		return TestResult{Service: cfg.Name, Success: true}
	}

	svcs := []ServiceConfig{{Name: "dead-service", Protocol: "HTTP"}}
	e.runBatch(context.Background(), svcs, dummyTester, 2, true)

	if callCount != 0 || len(e.results) != 1 || e.results[0].Success {
		t.Fatalf("expected tester to be skipped on attempt 2, called %d times (results=%v)", callCount, e.results)
	}
}
