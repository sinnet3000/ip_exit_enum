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
	label, consensus := e.CalculateConfidence()
	if label != "Unknown" {
		t.Fatalf("expected Unknown label, got %s", label)
	}

	// Case 2: Low success rate (1/10)
	e.testsCompleted = 10
	e.testsSuccessful = 1
	label, _ = e.CalculateConfidence()
	if label != "Low" {
		t.Fatalf("expected Low for 10%% success rate, got %s", label)
	}

	// Case 3: High success rate with single IP
	e.testsCompleted = 10
	e.testsSuccessful = 9
	e.results = []TestResult{
		{Protocol: "HTTP", Success: true},
		{Protocol: "UDP-STUN", Success: true},
	}
	e.familyIPs["IPv4"]["203.0.113.1"] = 9
	label, consensus = e.CalculateConfidence()
	if label != "High" && label != "Very High" {
		t.Fatalf("expected High or Very High, got %s", label)
	}
	if consensus != "Strong Consensus" {
		t.Fatalf("expected Strong Consensus, got %s", consensus)
	}

	// Case 4: Weak Consensus (dominance in [0.6, 0.8))
	e.familyIPs["IPv4"] = map[string]int{"203.0.113.1": 7, "203.0.113.2": 3}
	_, consensus = e.CalculateConfidence()
	if consensus != "Weak Consensus (IPv4)" {
		t.Fatalf("expected Weak Consensus (IPv4), got %s", consensus)
	}

	// Case 5: Multiple Mappings (dominance < 0.6)
	e.familyIPs["IPv4"] = map[string]int{"203.0.113.1": 5, "203.0.113.2": 5}
	_, consensus = e.CalculateConfidence()
	if consensus != "Multiple Mappings (IPv4)" {
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

	// Attempt 2 should skip invoking the tester func
	e.runBatch(context.Background(), svcs, dummyTester, 2, true)

	if callCount != 0 {
		t.Fatalf("expected tester to be skipped on attempt 2, called %d times", callCount)
	}
	if len(e.results) != 1 || e.results[0].Success {
		t.Fatalf("expected skipped failed result recorded, got: %v", e.results)
	}
}
