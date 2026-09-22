package discovery

import (
	"context"
	"fmt"
	"testing"
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
