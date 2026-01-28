package discovery

import (
	"context"
	"fmt"
	"math/rand"
	"net"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"ip_exit_enum/internal/ui"
)

type Engine struct {
	httpServices []ServiceConfig
	udpServices  []ServiceConfig
	results      []TestResult
	ui           *ui.Display

	ipsFound       map[string]int
	protocolIPs    map[string]map[string]int
	familyIPs      map[string]map[string]int
	serviceStatus  map[string]string
	startTime      time.Time
	testsCompleted int
	testsTotal     int
	currentPhase   string

	mu sync.Mutex // Protects state
}

func NewEngine(httpServices, udpServices []ServiceConfig) *Engine {
	e := &Engine{
		httpServices:  httpServices,
		udpServices:   udpServices,
		ui:            ui.NewDisplay(),
		ipsFound:      make(map[string]int),
		protocolIPs:   make(map[string]map[string]int),
		familyIPs:     make(map[string]map[string]int),
		serviceStatus: make(map[string]string),
		startTime:     time.Now(),
	}

	e.familyIPs["IPv4"] = make(map[string]int)
	e.familyIPs["IPv6"] = make(map[string]int)

	return e
}

func (e *Engine) ensureMaps() {
	if e.familyIPs == nil {
		e.familyIPs = make(map[string]map[string]int)
	}
	if e.familyIPs["IPv4"] == nil {
		e.familyIPs["IPv4"] = make(map[string]int)
	}
	if e.familyIPs["IPv6"] == nil {
		e.familyIPs["IPv6"] = make(map[string]int)
	}
	if e.protocolIPs == nil {
		e.protocolIPs = make(map[string]map[string]int)
	}
}

func (e *Engine) Run(ctx context.Context, verbose bool) {
	e.ensureMaps()
	e.startTime = time.Now()

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigChan
		fmt.Println("\nReceived interrupt, stopping...")
		cancel()
	}()

	httpSamples := 3
	udpSamples := 2

	e.testsTotal = (len(e.httpServices) * httpSamples) + (len(e.udpServices) * udpSamples)

	for attempt := 1; attempt <= httpSamples; attempt++ {
		e.currentPhase = fmt.Sprintf("HTTP(S) Discovery – sample %d/%d", attempt, httpSamples)

		services := make([]ServiceConfig, len(e.httpServices))
		copy(services, e.httpServices)
		rand.Shuffle(len(services), func(i, j int) { services[i], services[j] = services[j], services[i] })

		e.runBatch(ctx, services, TestHTTPService, attempt)

		if ctx.Err() != nil {
			break
		}

		if attempt < httpSamples {
			time.Sleep(300 * time.Millisecond)
		}
	}

	for attempt := 1; attempt <= udpSamples; attempt++ {
		e.currentPhase = fmt.Sprintf("UDP-STUN Discovery – sample %d/%d", attempt, udpSamples)

		services := make([]ServiceConfig, len(e.udpServices))
		copy(services, e.udpServices)
		rand.Shuffle(len(services), func(i, j int) { services[i], services[j] = services[j], services[i] })

		e.runBatch(ctx, services, TestSTUNService, attempt)

		if ctx.Err() != nil {
			break
		}

		if attempt < udpSamples {
			time.Sleep(300 * time.Millisecond)
		}
	}

	e.ui.RenderLiveResults(e.getUpdateSnapshot()) // Final update

	if verbose {
		var verboseItems []ui.VerboseResultItem
		for _, r := range e.results {
			errMsg := ""
			if r.Error != nil {
				errMsg = r.Error.Error()
			}

			verboseItems = append(verboseItems, ui.VerboseResultItem{
				Service:   r.Service,
				Protocol:  r.Protocol,
				Attempt:   r.Attempt,
				IPs:       r.IPs,
				LatencyMs: float64(r.Latency.Milliseconds()),
				Success:   r.Success,
				Error:     errMsg,
			})
		}
		e.ui.PrintVerbose(verboseItems)
	}

	fmt.Println("\nDone.")
}

type TesterFunc func(context.Context, ServiceConfig, int) TestResult

func (e *Engine) runBatch(ctx context.Context, services []ServiceConfig, tester TesterFunc, attempt int) {
	// Simple sequential execution for visual clarity, mirroring Python version.
	// Can be parallelized with workers if needed, but sequential output is nicer for this tool.
	// Note: Use a worker pool if user wants raw speed, but "spirit" implies UX focus.
	// Let's do semi-parallel: 4 concurrent workers to speed up but keep UI readable.

	var wg sync.WaitGroup
	semaphore := make(chan struct{}, 4) // Limit concurrency

	for _, svc := range services {
		if ctx.Err() != nil {
			break
		}

		wg.Add(1)
		semaphore <- struct{}{}

		go func(s ServiceConfig) {
			defer wg.Done()
			defer func() { <-semaphore }()

			res := tester(ctx, s, attempt)
			e.processResult(res)
		}(svc)
	}

	wg.Wait()
}

func (e *Engine) processResult(res TestResult) {
	e.mu.Lock()

	e.testsCompleted++
	e.results = append(e.results, res)

	if res.Success && len(res.IPs) > 0 {
		e.serviceStatus[res.Service] = "success"
		for _, ip := range res.IPs {
			e.ipsFound[ip]++

			if e.protocolIPs[res.Protocol] == nil {
				e.protocolIPs[res.Protocol] = make(map[string]int)
			}
			e.protocolIPs[res.Protocol][ip]++

			family := "IPv4"
			parsedIP := net.ParseIP(ip)
			if parsedIP != nil && parsedIP.To4() == nil {
				family = "IPv6"
			}
			e.familyIPs[family][ip]++
		}
	} else {
		e.serviceStatus[res.Service] = "failed"
	}

	update := e.getUpdateSnapshotLocked()
	e.mu.Unlock()

	e.ui.RenderLiveResults(update)
}

func (e *Engine) getUpdateSnapshot() ui.ResultUpdate {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.getUpdateSnapshotLocked()
}

func (e *Engine) getUpdateSnapshotLocked() ui.ResultUpdate {
	confidence, consensus := e.CalculateConfidence()

	ipsFound := make(map[string]int, len(e.ipsFound))
	for ip, count := range e.ipsFound {
		ipsFound[ip] = count
	}

	familyIPs := make(map[string]map[string]int, len(e.familyIPs))
	for fam, counts := range e.familyIPs {
		copyCounts := make(map[string]int, len(counts))
		for ip, count := range counts {
			copyCounts[ip] = count
		}
		familyIPs[fam] = copyCounts
	}

	loadBalancing := make(map[string]bool)
	for fam, counts := range familyIPs {
		if len(counts) > 1 {
			loadBalancing[fam] = true
		}
	}

	return ui.ResultUpdate{
		StartTime:          e.startTime,
		CurrentPhase:       e.currentPhase,
		CompletedTests:     e.testsCompleted,
		TotalTests:         e.testsTotal,
		IPs:                ipsFound,
		IPFamilies:         familyIPs,
		ConfidenceLevel:    confidence,
		Consensus:          consensus,
		LoadBalancingFound: loadBalancing,
	}
}

func (e *Engine) CalculateConfidence() (string, string) {
	if e.testsCompleted == 0 {
		return "Unknown", "Waiting..."
	}

	total := float64(e.testsCompleted)
	successCount := 0
	for _, r := range e.results {
		if r.Success {
			successCount++
		}
	}
	successRate := float64(successCount) / total

	// 1. Success Rate Component (0-40 points)
	score := 0.0
	if successRate >= 0.95 {
		score += 40
	} else if successRate >= 0.85 {
		score += 32
	} else if successRate >= 0.70 {
		score += 24
	} else if successRate >= 0.50 {
		score += 16
	} else {
		score += 8
	}

	// 2. Sample Size Component (0-25 points)
	if successCount >= 15 {
		score += 25
	} else if successCount >= 10 {
		score += 20
	} else if successCount >= 7 {
		score += 15
	} else if successCount >= 5 {
		score += 10
	} else {
		score += 5
	}

	// 3. Diversity Component (0-15 points)
	protocols := make(map[string]bool)
	for _, r := range e.results {
		if r.Success {
			protocols[r.Protocol] = true
		}
	}
	if len(protocols) >= 3 {
		score += 15
	} else if len(protocols) >= 2 {
		score += 10
	} else {
		score += 5
	}

	// 4. Consistency/Consensus Component (0-20 points)
	// Do we have a clear winner for each family?
	isConsistent := true
	consensusMsg := "Strong Consensus"

	for fam, counts := range e.familyIPs {
		if len(counts) == 0 {
			continue
		}

		totalFamHits := 0
		maxHits := 0
		for _, c := range counts {
			totalFamHits += c
			if c > maxHits {
				maxHits = c
			}
		}

		// Calculate dominance
		dominance := float64(maxHits) / float64(totalFamHits)

		if dominance < 0.8 && len(counts) > 1 {
			// Less than 80% agree on one IP
			isConsistent = false
			if dominance < 0.6 {
				consensusMsg = fmt.Sprintf("Split-Brain (%s)", fam)
			} else {
				consensusMsg = fmt.Sprintf("Weak Consensus (%s)", fam)
			}
		}

		// Bonus for repeated confirmation of single IP
		if len(counts) == 1 && maxHits >= 5 {
			// Perfect consistency
		} else if len(counts) > 1 {
			// Penalty handled by 'isConsistent' flag
		}
	}

	if isConsistent {
		score += 20
	} else {
		// Penalty for inconsistency
		score -= 10
	}

	// Map score to label
	label := "Low"
	if score >= 85 {
		label = "Very High"
	} else if score >= 70 {
		label = "High"
	} else if score >= 55 {
		label = "Medium-High"
	} else if score >= 40 {
		label = "Medium"
	} else if score >= 25 {
		label = "Low-Medium"
	}

	// Append score for debugging/transparency if needed, or keeping it clean
	// label = fmt.Sprintf("%s (%.0f)", label, score)

	if !isConsistent {
		label += " / " + consensusMsg // e.g. "Medium / Split-Brain (IPv4)"
	}

	return label, consensusMsg
}
