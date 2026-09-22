package discovery

import (
	"context"
	"encoding/json"
	"fmt"
	"math/rand"
	"net"
	"os"
	"os/signal"
	"sort"
	"strings"
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

	ipsFound        map[string]int
	familyIPs       map[string]map[string]int
	deadServices    map[string]error
	startTime       time.Time
	testsCompleted  int
	testsSuccessful int
	testsTotal      int
	currentPhase    string

	lastRender time.Time
	renderMu   sync.Mutex
	mu         sync.Mutex
}

func NewEngine(httpServices, udpServices []ServiceConfig) *Engine {
	return &Engine{
		httpServices: httpServices,
		udpServices:  udpServices,
		ui:           ui.NewDisplay(),
		ipsFound:     make(map[string]int),
		familyIPs: map[string]map[string]int{
			"IPv4": make(map[string]int),
			"IPv6": make(map[string]int),
		},
		deadServices: make(map[string]error),
		startTime:    time.Now(),
	}
}

func (e *Engine) Run(ctx context.Context, verbose bool) {
	e.RunWithOptions(ctx, RunOptions{
		Verbose:  verbose,
		Samples:  3,
		Interval: 300 * time.Millisecond,
		Timeout:  5 * time.Second,
	})
}

func (e *Engine) RunWithOptions(ctx context.Context, opts RunOptions) {
	e.startTime = time.Now()

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigChan
		if !opts.JSON {
			fmt.Println("\nReceived interrupt, stopping...")
		}
		cancel()
	}()

	samples := opts.Samples
	if samples <= 0 {
		samples = 3
	}
	interval := opts.Interval
	if interval <= 0 {
		interval = 300 * time.Millisecond
	}
	if opts.Timeout > 0 {
		for i := range e.httpServices {
			e.httpServices[i].Timeout = opts.Timeout
		}
		for i := range e.udpServices {
			e.udpServices[i].Timeout = opts.Timeout
		}
	}

	e.testsTotal = (len(e.httpServices) * samples) + (len(e.udpServices) * samples)
	e.currentPhase = "Concurrent Discovery"

	// Run HTTP and UDP-STUN discovery concurrently
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		e.runPhase(ctx, "HTTP(S)", e.httpServices, TestHTTPService, samples, interval, opts.JSON)
	}()

	go func() {
		defer wg.Done()
		e.runPhase(ctx, "UDP-STUN", e.udpServices, TestSTUNService, samples, interval, opts.JSON)
	}()

	wg.Wait()

	if opts.JSON {
		e.outputJSON()
		return
	}

	e.maybeRender(true, false)

	if opts.Verbose {
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

func (e *Engine) runPhase(ctx context.Context, phaseName string, services []ServiceConfig, tester TesterFunc, samples int, interval time.Duration, jsonMode bool) {
	for attempt := 1; attempt <= samples; attempt++ {
		if ctx.Err() != nil {
			break
		}

		e.mu.Lock()
		e.currentPhase = fmt.Sprintf("%s (sample %d/%d)", phaseName, attempt, samples)
		e.mu.Unlock()

		shuffled := make([]ServiceConfig, len(services))
		copy(shuffled, services)
		rand.Shuffle(len(shuffled), func(i, j int) { shuffled[i], shuffled[j] = shuffled[j], shuffled[i] })

		e.runBatch(ctx, shuffled, tester, attempt, jsonMode)

		if ctx.Err() != nil {
			break
		}

		if attempt < samples {
			time.Sleep(interval)
		}
	}
}

func (e *Engine) runBatch(ctx context.Context, services []ServiceConfig, tester TesterFunc, attempt int, jsonMode bool) {
	var wg sync.WaitGroup
	semaphore := make(chan struct{}, 12)

	for _, svc := range services {
		if ctx.Err() != nil {
			break
		}

		e.mu.Lock()
		prevErr, isDead := e.deadServices[svc.Name]
		e.mu.Unlock()

		// Skip repeat timeouts for services unreachable on attempt 1
		if isDead && attempt > 1 {
			e.processResult(TestResult{
				Service:   svc.Name,
				Protocol:  svc.Protocol,
				Attempt:   attempt,
				Success:   false,
				Error:     fmt.Errorf("skipped (previously unreachable: %v)", prevErr),
				Timestamp: time.Now(),
			}, jsonMode)
			continue
		}

		wg.Add(1)
		semaphore <- struct{}{}

		go func(s ServiceConfig) {
			defer wg.Done()
			defer func() { <-semaphore }()

			res := tester(ctx, s, attempt)

			if !res.Success && attempt == 1 && res.Error != nil {
				errStr := res.Error.Error()
				if strings.Contains(errStr, "deadline exceeded") || strings.Contains(errStr, "connection refused") || strings.Contains(errStr, "no route to host") {
					e.mu.Lock()
					e.deadServices[s.Name] = res.Error
					e.mu.Unlock()
				}
			}

			e.processResult(res, jsonMode)
		}(svc)
	}

	wg.Wait()
}

func (e *Engine) processResult(res TestResult, jsonMode bool) {
	e.mu.Lock()

	e.testsCompleted++
	e.results = append(e.results, res)

	if res.Success && len(res.IPs) > 0 {
		e.testsSuccessful++
		for _, ip := range res.IPs {
			e.ipsFound[ip]++

			family := "IPv4"
			parsedIP := net.ParseIP(ip)
			if parsedIP != nil && parsedIP.To4() == nil {
				family = "IPv6"
			}
			e.familyIPs[family][ip]++
		}
	}

	e.mu.Unlock()

	e.maybeRender(false, jsonMode)
}

func (e *Engine) maybeRender(force bool, jsonMode bool) {
	if jsonMode {
		return
	}

	e.renderMu.Lock()
	defer e.renderMu.Unlock()

	now := time.Now()
	if !force && now.Sub(e.lastRender) < 100*time.Millisecond {
		return
	}
	e.lastRender = now

	snapshot := e.getUpdateSnapshot()
	e.ui.RenderLiveResults(snapshot)
}

func (e *Engine) getUpdateSnapshot() ui.ResultUpdate {
	e.mu.Lock()
	defer e.mu.Unlock()

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

	multipleEgress := make(map[string]bool)
	for fam, counts := range familyIPs {
		if len(counts) > 1 {
			multipleEgress[fam] = true
		}
	}

	protocolStats := make(map[string]ui.ProtocolStat)
	for _, r := range e.results {
		stat := protocolStats[r.Protocol]
		stat.Attempted++
		if r.Success {
			stat.Succeeded++
		}
		protocolStats[r.Protocol] = stat
	}

	return ui.ResultUpdate{
		StartTime:              e.startTime,
		CurrentPhase:           e.currentPhase,
		CompletedTests:         e.testsCompleted,
		TotalTests:             e.testsTotal,
		SuccessfulTests:        e.testsSuccessful,
		ProtocolStats:          protocolStats,
		IPs:                    ipsFound,
		IPFamilies:             familyIPs,
		ConfidenceLevel:        confidence,
		Consensus:              consensus,
		MultipleEgressObserved: multipleEgress,
	}
}

func (e *Engine) CalculateConfidence() (string, string) {
	if e.testsCompleted == 0 {
		return "Unknown", "Waiting..."
	}
	if e.testsSuccessful == 0 {
		return "Low", "No egress IPs discovered"
	}

	total := float64(e.testsCompleted)
	successRate := float64(e.testsSuccessful) / total

	protocols := make(map[string]bool)
	for _, r := range e.results {
		if r.Success {
			protocols[r.Protocol] = true
		}
	}

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

		dominance := float64(maxHits) / float64(totalFamHits)
		if dominance < 0.8 && len(counts) > 1 {
			isConsistent = false
			if dominance < 0.6 {
				consensusMsg = fmt.Sprintf("Multiple Mappings (%s)", fam)
			} else {
				consensusMsg = fmt.Sprintf("Weak Consensus (%s)", fam)
			}
		}
	}

	var label string
	switch {
	case successRate < 0.40:
		label = "Low"
	case successRate < 0.65:
		label = "Low-Medium"
	case successRate < 0.80:
		label = "Medium"
	case successRate < 0.90:
		if len(protocols) >= 2 && e.testsSuccessful >= 6 && isConsistent {
			label = "High"
		} else {
			label = "Medium-High"
		}
	default: // >= 0.90
		if len(protocols) >= 2 && e.testsSuccessful >= 8 && isConsistent {
			label = "Very High"
		} else if isConsistent {
			label = "High"
		} else {
			label = "Medium-High"
		}
	}

	if !isConsistent {
		label += " / " + consensusMsg
	}

	return label, consensusMsg
}

func (e *Engine) outputJSON() {
	e.mu.Lock()
	defer e.mu.Unlock()

	confidence, consensus := e.CalculateConfidence()
	durationMs := float64(time.Since(e.startTime).Milliseconds())

	protocolStats := make(map[string]ui.ProtocolStat)
	for _, r := range e.results {
		stat := protocolStats[r.Protocol]
		stat.Attempted++
		if r.Success {
			stat.Succeeded++
		}
		protocolStats[r.Protocol] = stat
	}

	discoveredIPs := make(map[string][]JSONIPEntry)
	for fam, counts := range e.familyIPs {
		total := 0
		for _, count := range counts {
			total += count
		}
		var entries []JSONIPEntry
		for ip, count := range counts {
			pct := 0.0
			if total > 0 {
				pct = (float64(count) / float64(total)) * 100
			}
			entries = append(entries, JSONIPEntry{
				IP:         ip,
				Hits:       count,
				Percentage: pct,
			})
		}
		sort.Slice(entries, func(i, j int) bool {
			return entries[i].Hits > entries[j].Hits
		})
		discoveredIPs[strings.ToLower(fam)] = entries
	}

	var detailed []JSONResultItem
	for _, r := range e.results {
		errMsg := ""
		if r.Error != nil {
			errMsg = r.Error.Error()
		}
		detailed = append(detailed, JSONResultItem{
			Service:   r.Service,
			Protocol:  r.Protocol,
			Attempt:   r.Attempt,
			Success:   r.Success,
			IPs:       r.IPs,
			LatencyMs: float64(r.Latency.Milliseconds()),
			Error:     errMsg,
		})
	}

	out := JSONOutput{
		Timestamp:       e.startTime.UTC(),
		DurationMs:      durationMs,
		Confidence:      confidence,
		Consensus:       consensus,
		CompletedTests:  e.testsCompleted,
		SuccessfulTests: e.testsSuccessful,
		ProtocolStats:   protocolStats,
		DiscoveredIPs:   discoveredIPs,
		DetailedResults: detailed,
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	_ = enc.Encode(out)
}
