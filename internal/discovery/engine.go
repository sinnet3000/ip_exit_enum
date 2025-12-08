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

// Engine orchestrates the discovery process
type Engine struct {
	httpServices []ServiceConfig
	udpServices  []ServiceConfig
	results      []TestResult
	ui           *ui.Display

	// State for UI
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

// ensureMaps ensures nested maps are initialized (helper)
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

	// Create cancelable context for graceful shutdown
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	// Handle signals
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigChan
		fmt.Println("\nReceived interrupt, stopping...")
		cancel()
	}()

	// Samples config
	httpSamples := 3
	udpSamples := 2

	e.testsTotal = (len(e.httpServices) * httpSamples) + (len(e.udpServices) * udpSamples)

	// Run HTTP Tests
	for attempt := 1; attempt <= httpSamples; attempt++ {
		e.currentPhase = fmt.Sprintf("HTTP(S) Discovery – sample %d/%d", attempt, httpSamples)

		// Shuffle services
		services := make([]ServiceConfig, len(e.httpServices))
		copy(services, e.httpServices)
		rand.Shuffle(len(services), func(i, j int) { services[i], services[j] = services[j], services[i] })

		e.runBatch(ctx, services, TestHTTPService, attempt)

		// Break if context cancelled
		if ctx.Err() != nil {
			break
		}

		if attempt < httpSamples {
			time.Sleep(300 * time.Millisecond)
		}
	}

	// Run STUN Tests
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

	// Final Report
	e.ui.RenderLiveResults(e.getUpdate()) // Final update

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

			// Small jitter to prevent stampedes
			time.Sleep(time.Duration(rand.Intn(100)) * time.Millisecond)

			res := tester(ctx, s, attempt)
			e.processResult(res)
		}(svc)
	}

	wg.Wait()
}

func (e *Engine) processResult(res TestResult) {
	e.mu.Lock()
	defer e.mu.Unlock()

	e.testsCompleted++
	e.results = append(e.results, res)

	if res.Success && len(res.IPs) > 0 {
		e.serviceStatus[res.Service] = "success"
		for _, ip := range res.IPs {
			e.ipsFound[ip]++

			// Protocol accounting
			if e.protocolIPs[res.Protocol] == nil {
				e.protocolIPs[res.Protocol] = make(map[string]int)
			}
			e.protocolIPs[res.Protocol][ip]++

			// Family accounting
			family := "IPv4"
			if net.ParseIP(ip).To4() == nil {
				family = "IPv6"
			}
			e.familyIPs[family][ip]++
		}
	} else {
		e.serviceStatus[res.Service] = "failed"
	}

	// Trigger UI update
	e.ui.RenderLiveResults(e.getUpdate())
}

func (e *Engine) getUpdate() ui.ResultUpdate {
	// Calculate confidence (simple version)
	confidence := "Low"
	successCount := 0
	for _, r := range e.results {
		if r.Success {
			successCount++
		}
	}

	if successCount > 5 {
		confidence = "Medium"
	}
	if successCount > 10 {
		confidence = "High"
	}

	return ui.ResultUpdate{
		StartTime:       e.startTime,
		CurrentPhase:    e.currentPhase,
		CompletedTests:  e.testsCompleted,
		TotalTests:      e.testsTotal,
		IPs:             e.ipsFound,
		IPFamilies:      e.familyIPs,
		ConfidenceLevel: confidence,
	}
}
