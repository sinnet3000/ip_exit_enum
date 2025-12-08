package ui

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

// ANSI color codes
const (
	ColorHeader           = "\033[95m"
	ColorOKBlue           = "\033[94m"
	ColorOKCyan           = "\033[96m"
	ColorOKGreen          = "\033[92m"
	ColorWarning          = "\033[93m"
	ColorFail             = "\033[91m"
	ColorEnd              = "\033[0m"
	ColorBold             = "\033[1m"
	ColorUnderline        = "\033[4m"
	ColorProgressComplete = "\033[42m"
	ColorProgressPartial  = "\033[43m"
	ColorProgressEmpty    = "\033[47m"
)

// Display handles terminal output and live updates
type Display struct {
	lastLines int
}

// ResultUpdate represents a snapshot of the current state for rendering
type ResultUpdate struct {
	StartTime          time.Time
	CurrentPhase       string
	CompletedTests     int
	TotalTests         int
	IPs                map[string]int            // IP -> count
	IPFamilies         map[string]map[string]int // Family -> IP -> count
	ConfidenceLevel    string
	LoadBalancingFound map[string]bool
}

// NewDisplay creates a new display handler
func NewDisplay() *Display {
	return &Display{}
}

// ClearPrevious clears the lines printed by the last render
func (d *Display) ClearPrevious() {
	if d.lastLines > 0 {
		fmt.Printf("\033[%dA\033[J", d.lastLines)
	}
}

// ProgressBar generates a progress bar string
func (d *Display) ProgressBar(completed, total int, width int) string {
	if total == 0 {
		return fmt.Sprintf("[%s] 0/0", strings.Repeat(" ", width))
	}

	pct := float64(completed) / float64(total)
	filled := int(float64(width) * pct)

	bar := ColorProgressComplete + strings.Repeat(" ", filled) + ColorEnd
	bar += ColorProgressEmpty + strings.Repeat(" ", width-filled) + ColorEnd

	return fmt.Sprintf("[%s] %d/%d (%.1f%%)", bar, completed, total, pct*100)
}

// FormatIPList returns a formatted list of discovered IPs
func (d *Display) FormatIPList(ipCounts map[string]int) []string {
	var lines []string

	// Convert map to slice for sorting
	type ipHit struct {
		ip    string
		count int
	}
	var hits []ipHit
	totalHits := 0

	for ip, count := range ipCounts {
		hits = append(hits, ipHit{ip, count})
		totalHits += count
	}

	// Sort by count (descending)
	sort.Slice(hits, func(i, j int) bool {
		return hits[i].count > hits[j].count
	})

	for _, h := range hits {
		pct := 0.0
		if totalHits > 0 {
			pct = (float64(h.count) / float64(totalHits)) * 100
		}

		color := ColorFail
		if h.count >= 3 {
			color = ColorOKGreen
		} else if h.count >= 2 {
			color = ColorWarning
		}

		line := fmt.Sprintf("   %s✓ %-39s%s (%d hits, %.1f%%)",
			color, h.ip, ColorEnd, h.count, pct)
		lines = append(lines, line)
	}

	return lines
}

// RenderLiveResults prints the current status to the terminal
func (d *Display) RenderLiveResults(state ResultUpdate) {
	d.ClearPrevious()
	var lines []string

	elapsed := time.Since(state.StartTime).Seconds()

	lines = append(lines, fmt.Sprintf("%s%s🔍 IP Exit Discovery – Live Results%s", ColorHeader, ColorBold, ColorEnd))
	lines = append(lines, fmt.Sprintf("%sPhase: %s | Elapsed: %.1fs%s", ColorOKCyan, state.CurrentPhase, elapsed, ColorEnd))
	lines = append(lines, "")

	lines = append(lines, fmt.Sprintf("Overall Progress: %s", d.ProgressBar(state.CompletedTests, state.TotalTests, 40)))
	lines = append(lines, "")

	// Families to check
	families := []string{"IPv4", "IPv6"}
	hasIPs := false

	for _, fam := range families {
		if ips, ok := state.IPFamilies[fam]; ok && len(ips) > 0 {
			if !hasIPs {
				lines = append(lines, fmt.Sprintf("%s📊 IPs Discovered:%s", ColorBold, ColorEnd))
				hasIPs = true
			}

			lines = append(lines, fmt.Sprintf(" %s%s:%s", ColorBold, fam, ColorEnd))
			lines = append(lines, d.FormatIPList(ips)...)

			// Load balancing status
			isBalanced := len(ips) > 1
			summaryColor := ColorOKGreen
			summaryIcon := "📍"
			summaryText := "single egress IP"

			if isBalanced {
				summaryColor = ColorWarning
				summaryIcon = "🔄"
				summaryText = fmt.Sprintf("load balancing across %d IPs", len(ips))
			}

			lines = append(lines, fmt.Sprintf("   %s%s %s: %s%s", summaryColor, summaryIcon, fam, summaryText, ColorEnd))
			lines = append(lines, "")
		}
	}

	if hasIPs {
		lines = append(lines, fmt.Sprintf("%s📈 Confidence: %s%s", ColorOKCyan, state.ConfidenceLevel, ColorEnd))
		lines = append(lines, "")
	} else {
		lines = append(lines, fmt.Sprintf("%s⏳ Discovering IPs...%s", ColorWarning, ColorEnd))
		lines = append(lines, "")
	}

	for _, line := range lines {
		fmt.Println(line)
	}

	d.lastLines = len(lines)
}

// VerboseResultItem holds data for detailed report
type VerboseResultItem struct {
	Service   string
	Protocol  string
	Attempt   int
	IPs       []string
	LatencyMs float64
	Success   bool
	Error     string
}

// PrintVerbose prints the detailed execution log
func (d *Display) PrintVerbose(results []VerboseResultItem) {
	fmt.Println("\n📋 Detailed results:")

	for _, r := range results {
		status := "✓"
		if !r.Success {
			status = "✗"
		}

		ipsDisplay := "-"
		if len(r.IPs) > 0 {
			ipsDisplay = strings.Join(r.IPs, ", ")
		} else if r.Error != "" {
			ipsDisplay = fmt.Sprintf("(%s)", r.Error)
		}

		// Truncate error/IPs if too long
		if len(ipsDisplay) > 45 {
			ipsDisplay = ipsDisplay[:42] + "..."
		}

		fmt.Printf("   %s %-25s | %-10s | #%-2d | %-45s | %7.1fms\n",
			status, r.Service, r.Protocol, r.Attempt, ipsDisplay, r.LatencyMs)
	}
}
