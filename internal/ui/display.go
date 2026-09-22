package ui

import (
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	ColorHeader           = "\033[95m"
	ColorOKBlue           = "\033[94m"
	ColorOKCyan           = "\033[96m"
	ColorOKGreen          = "\033[92m"
	ColorWarning          = "\033[93m"
	ColorFail             = "\033[91m"
	ColorEnd              = "\033[0m"
	ColorBold             = "\033[1m"
	ColorProgressComplete = "\033[42m"
	ColorProgressEmpty    = "\033[47m"
)

type Display struct {
	mu        sync.Mutex
	lastLines int
}

type ProtocolStat struct {
	Succeeded int `json:"succeeded"`
	Attempted int `json:"attempted"`
}

type IPEntry struct {
	IP         string  `json:"ip"`
	Hits       int     `json:"hits"`
	Percentage float64 `json:"percentage"`
}

func RankIPs(counts map[string]int) []IPEntry {
	total := 0
	for _, c := range counts {
		total += c
	}
	entries := make([]IPEntry, 0, len(counts))
	for ip, c := range counts {
		pct := 0.0
		if total > 0 {
			pct = (float64(c) / float64(total)) * 100
		}
		entries = append(entries, IPEntry{IP: ip, Hits: c, Percentage: pct})
	}
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].Hits > entries[j].Hits
	})
	return entries
}

type ResultUpdate struct {
	StartTime       time.Time
	CurrentPhase    string
	CompletedTests  int
	TotalTests      int
	SuccessfulTests int
	ProtocolStats   map[string]ProtocolStat
	IPFamilies      map[string][]IPEntry
	ConfidenceLevel string
	Consensus       string
}

func NewDisplay() *Display {
	return &Display{}
}

func (d *Display) ClearPrevious() {
	if d.lastLines > 0 {
		fmt.Printf("\033[%dA\033[J", d.lastLines)
	}
}

func (d *Display) ProgressBar(completed, total int, width int) string {
	if total == 0 {
		return fmt.Sprintf("[%s] 0/0", strings.Repeat(" ", width))
	}

	pct := float64(completed) / float64(total)
	if pct > 1.0 {
		pct = 1.0
	}
	filled := int(float64(width) * pct)

	bar := ColorProgressComplete + strings.Repeat(" ", filled) + ColorEnd
	bar += ColorProgressEmpty + strings.Repeat(" ", width-filled) + ColorEnd

	return fmt.Sprintf("[%s] %d/%d (%.1f%%)", bar, completed, total, pct*100)
}

func (d *Display) FormatIPList(entries []IPEntry) []string {
	var lines []string
	for _, h := range entries {
		color := ColorFail
		if h.Hits >= 3 {
			color = ColorOKGreen
		} else if h.Hits >= 2 {
			color = ColorWarning
		}

		line := fmt.Sprintf("   %s✓ %-39s%s (%d hits, %.1f%%)",
			color, h.IP, ColorEnd, h.Hits, h.Percentage)
		lines = append(lines, line)
	}
	return lines
}

func (d *Display) RenderLiveResults(state ResultUpdate) {
	d.mu.Lock()
	defer d.mu.Unlock()

	d.ClearPrevious()
	var lines []string

	elapsed := time.Since(state.StartTime).Seconds()

	lines = append(lines, fmt.Sprintf("%s%s🔍 IP Exit Discovery – Live Results%s", ColorHeader, ColorBold, ColorEnd))
	lines = append(lines, fmt.Sprintf("%sPhase: %s | Elapsed: %.1fs%s", ColorOKCyan, state.CurrentPhase, elapsed, ColorEnd))
	lines = append(lines, "")

	lines = append(lines, fmt.Sprintf("Overall Progress: %s", d.ProgressBar(state.CompletedTests, state.TotalTests, 40)))
	lines = append(lines, "")

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

			hasMultiple := len(ips) > 1
			summaryColor := ColorOKGreen
			summaryIcon := "📍"
			summaryText := "single egress IP observed"

			if hasMultiple {
				summaryColor = ColorWarning
				summaryIcon = "⚠️"
				summaryText = fmt.Sprintf("multiple egress mappings observed (%d IPs)", len(ips))
			}

			lines = append(lines, fmt.Sprintf("   %s%s %s: %s%s", summaryColor, summaryIcon, fam, summaryText, ColorEnd))
			lines = append(lines, "")
		}
	}

	if hasIPs {
		confLine := fmt.Sprintf("%s📈 Confidence: %s%s", ColorOKCyan, state.ConfidenceLevel, ColorEnd)
		if state.Consensus != "" && state.Consensus != "Strong Consensus" {
			confLine += fmt.Sprintf(" (%s)", state.Consensus)
		}
		lines = append(lines, confLine)

		// Explicit confidence inputs: probe stats & protocol breakdown
		if state.CompletedTests > 0 {
			probePct := float64(state.SuccessfulTests) / float64(state.CompletedTests) * 100
			probeDetail := fmt.Sprintf("   Probes: %d/%d succeeded (%.1f%%)", state.SuccessfulTests, state.CompletedTests, probePct)

			if len(state.ProtocolStats) > 0 {
				var protoParts []string
				var protoKeys []string
				for k := range state.ProtocolStats {
					protoKeys = append(protoKeys, k)
				}
				sort.Strings(protoKeys)
				for _, k := range protoKeys {
					ps := state.ProtocolStats[k]
					protoParts = append(protoParts, fmt.Sprintf("%s: %d/%d", k, ps.Succeeded, ps.Attempted))
				}
				probeDetail += fmt.Sprintf(" | %s", strings.Join(protoParts, ", "))
			}
			lines = append(lines, fmt.Sprintf("%s%s%s", ColorOKBlue, probeDetail, ColorEnd))
		}
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

type VerboseResultItem struct {
	Service   string
	Protocol  string
	Attempt   int
	IPs       []string
	LatencyMs float64
	Success   bool
	Error     string
}

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

		if len(ipsDisplay) > 45 {
			ipsDisplay = ipsDisplay[:42] + "..."
		}

		fmt.Printf("   %s %-25s | %-10s | #%-2d | %-45s | %7.1fms\n",
			status, r.Service, r.Protocol, r.Attempt, ipsDisplay, r.LatencyMs)
	}
}
