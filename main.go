package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"ip_exit_enum/internal/discovery"
	"ip_exit_enum/internal/update"
	"ip_exit_enum/internal/version"
)

const defaultTimeout = 5 * time.Second

func main() {
	verbose := flag.Bool("v", false, "Verbose output")
	showVersion := flag.Bool("version", false, "Show version and exit")
	doUpdate := flag.Bool("update", false, "Update to the latest version")
	samples := flag.Int("samples", 3, "Number of probe samples")
	interval := flag.Duration("interval", 300*time.Millisecond, "Interval between samples")
	timeout := flag.Duration("timeout", defaultTimeout, "Per-probe timeout")
	jsonOutput := flag.Bool("json", false, "Output results as JSON")
	flag.Parse()

	if *showVersion {
		fmt.Printf("ip_exit_enum %s\n", version.Version)
		return
	}

	if *doUpdate {
		runUpdate()
		return
	}

	probeTimeout := *timeout

	httpServices := []discovery.ServiceConfig{
		httpService("ipify", "https://api.ipify.org", "", "", probeTimeout),
		httpService("httpbin", "https://httpbin.org/ip", "", "origin", probeTimeout),
		httpService("icanhazip", "https://icanhazip.com", "", "", probeTimeout),
		httpService("jsonip", "https://jsonip.com", "", "ip", probeTimeout),
		httpService("ipecho", "http://ipecho.net/plain", "", "", probeTimeout),
		httpService("myip", "https://api.myip.com", "", "ip", probeTimeout),

		httpService("icanhazip-ipv4", "https://ipv4.icanhazip.com", "IPv4", "", probeTimeout),
		httpService("seeip-ipv4", "https://ipv4.seeip.org", "IPv4", "", probeTimeout),

		httpService("ipify-v6", "https://api6.ipify.org", "IPv6", "", probeTimeout),
		httpService("icanhazip-ipv6", "https://ipv6.icanhazip.com", "IPv6", "", probeTimeout),
		httpService("seeip-ipv6", "https://ipv6.seeip.org", "IPv6", "", probeTimeout),
	}

	udpServices := []discovery.ServiceConfig{
		stunService("stun-google-v4", "stun.l.google.com:19302", "UDP-STUN", probeTimeout),
		stunService("stun-cloudflare-v4", "stun.cloudflare.com:3478", "UDP-STUN", probeTimeout),

		stunService("stun-google-v6", "stun.l.google.com:19302", "UDP-STUN6", probeTimeout),
		stunService("stun-cloudflare-v6", "stun.cloudflare.com:3478", "UDP-STUN6", probeTimeout),
	}

	engine := discovery.NewEngine(httpServices, udpServices)
	engine.RunWithOptions(context.Background(), discovery.RunOptions{
		Verbose:  *verbose,
		JSON:     *jsonOutput,
		Samples:  *samples,
		Interval: *interval,
		Timeout:  probeTimeout,
	})
}

func runUpdate() {
	fmt.Println("Checking for updates...")

	info, err := update.CheckForUpdate()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	if info == nil {
		fmt.Printf("Already running latest version (%s)\n", version.Version)
		return
	}

	fmt.Printf("\n  Current version: %s\n", info.CurrentVersion)
	fmt.Printf("  Latest version:  %s\n", info.LatestVersion)
	fmt.Printf("\n  Download: %s\n", info.DownloadURL)
	fmt.Printf("  Size:     %s\n", update.FormatSize(info.Size))

	fmt.Print("\nProceed with update? [y/N] ")
	var response string
	fmt.Scanln(&response)
	if strings.ToLower(response) != "y" && strings.ToLower(response) != "yes" {
		fmt.Println("Update cancelled")
		return
	}

	fmt.Println()
	if err := update.PerformUpdate(info); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Updated to %s\n", info.LatestVersion)
}

func httpService(name, url, family, extractField string, timeout time.Duration) discovery.ServiceConfig {
	cfg := discovery.ServiceConfig{
		Name:     name,
		URL:      url,
		Protocol: "HTTP",
		Family:   family,
		Timeout:  timeout,
	}
	if extractField != "" {
		cfg.ExtractMethod = "json"
		cfg.ExtractField = extractField
	}
	return cfg
}

func stunService(name, url, protocol string, timeout time.Duration) discovery.ServiceConfig {
	return discovery.ServiceConfig{
		Name:     name,
		URL:      url,
		Protocol: protocol,
		Timeout:  timeout,
	}
}
