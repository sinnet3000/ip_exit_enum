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

type serviceProtocol string

type extractMethod string

const serviceTimeout = 5 * time.Second

const (
	protocolHTTP     serviceProtocol = "HTTP"
	protocolUDPSTUN  serviceProtocol = "UDP-STUN"
	protocolUDPSTUN6 serviceProtocol = "UDP-STUN6"

	extractJSON extractMethod = "json"
)

func main() {
	verbose := flag.Bool("v", false, "Verbose output")
	showVersion := flag.Bool("version", false, "Show version and exit")
	doUpdate := flag.Bool("update", false, "Update to the latest version")
	samples := flag.Int("samples", 3, "Number of probe samples")
	interval := flag.Duration("interval", 300*time.Millisecond, "Interval between samples")
	timeout := flag.Duration("timeout", serviceTimeout, "Per-probe timeout")
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
		httpService("ipify", "https://api.ipify.org", probeTimeout, ""),
		httpService("httpbin", "https://httpbin.org/ip", probeTimeout, "origin"),
		httpService("icanhazip", "https://icanhazip.com", probeTimeout, ""),
		httpService("jsonip", "https://jsonip.com", probeTimeout, "ip"),
		httpService("ipecho", "http://ipecho.net/plain", probeTimeout, ""),
		httpService("myip", "https://api.myip.com", probeTimeout, "ip"),

		httpService("icanhazip-ipv4", "https://ipv4.icanhazip.com", probeTimeout, ""),
		httpService("seeip-ipv4", "https://ipv4.seeip.org", probeTimeout, ""),

		httpService("ipify-v6", "https://api6.ipify.org", probeTimeout, ""),
		httpService("icanhazip-ipv6", "https://ipv6.icanhazip.com", probeTimeout, ""),
		httpService("seeip-ipv6", "https://ipv6.seeip.org", probeTimeout, ""),
	}

	udpServices := []discovery.ServiceConfig{
		stunService("stun-google-v4", "stun.l.google.com:19302", probeTimeout, protocolUDPSTUN),
		stunService("stun-cloudflare-v4", "stun.cloudflare.com:3478", probeTimeout, protocolUDPSTUN),

		stunService("stun-google-v6", "stun.l.google.com:19302", probeTimeout, protocolUDPSTUN6),
		stunService("stun-cloudflare-v6", "stun.cloudflare.com:3478", probeTimeout, protocolUDPSTUN6),
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

func httpService(name, url string, timeout time.Duration, extractField string) discovery.ServiceConfig {
	service := discovery.ServiceConfig{
		Name:     name,
		URL:      url,
		Protocol: string(protocolHTTP),
		Timeout:  timeout,
	}

	if extractField != "" {
		service.ExtractMethod = string(extractJSON)
		service.ExtractField = extractField
	}

	return service
}

func stunService(name, url string, timeout time.Duration, protocol serviceProtocol) discovery.ServiceConfig {
	return discovery.ServiceConfig{
		Name:     name,
		URL:      url,
		Protocol: string(protocol),
		Timeout:  timeout,
	}
}
