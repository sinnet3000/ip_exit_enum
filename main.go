package main

import (
	"context"
	"flag"
	"time"

	"ip_exit_enum/internal/discovery"
)

func main() {
	verbose := flag.Bool("v", false, "Verbose output")
	flag.Parse()

	// Configuration - Mirroring Python service list
	httpServices := []discovery.ServiceConfig{
		// Primary IPv4
		{Name: "ipify", URL: "https://api.ipify.org", Protocol: "HTTP", Timeout: 5 * time.Second},
		{Name: "httpbin", URL: "https://httpbin.org/ip", Protocol: "HTTP", ExtractMethod: "json", ExtractField: "origin", Timeout: 5 * time.Second},
		{Name: "icanhazip", URL: "https://icanhazip.com", Protocol: "HTTP", Timeout: 5 * time.Second},
		{Name: "jsonip", URL: "https://jsonip.com", Protocol: "HTTP", ExtractMethod: "json", ExtractField: "ip", Timeout: 5 * time.Second},
		{Name: "ipecho", URL: "http://ipecho.net/plain", Protocol: "HTTP", Timeout: 5 * time.Second},
		{Name: "myip", URL: "https://api.myip.com", Protocol: "HTTP", ExtractMethod: "json", ExtractField: "ip", Timeout: 5 * time.Second},

		// IPv4 Specific
		{Name: "icanhazip-ipv4", URL: "https://ipv4.icanhazip.com", Protocol: "HTTP", Timeout: 5 * time.Second},
		{Name: "seeip-ipv4", URL: "https://ipv4.seeip.org", Protocol: "HTTP", Timeout: 5 * time.Second},

		// IPv6 Specific
		{Name: "ipify-v6", URL: "https://api6.ipify.org", Protocol: "HTTP", Timeout: 5 * time.Second},
		{Name: "icanhazip-ipv6", URL: "https://ipv6.icanhazip.com", Protocol: "HTTP", Timeout: 5 * time.Second},
		{Name: "seeip-ipv6", URL: "https://ipv6.seeip.org", Protocol: "HTTP", Timeout: 5 * time.Second},
	}

	udpServices := []discovery.ServiceConfig{
		// IPv4 STUN
		{Name: "stun-google-v4", URL: "stun.l.google.com:19302", Protocol: "UDP-STUN", Timeout: 5 * time.Second},
		{Name: "stun-cloudflare-v4", URL: "stun.cloudflare.com:3478", Protocol: "UDP-STUN", Timeout: 5 * time.Second},

		// IPv6 STUN
		// Note: pion/stun will resolve to AAAA records if available, but to force v6 we rely on system routing
		// or specific listeners in our generic engine.
		{Name: "stun-google-v6", URL: "stun.l.google.com:19302", Protocol: "UDP-STUN6", Timeout: 5 * time.Second},
		{Name: "stun-cloudflare-v6", URL: "stun.cloudflare.com:3478", Protocol: "UDP-STUN6", Timeout: 5 * time.Second},
	}

	engine := discovery.NewEngine(httpServices, udpServices)
	engine.Run(context.Background(), *verbose)
}
