#!/usr/bin/env python3
"""
IP Exit Enumeration Tool – Dual-Stack Edition

Discovers all public IPv4/IPv6 addresses used by the system for outbound connections
through comprehensive testing of HTTP/HTTPS and UDP-STUN services.

This tool helps identify:
- Primary egress IP addresses (IPv4 and IPv6)
- Load balancing configurations
- Network path diversity
- Connection consistency across protocols

Usage:
    python3 ip_exit_tool.py [--verbose] [--quiet]
"""

# Standard library imports
import argparse
import asyncio
import json
import os
import random
import re
import signal
import socket
import sys
import time
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from typing import Dict, List, Optional

# Third-party imports
import aiohttp
import ipaddress


# ==============================================================================
# Terminal Colors and Formatting
# ==============================================================================
class Colors:
    """ANSI color codes for terminal output formatting."""
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    PROGRESS_COMPLETE = '\033[42m'
    PROGRESS_PARTIAL = '\033[43m'
    PROGRESS_EMPTY = '\033[47m'


# ==============================================================================
# Data Structures
# ==============================================================================
@dataclass
class TestResult:
    """Container for individual service test results."""
    service: str                # Service identifier (e.g., "ipify", "stun-google")
    protocol: str               # Protocol used (HTTP, UDP-STUN, etc.)
    ips: List[str]             # All IPs observed during the test
    timestamp: float           # When the test completed
    latency_ms: float         # Response time in milliseconds
    success: bool             # Whether the test succeeded
    attempt: int              # Which sampling attempt generated this result
    error: Optional[str] = None  # Error message if test failed

    @property
    def primary_ip(self) -> str:
        """Return the first discovered IP for backward-compatible access."""
        return self.ips[0] if self.ips else ""


@dataclass
class ServiceConfig:
    """Configuration for a service endpoint."""
    name: str                           # Unique service identifier
    url: str                           # Service URL or hostname:port
    protocol: str                      # Protocol type for categorization
    timeout: int = 5                   # Request timeout in seconds
    extract_method: str = 'text'       # How to parse response: 'text', 'json', 'headers'
    extract_field: Optional[str] = None  # JSON field name for extraction
    socket_family: int = socket.AF_INET  # AF_INET (IPv4) or AF_INET6 (IPv6)


@dataclass
class LiveResults:
    """Container for real-time test results and statistics."""
    results: List[TestResult] = field(default_factory=list)
    ips_found: Counter = field(default_factory=Counter)                    # IP -> hit count
    protocol_ips: Dict[str, Counter] = field(default_factory=lambda: defaultdict(Counter))  # protocol -> IP counts
    family_ips: Dict[str, Counter] = field(default_factory=lambda: defaultdict(Counter))    # IP family -> counts
    service_status: Dict[str, str] = field(default_factory=dict)           # service -> status
    start_time: float = field(default_factory=time.time)
    tests_completed: int = 0
    tests_total: int = 0
    current_phase: str = "Initializing"
    confidence_level: str = "Unknown"
    load_balancing_detected: Dict[str, bool] = field(default_factory=dict)


# ==============================================================================
# Progress Display System
# ==============================================================================
class ProgressDisplay:
    """Handles live updating of terminal output during discovery process."""
    
    def __init__(self):
        self.last_lines = 0

    def clear_previous(self):
        """Clear previously printed lines to update display in place."""
        if self.last_lines:
            print(f'\033[{self.last_lines}A\033[J', end='')

    def progress_bar(self, completed: int, total: int, width: int = 40) -> str:
        """Generate a colored progress bar string."""
        if not total:
            return f"[{' ' * width}] 0/0"
        
        pct = completed / total
        filled = int(width * pct)
        
        # Create colored progress bar
        bar = Colors.PROGRESS_COMPLETE + ' ' * filled + Colors.ENDC
        bar += Colors.PROGRESS_EMPTY + ' ' * (width - filled) + Colors.ENDC
        
        return f"[{bar}] {completed}/{total} ({pct*100:.1f}%)"

    def format_ip_list(self, ip_counter: Counter) -> List[str]:
        """Format discovered IPs with hit counts and percentages."""
        lines = []
        total_hits = sum(ip_counter.values())
        for ip, count in ip_counter.most_common():
            pct = (count / total_hits * 100) if total_hits else 0

            # Color code based on confidence (more hits = more confident)
            colour = (Colors.OKGREEN if count >= 3 else
                      Colors.WARNING if count >= 2 else
                      Colors.FAIL)

            lines.append(f"   {colour}✓ {ip:<39}{Colors.ENDC} ({count} hits, {pct:.1f}%)")
        return lines

    def render_live_results(self, results: LiveResults):
        """Display live results during discovery process."""
        self.clear_previous()
        lines = []
        
        # Header and timing info
        elapsed = time.time() - results.start_time
        lines.append(f"{Colors.HEADER}{Colors.BOLD}🔍 IP Exit Discovery – Live Results{Colors.ENDC}")
        lines.append(f"{Colors.OKCYAN}Phase: {results.current_phase} | Elapsed: {elapsed:.1f}s{Colors.ENDC}")
        lines.append("")
        
        # Progress bar
        lines.append(f"Overall Progress: {self.progress_bar(results.tests_completed, results.tests_total)}")
        lines.append("")
        
        # Display discovered IPs or waiting message
        active_families = {family: counter for family, counter in results.family_ips.items() if counter}
        if active_families:
            lines.append(f"{Colors.BOLD}📊 IPs Discovered:{Colors.ENDC}")
            results.load_balancing_detected = {}
            
            for family in ("IPv4", "IPv6"):
                counter = active_families.get(family)
                if not counter:
                    continue

                lines.append(f" {Colors.BOLD}{family}:{Colors.ENDC}")
                lines.extend(self.format_ip_list(counter))

                balanced = len(counter) > 1
                results.load_balancing_detected[family] = balanced
                summary_colour = Colors.WARNING if balanced else Colors.OKGREEN
                summary_icon = "🔄" if balanced else "📍"
                summary_text = (f"{summary_icon} {family}: load balancing across {len(counter)} IPs"
                                 if balanced else
                                 f"{summary_icon} {family}: single egress IP")
                lines.append(f"   {summary_colour}{summary_text}{Colors.ENDC}")
                lines.append("")

            lines.append(f"{Colors.OKCYAN}📈 Confidence: {results.confidence_level}{Colors.ENDC}")
            lines.append("")
        else:
            lines.append(f"{Colors.WARNING}⏳ Discovering IPs...{Colors.ENDC}\n")

        print('\n'.join(lines))
        self.last_lines = len(lines)


# ==============================================================================
# Main IP Exit Enumeration Class
# ==============================================================================
class IPExitEnumerator:
    """
    Main class that orchestrates IP discovery across multiple services and protocols.
    
    Supports both IPv4 and IPv6 discovery through:
    - HTTP/HTTPS services that return client IP
    - UDP STUN servers for NAT traversal IP discovery
    """
    
    def __init__(self, verbose: bool = False):
        self.verbose = verbose
        self.results = LiveResults()
        self.display = ProgressDisplay()
        self.session: Optional[aiohttp.ClientSession] = None
        self.interrupted = False
        self.sequence_rng = random.Random(42)  # Deterministic ordering for reproducibility
        self.http_samples = 3
        self.udp_samples = 2
        self.sample_round_delay = 0.3
        self.request_delay = 0.1

        # Set up signal handler for graceful interruption
        signal.signal(signal.SIGINT, self.signal_handler)

        # HTTP/HTTPS IP discovery services
        self.http_services = [
            # Primary IPv4 services
            ServiceConfig("ipify", "https://api.ipify.org", "HTTP"),
            ServiceConfig("httpbin", "https://httpbin.org/ip", "HTTP", 
                         extract_method="json", extract_field="origin"),
            ServiceConfig("icanhazip", "https://icanhazip.com", "HTTP"),
            ServiceConfig("jsonip", "https://jsonip.com", "HTTP", 
                         extract_method="json", extract_field="ip"),
            ServiceConfig("ipecho", "http://ipecho.net/plain", "HTTP"),
            ServiceConfig("myip", "https://api.myip.com", "HTTP", 
                         extract_method="json", extract_field="ip"),
            
            # IPv4-specific endpoints
            ServiceConfig("icanhazip-ipv4", "https://ipv4.icanhazip.com", "HTTP"),
            ServiceConfig("seeip-ipv4", "https://ipv4.seeip.org", "HTTP"),

            # IPv6-specific endpoints
            ServiceConfig("ipify-v6", "https://api6.ipify.org", "HTTP"),
            ServiceConfig("icanhazip-ipv6", "https://ipv6.icanhazip.com", "HTTP"),
            ServiceConfig("seeip-ipv6", "https://ipv6.seeip.org", "HTTP"),
        ]

        # STUN (Session Traversal Utilities for NAT) services
        # These help discover the public IP behind NAT/firewalls
        self.udp_services = [
            # IPv4 STUN servers
            ServiceConfig("stun-google-v4", "stun.l.google.com:19302", "UDP-STUN", 
                         socket_family=socket.AF_INET),
            ServiceConfig("stun-cloudflare-v4", "stun.cloudflare.com:3478", "UDP-STUN", 
                         socket_family=socket.AF_INET),

            # IPv6 STUN servers
            ServiceConfig("stun-google-v6", "stun.l.google.com:19302", "UDP-STUN6", 
                         socket_family=socket.AF_INET6),
            ServiceConfig("stun-cloudflare-v6", "stun.cloudflare.com:3478", "UDP-STUN6", 
                         socket_family=socket.AF_INET6),
        ]

    def signal_handler(self, signum, frame):
        """Handle SIGINT (Ctrl+C) gracefully."""
        print(f"\n{Colors.WARNING}Interrupted by user. Generating report from current results...{Colors.ENDC}")
        self.interrupted = True

    def update_confidence(self):
        """
        Calculate confidence level based on multiple factors:
        - Success rate of tests
        - Number of successful tests
        - Protocol diversity
        - Result consistency
        """
        total = self.results.tests_completed
        if not total:
            self.results.confidence_level = "Unknown"
            return

        success_rate = sum(1 for r in self.results.results if r.success) / total
        unique_protocols = sum(1 for counter in self.results.protocol_ips.values() if counter)
        family_counters = [counter for counter in self.results.family_ips.values() if counter]

        score = 0
        
        # Success rate component (0–40 points)
        if success_rate >= 0.95:
            score += 40
        elif success_rate >= 0.85:
            score += 32
        elif success_rate >= 0.70:
            score += 24
        elif success_rate >= 0.50:
            score += 16
        else:
            score += 8

        # Successful test count component (0–25 points)
        successful_tests = sum(1 for r in self.results.results if r.success)
        if successful_tests >= 15:
            score += 25
        elif successful_tests >= 10:
            score += 20
        elif successful_tests >= 7:
            score += 15
        elif successful_tests >= 5:
            score += 10
        else:
            score += 5

        # Protocol diversity component (0–15 points)
        if unique_protocols >= 3:
            score += 15
        elif unique_protocols >= 2:
            score += 10
        else:
            score += 5

        # Consistency component (0–20 points)
        if family_counters:
            if all(len(counter) == 1 for counter in family_counters):
                min_hits = min(counter.most_common(1)[0][1] for counter in family_counters)
                if min_hits >= 5:
                    score += 20
                elif min_hits >= 3:
                    score += 15
                else:
                    score += 10
            elif all(all(count >= 2 for count in counter.values()) for counter in family_counters):
                score += 15  # Multiple IPs but each is seen repeatedly
        # else: 0 points for inconsistent or sparse results

        # Map score to confidence label
        if score >= 85:
            self.results.confidence_level = "Very High"
        elif score >= 70:
            self.results.confidence_level = "High"
        elif score >= 55:
            self.results.confidence_level = "Medium-High"
        elif score >= 40:
            self.results.confidence_level = "Medium"
        elif score >= 25:
            self.results.confidence_level = "Low-Medium"
        else:
            self.results.confidence_level = "Low"

        # Add score in verbose mode
        if self.verbose:
            self.results.confidence_level += f" (score={score}/100)"

    def extract_ips(self, text: str, method: str, field: Optional[str] = None) -> List[str]:
        """Extract all public IP addresses from a service response."""

        def tokens_from_value(value) -> List[str]:
            if isinstance(value, str):
                return re.split(r'[\s,]+', value.strip())
            if isinstance(value, list):
                tokens: List[str] = []
                for item in value:
                    tokens.extend(tokens_from_value(item))
                return tokens
            return [str(value)]

        try:
            if method == "json" and field:
                payload = json.loads(text)
                value = payload.get(field)
                raw_tokens = tokens_from_value(value) if value is not None else []
            else:
                raw_tokens = re.split(r'[\s,]+', text.strip())
        except Exception:
            return []

        ips: List[str] = []
        for token in raw_tokens:
            candidate = token.strip()
            if not candidate:
                continue
            try:
                ip_obj = ipaddress.ip_address(candidate)
            except ValueError:
                continue

            if not self.is_public_ip_obj(ip_obj):
                continue

            normalized = str(ip_obj)
            if normalized not in ips:
                ips.append(normalized)

        return ips

    @staticmethod
    def is_public_ip(ip: str) -> bool:
        """Return True if the string is a valid public IP address."""
        try:
            return IPExitEnumerator.is_public_ip_obj(ipaddress.ip_address(ip))
        except ValueError:
            return False

    @staticmethod
    def is_public_ip_obj(ip_obj) -> bool:
        """Return True if the ipaddress object represents a global address."""
        return ip_obj.is_global

    async def test_http_service(self, service: ServiceConfig, attempt: int) -> Optional[TestResult]:
        """
        Test an HTTP/HTTPS service for IP discovery.
        
        Args:
            service: Service configuration
            
        Returns:
            TestResult with discovered IP or error information
        """
        start = time.time()
        try:
            timeout = aiohttp.ClientTimeout(total=service.timeout)
            async with self.session.get(service.url, timeout=timeout) as r:
                body = await r.text()
                ips = self.extract_ips(body, service.extract_method, service.extract_field)

                return TestResult(
                    service.name,
                    service.protocol,
                    ips,
                    time.time(),
                    (time.time() - start) * 1000,
                    bool(ips),
                    attempt,
                    None if ips else "No public IP found"
                )
        except Exception as e:
            return TestResult(
                service.name,
                service.protocol,
                [],
                time.time(),
                (time.time() - start) * 1000,
                False,
                attempt,
                str(e)
            )

    async def test_udp_stun(self, service: ServiceConfig, attempt: int) -> Optional[TestResult]:
        """
        Test a STUN server for IP discovery via UDP.
        
        STUN (Session Traversal Utilities for NAT) protocol is used to discover
        the public IP address and port allocated by a NAT for UDP connections.
        
        Args:
            service: STUN service configuration
            
        Returns:
            TestResult with discovered IP or error information
        """
        start = time.time()
        try:
            # Parse hostname and port
            host, port_str = service.url.rsplit(':', 1)
            port = int(port_str)

            # Generate random 12-byte transaction ID for STUN request
            transaction_id = os.urandom(12)
            
            # Build STUN binding request packet
            # Format: Message Type (2) + Message Length (2) + Magic Cookie (4) + Transaction ID (12)
            stun_req = b'\x00\x01\x00\x00\x21\x12\xa4\x42' + transaction_id
            
            # Create UDP socket with appropriate family (IPv4/IPv6)
            sock = socket.socket(service.socket_family, socket.SOCK_DGRAM)
            sock.settimeout(service.timeout)

            loop = asyncio.get_running_loop()
            try:
                # Send STUN request and wait for response
                await loop.run_in_executor(None, sock.sendto, stun_req, (host, port))
                data, _ = await loop.run_in_executor(None, sock.recvfrom, 1024)
            finally:
                sock.close()

            # Validate STUN response format
            if len(data) < 20 or data[0:2] != b'\x01\x01':  # Success response type
                return TestResult(
                    service.name,
                    service.protocol,
                    [],
                    time.time(),
                    (time.time() - start) * 1000,
                    False,
                    attempt,
                    "Invalid STUN response"
                )

            # Parse STUN attributes to find XOR-MAPPED-ADDRESS
            i = 20  # Skip STUN header
            discovered_ips: List[str] = []
            while i + 4 <= len(data):
                attr_type = int.from_bytes(data[i:i + 2], 'big')
                attr_len = int.from_bytes(data[i + 2:i + 4], 'big')
                
                if i + 4 + attr_len > len(data):
                    break
                
                # Look for XOR-MAPPED-ADDRESS attribute (0x0020)
                if attr_type == 0x0020:
                    if attr_len < 8:
                        i += 4 + attr_len
                        continue
                    
                    # Parse address family
                    family = int.from_bytes(data[i + 5:i + 6], 'big')

                    if family == 0x01 and attr_len >= 8:  # IPv4
                        ip_bytes = data[i + 8:i + 12]
                        magic_cookie = b'\x21\x12\xa4\x42'
                        ip_xor = bytes(a ^ b for a, b in zip(ip_bytes, magic_cookie))
                        ip = socket.inet_ntoa(ip_xor)
                        if self.is_public_ip(ip):
                            discovered_ips.append(ip)

                    elif family == 0x02 and attr_len >= 20:  # IPv6
                        # For IPv6, XOR with magic cookie + transaction ID
                        ip_bytes = data[i + 8:i + 24]
                        xor_key = b'\x21\x12\xa4\x42' + transaction_id
                        ip_xor = bytes(a ^ b for a, b in zip(ip_bytes, xor_key))
                        ip = socket.inet_ntop(socket.AF_INET6, ip_xor)
                        if self.is_public_ip(ip):
                            discovered_ips.append(ip)
                
                # Move to next attribute (attributes are padded to 4-byte boundaries)
                attr_len_padded = (attr_len + 3) & ~3  # Round up to multiple of 4
                i += 4 + attr_len_padded

            if discovered_ips:
                return TestResult(
                    service.name,
                    service.protocol,
                    discovered_ips,
                    time.time(),
                    (time.time() - start) * 1000,
                    True,
                    attempt
                )

            return TestResult(
                service.name,
                service.protocol,
                [],
                time.time(),
                (time.time() - start) * 1000,
                False,
                attempt,
                "No mapped address found in STUN response"
            )
            
        except Exception as e:
            return TestResult(
                service.name,
                service.protocol,
                [],
                time.time(),
                (time.time() - start) * 1000,
                False,
                attempt,
                str(e)
            )

    async def run_batch(self, services: List[ServiceConfig], tester, phase: str, attempt: int):
        """Execute a batch of tests sequentially with live progress updates."""
        self.results.current_phase = phase
        for service in services:
            if self.interrupted:
                break

            result = await tester(service, attempt)
            self.results.tests_completed += 1

            if result:
                # Store result and update statistics
                self.results.results.append(result)
                if result.success and result.ips:
                    for ip in result.ips:
                        self.results.ips_found[ip] += 1
                        self.results.protocol_ips[result.protocol][ip] += 1

                        try:
                            family = "IPv6" if ipaddress.ip_address(ip).version == 6 else "IPv4"
                        except ValueError:
                            family = "Unknown"

                        if family != "Unknown":
                            self.results.family_ips[family][ip] += 1

                self.results.service_status[result.service] = "success" if result.success else "failed"

            # Update confidence and refresh display
            self.update_confidence()
            self.display.render_live_results(self.results)

            # Small delay to make progress visible
            await asyncio.sleep(self.request_delay)

    async def discover_ips(self):
        """
        Main discovery process - tests all configured services.
        """
        # Set up HTTP session with connection limits
        connector = aiohttp.TCPConnector(limit=10)
        self.session = aiohttp.ClientSession(connector=connector)
        
        try:
            # Calculate total tests for progress tracking
            self.results.tests_total = (
                len(self.http_services) * self.http_samples +
                len(self.udp_services) * self.udp_samples
            )

            # Run HTTP/HTTPS samples
            for attempt in range(1, self.http_samples + 1):
                services = list(self.http_services)
                self.sequence_rng.shuffle(services)
                phase = f"HTTP(S) Discovery – sample {attempt}/{self.http_samples}"
                await self.run_batch(services, self.test_http_service, phase, attempt)

                if self.interrupted:
                    break

                if attempt < self.http_samples:
                    await asyncio.sleep(self.sample_round_delay)

            # Run STUN samples if not interrupted
            if not self.interrupted:
                for attempt in range(1, self.udp_samples + 1):
                    services = list(self.udp_services)
                    self.sequence_rng.shuffle(services)
                    phase = f"UDP-STUN Discovery – sample {attempt}/{self.udp_samples}"
                    await self.run_batch(services, self.test_udp_stun, phase, attempt)

                    if self.interrupted:
                        break

                    if attempt < self.udp_samples:
                        await asyncio.sleep(self.sample_round_delay)

        finally:
            if self.session:
                await self.session.close()

    def generate_report(self):
        """Generate and display final results report."""
        self.display.clear_previous()
        
        # Report header
        print(f"\n{Colors.HEADER}{Colors.BOLD}{'='*70}")
        print("🎯 IP EXIT ENUMERATION – DUAL-STACK FINAL REPORT")
        print(f"{'='*70}{Colors.ENDC}")
        
        # Summary statistics
        elapsed = time.time() - self.results.start_time
        successful = sum(1 for r in self.results.results if r.success)
        print(f"{Colors.OKCYAN}Elapsed: {elapsed:.1f}s | Total tests: {self.results.tests_completed} | Success: {successful}{Colors.ENDC}\n")
        
        # Main results
        family_counters = {family: counter for family, counter in self.results.family_ips.items() if counter}
        if not family_counters:
            print(f"{Colors.FAIL}❌ No public IPs discovered{Colors.ENDC}")
            return

        print(f"{Colors.BOLD}📊 Discovered IPs:{Colors.ENDC}")
        for family in ("IPv4", "IPv6"):
            counter = family_counters.get(family)
            if not counter:
                continue

            print(f" {family}:")
            total_hits = sum(counter.values())
            for ip, cnt in counter.most_common():
                pct = (cnt / total_hits * 100) if total_hits else 0
                print(f"   {Colors.OKGREEN}{ip:<39}{Colors.ENDC} ({cnt} hits, {pct:.1f}%)")

            if len(counter) > 1:
                print(f"   {Colors.WARNING}🔄 {family} load balancing across {len(counter)} IPs{Colors.ENDC}")
            else:
                print(f"   {Colors.OKGREEN}📍 {family} single egress IP{Colors.ENDC}")

            print()

        print(f"{Colors.OKCYAN}Confidence: {self.results.confidence_level}{Colors.ENDC}")

        # Verbose details if requested
        if self.verbose:
            self.print_verbose()

    def print_verbose(self):
        """Print detailed results for each test (verbose mode)."""
        print("\n📋 Detailed results:")
        for r in self.results.results:
            status = "✓" if r.success else "✗"
            ips_display = ', '.join(r.ips) if r.ips else "-"
            print(
                f"   {status} {r.service:<25} | {r.protocol:<10} | #{r.attempt:<2} | "
                f"{ips_display:<45} | {r.latency_ms:>7.1f}ms"
            )


# ==============================================================================
# Main Entry Point
# ==============================================================================
async def main():
    """Main function - parse arguments and run discovery."""
    parser = argparse.ArgumentParser(
        description="Discover IPv4/IPv6 egress addresses through multiple services and protocols."
    )
    parser.add_argument("-v", "--verbose", action="store_true", 
                       help="Show detailed results for each test")
    parser.add_argument("-q", "--quiet", action="store_true", 
                       help="Minimal output (not yet implemented)")
    
    args = parser.parse_args()
    
    # Validate argument combinations
    if args.quiet and args.verbose:
        print("Error: Choose either --quiet or --verbose, not both")
        return
    
    # Create enumerator and run discovery
    enum = IPExitEnumerator(verbose=args.verbose)
    try:
        await enum.discover_ips()
    except KeyboardInterrupt:
        pass  # Handled by signal handler
    
    # Always generate final report
    enum.generate_report()


if __name__ == "__main__":
    # Check for required dependencies
    try:
        import aiohttp
    except ImportError:
        print("Error: Required dependency missing. Install with: pip3 install aiohttp")
        sys.exit(1)
    
    # Run the main async function
    asyncio.run(main())
