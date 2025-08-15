#!/usr/bin/env python3
"""
IP Exit Enumeration Tool
Discovers all public IP addresses used by the system for outbound connections.
"""

import asyncio
import aiohttp
import socket
import time
import json
import sys
import signal
from collections import defaultdict, Counter
from dataclasses import dataclass, field
from typing import Dict, List, Set, Optional, Tuple
from datetime import datetime
import argparse

# Terminal colors and formatting
class Colors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    
    # Progress bar colors
    PROGRESS_COMPLETE = '\033[42m'  # Green background
    PROGRESS_PARTIAL = '\033[43m'   # Yellow background
    PROGRESS_EMPTY = '\033[47m'     # White background

@dataclass
class TestResult:
    service: str
    protocol: str
    ip: str
    timestamp: float
    latency_ms: float
    success: bool
    error: Optional[str] = None

@dataclass
class ServiceConfig:
    name: str
    url: str
    protocol: str
    timeout: int = 5
    extract_method: str = 'text'  # 'text', 'json', 'headers'
    extract_field: Optional[str] = None

@dataclass
class LiveResults:
    results: List[TestResult] = field(default_factory=list)
    ips_found: Counter = field(default_factory=Counter)
    protocol_ips: Dict[str, Counter] = field(default_factory=lambda: defaultdict(Counter))
    service_status: Dict[str, str] = field(default_factory=dict)
    start_time: float = field(default_factory=time.time)
    tests_completed: int = 0
    tests_total: int = 0
    current_phase: str = "Initializing"
    confidence_level: str = "Unknown"
    load_balancing_detected: bool = False

class ProgressDisplay:
    def __init__(self):
        self.last_lines = 0
        
    def clear_previous(self):
        if self.last_lines > 0:
            # Move cursor up and clear lines
            print(f'\033[{self.last_lines}A\033[J', end='')
        
    def progress_bar(self, completed: int, total: int, width: int = 40) -> str:
        if total == 0:
            return f"[{' ' * width}] 0/0"
            
        percentage = completed / total
        filled = int(width * percentage)
        
        bar = Colors.PROGRESS_COMPLETE + ' ' * filled + Colors.ENDC
        bar += Colors.PROGRESS_EMPTY + ' ' * (width - filled) + Colors.ENDC
        
        return f"[{bar}] {completed}/{total} ({percentage*100:.1f}%)"
    
    def format_ip_list(self, ip_counter: Counter, total_tests: int) -> List[str]:
        lines = []
        for ip, count in ip_counter.most_common():
            percentage = (count / total_tests * 100) if total_tests > 0 else 0
            confidence_color = Colors.OKGREEN if count >= 3 else Colors.WARNING if count >= 2 else Colors.FAIL
            lines.append(f"   {confidence_color}✓ {ip:<15}{Colors.ENDC} ({count} hits, {percentage:.1f}%)")
        return lines
    
    def render_live_results(self, results: LiveResults):
        self.clear_previous()
        
        lines = []
        elapsed = time.time() - results.start_time
        
        # Header
        lines.append(f"{Colors.HEADER}{Colors.BOLD}🔍 IP Exit Discovery - Live Results{Colors.ENDC}")
        lines.append(f"{Colors.OKCYAN}Phase: {results.current_phase} | Elapsed: {elapsed:.1f}s{Colors.ENDC}")
        lines.append("")
        
        # Progress bar
        progress = self.progress_bar(results.tests_completed, results.tests_total)
        lines.append(f"Overall Progress: {progress}")
        lines.append("")
        
        # Current findings
        if results.ips_found:
            lines.append(f"{Colors.BOLD}📊 IPs Discovered:{Colors.ENDC}")
            lines.extend(self.format_ip_list(results.ips_found, results.tests_completed))
            lines.append("")
            
            # Analysis
            num_ips = len(results.ips_found)
            if num_ips > 1:
                lines.append(f"{Colors.WARNING}🔄 Load Balancing: DETECTED ({num_ips} different IPs){Colors.ENDC}")
                results.load_balancing_detected = True
            else:
                lines.append(f"{Colors.OKGREEN}📍 Single IP: Consistent egress point{Colors.ENDC}")
            
            lines.append(f"{Colors.OKCYAN}📈 Confidence: {results.confidence_level}{Colors.ENDC}")
            lines.append("")
        else:
            lines.append(f"{Colors.WARNING}⏳ Discovering IPs...{Colors.ENDC}")
            lines.append("")
        
        # Protocol breakdown (if we have multiple protocols)
        if len(results.protocol_ips) > 1:
            lines.append(f"{Colors.BOLD}🔧 Protocol Breakdown:{Colors.ENDC}")
            for protocol, ip_counter in results.protocol_ips.items():
                lines.append(f"   {Colors.OKBLUE}{protocol}:{Colors.ENDC}")
                for ip, count in ip_counter.most_common(3):  # Top 3 IPs per protocol
                    lines.append(f"      {ip} ({count} hits)")
            lines.append("")
        
        # Service status
        if results.service_status:
            lines.append(f"{Colors.BOLD}🌐 Service Status:{Colors.ENDC}")
            for service, status in results.service_status.items():
                if status == "success":
                    lines.append(f"   {Colors.OKGREEN}✓{Colors.ENDC} {service}")
                elif status == "failed":
                    lines.append(f"   {Colors.FAIL}✗{Colors.ENDC} {service}")
                else:
                    lines.append(f"   {Colors.WARNING}⏳{Colors.ENDC} {service}")
            lines.append("")
        
        # Print all lines
        for line in lines:
            print(line)
        
        self.last_lines = len(lines)

class IPExitEnumerator:
    def __init__(self, verbose: bool = False):
        self.verbose = verbose
        self.results = LiveResults()
        self.display = ProgressDisplay()
        self.session: Optional[aiohttp.ClientSession] = None
        self.interrupted = False
        
        # Service configurations
        self.http_services = [
            ServiceConfig("ipify", "https://api.ipify.org", "HTTP"),
            ServiceConfig("httpbin", "https://httpbin.org/ip", "HTTP", extract_method="json", extract_field="origin"),
            ServiceConfig("icanhazip", "https://icanhazip.com", "HTTP"),
            ServiceConfig("jsonip", "https://jsonip.com", "HTTP", extract_method="json", extract_field="ip"),
            ServiceConfig("ipecho", "http://ipecho.net/plain", "HTTP"),
            ServiceConfig("myip", "https://api.myip.com", "HTTP", extract_method="json", extract_field="ip"),
            ServiceConfig("icanhazip-ipv4", "https://ipv4.icanhazip.com", "HTTP"),
            ServiceConfig("seeip-ipv4", "https://ipv4.seeip.org", "HTTP"),
        ]
        
        # UDP-based services for testing different protocols
        self.udp_services = [
            ServiceConfig("stun-google", "stun.l.google.com:19302", "UDP-STUN"),
            ServiceConfig("stun-cloudflare", "stun.cloudflare.com:3478", "UDP-STUN"),
        ]
        
        # Signal handling
        signal.signal(signal.SIGINT, self.signal_handler)
        
    def signal_handler(self, signum, frame):
        print(f"\n{Colors.WARNING}Interrupted by user. Generating report from current results...{Colors.ENDC}")
        self.interrupted = True
    
    def update_confidence(self):
        """Update confidence level based on multiple factors."""
        total_tests = self.results.tests_completed
        successful_tests = sum(1 for r in self.results.results if r.success)
        
        if total_tests == 0:
            self.results.confidence_level = "Unknown"
            return
            
        success_rate = successful_tests / total_tests
        unique_ips = len(self.results.ips_found)
        unique_protocols = len(self.results.protocol_ips)
        
        # Calculate base confidence score (0-100)
        confidence_score = 0
        
        # Factor 1: Success rate (0-40 points)
        if success_rate >= 0.95:
            confidence_score += 40
        elif success_rate >= 0.85:
            confidence_score += 32
        elif success_rate >= 0.70:
            confidence_score += 24
        elif success_rate >= 0.50:
            confidence_score += 16
        else:
            confidence_score += 8
        
        # Factor 2: Number of successful tests (0-25 points)
        if successful_tests >= 15:
            confidence_score += 25
        elif successful_tests >= 10:
            confidence_score += 20
        elif successful_tests >= 7:
            confidence_score += 15
        elif successful_tests >= 5:
            confidence_score += 10
        else:
            confidence_score += 5
        
        # Factor 3: Protocol diversity (0-15 points)
        if unique_protocols >= 3:
            confidence_score += 15
        elif unique_protocols >= 2:
            confidence_score += 10
        else:
            confidence_score += 5
        
        # Factor 4: Pattern consistency (0-20 points)
        if unique_ips > 0:
            most_common_ip_count = self.results.ips_found.most_common(1)[0][1]
            if unique_ips == 1:
                # Single IP with multiple confirmations
                if most_common_ip_count >= 5:
                    confidence_score += 20
                elif most_common_ip_count >= 3:
                    confidence_score += 15
                else:
                    confidence_score += 10
            else:
                # Multiple IPs - check if each has multiple confirmations
                min_confirmations = min(self.results.ips_found.values())
                avg_confirmations = sum(self.results.ips_found.values()) / unique_ips
                
                if min_confirmations >= 3 and avg_confirmations >= 4:
                    confidence_score += 20  # All IPs well-confirmed
                elif min_confirmations >= 2 and avg_confirmations >= 3:
                    confidence_score += 15  # Good confirmation pattern
                elif min_confirmations >= 2:
                    confidence_score += 10  # Decent confirmation
                else:
                    confidence_score += 5   # Some IPs only seen once
        
        # Convert score to confidence level
        if confidence_score >= 85:
            self.results.confidence_level = "Very High"
        elif confidence_score >= 70:
            self.results.confidence_level = "High" 
        elif confidence_score >= 55:
            self.results.confidence_level = "Medium-High"
        elif confidence_score >= 40:
            self.results.confidence_level = "Medium"
        elif confidence_score >= 25:
            self.results.confidence_level = "Low-Medium"
        else:
            self.results.confidence_level = "Low"
        
        # Add details for verbose mode
        if hasattr(self, 'verbose') and self.verbose:
            details = f" (Score: {confidence_score}/100, Success: {success_rate:.1%}, Tests: {successful_tests}, Protocols: {unique_protocols}, IPs: {unique_ips})"
            self.results.confidence_level += details
    
    def extract_ip_from_response(self, response_text: str, method: str, field: Optional[str] = None) -> Optional[str]:
        """Extract IP address from service response."""
        try:
            if method == "json" and field:
                data = json.loads(response_text)
                ip = data.get(field, "").strip()
                # Handle cases like "203.0.113.1, 203.0.113.2" (multiple IPs)
                if "," in ip:
                    ip = ip.split(",")[0].strip()
                return ip if self.is_public_ip(ip) else None
            else:
                # Text method - extract first IP-like string
                import re
                ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
                matches = re.findall(ip_pattern, response_text)
                for ip in matches:
                    if self.is_public_ip(ip):
                        return ip
                return None
        except Exception:
            return None
    
    def is_public_ip(self, ip: str) -> bool:
        """Check if IP address is public (not private/reserved)."""
        try:
            import ipaddress
            ip_obj = ipaddress.ip_address(ip)
            return not (ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_reserved)
        except ValueError:
            return False
    
    async def test_http_service(self, service: ServiceConfig) -> Optional[TestResult]:
        """Test a single HTTP service to get external IP."""
        start_time = time.time()
        
        try:
            timeout = aiohttp.ClientTimeout(total=service.timeout)
            async with self.session.get(service.url, timeout=timeout) as response:
                response_text = await response.text()
                latency = (time.time() - start_time) * 1000
                
                ip = self.extract_ip_from_response(response_text, service.extract_method, service.extract_field)
                
                if ip:
                    return TestResult(
                        service=service.name,
                        protocol=service.protocol,
                        ip=ip,
                        timestamp=time.time(),
                        latency_ms=latency,
                        success=True
                    )
                else:
                    return TestResult(
                        service=service.name,
                        protocol=service.protocol,
                        ip="",
                        timestamp=time.time(),
                        latency_ms=latency,
                        success=False,
                        error="Could not extract valid IP"
                    )
                    
        except Exception as e:
            latency = (time.time() - start_time) * 1000
            return TestResult(
                service=service.name,
                protocol=service.protocol,
                ip="",
                timestamp=time.time(),
                latency_ms=latency,
                success=False,
                error=str(e)
            )
    
    async def test_udp_stun(self, service: ServiceConfig) -> Optional[TestResult]:
        """Test UDP STUN server to get external IP."""
        start_time = time.time()
        
        try:
            host, port = service.url.split(':')
            port = int(port)
            
            # Create STUN binding request packet
            stun_request = b'\x00\x01\x00\x00\x21\x12\xa4\x42' + b'\x00' * 12
            
            # Create UDP socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(service.timeout)
            
            try:
                # Send STUN request
                await asyncio.get_event_loop().run_in_executor(
                    None, sock.sendto, stun_request, (host, port)
                )
                
                # Receive response
                data, addr = await asyncio.get_event_loop().run_in_executor(
                    None, sock.recvfrom, 1024
                )
                
                latency = (time.time() - start_time) * 1000
                
                # Parse STUN response for IP address
                if len(data) >= 20 and data[0:2] == b'\x01\x01':  # Success response
                    # Look for XOR-MAPPED-ADDRESS attribute (0x0020)
                    i = 20  # Skip STUN header
                    while i < len(data) - 8:
                        attr_type = int.from_bytes(data[i:i+2], 'big')
                        attr_len = int.from_bytes(data[i+2:i+4], 'big')
                        
                        if attr_type == 0x0020 and attr_len >= 8:  # XOR-MAPPED-ADDRESS
                            # Extract IP (XOR with magic cookie)
                            ip_bytes = data[i+8:i+12]
                            magic_cookie = b'\x21\x12\xa4\x42'
                            ip_bytes = bytes(a ^ b for a, b in zip(ip_bytes, magic_cookie))
                            ip = '.'.join(str(b) for b in ip_bytes)
                            
                            if self.is_public_ip(ip):
                                return TestResult(
                                    service=service.name,
                                    protocol=service.protocol,
                                    ip=ip,
                                    timestamp=time.time(),
                                    latency_ms=latency,
                                    success=True
                                )
                        i += 4 + attr_len
                
                return TestResult(
                    service=service.name,
                    protocol=service.protocol,
                    ip="",
                    timestamp=time.time(),
                    latency_ms=latency,
                    success=False,
                    error="Could not parse STUN response"
                )
                
            finally:
                sock.close()
                
        except Exception as e:
            latency = (time.time() - start_time) * 1000
            return TestResult(
                service=service.name,
                protocol=service.protocol,
                ip="",
                timestamp=time.time(),
                latency_ms=latency,
                success=False,
                error=str(e)
            )
    
    async def run_test_batch(self, test_coros, phase_name: str):
        """Run a batch of tests with live progress updates."""
        self.results.current_phase = phase_name
        
        for i, coro in enumerate(test_coros):
            if self.interrupted:
                break
                
            result = await coro
            
            if result:
                self.results.results.append(result)
                
                if result.success and result.ip:
                    self.results.ips_found[result.ip] += 1
                    self.results.protocol_ips[result.protocol][result.ip] += 1
                
                self.results.service_status[result.service] = "success" if result.success else "failed"
                self.results.tests_completed += 1
                
                self.update_confidence()
                self.display.render_live_results(self.results)
                
                # Small delay to make progress visible
                await asyncio.sleep(0.1)
    
    async def discover_ips(self):
        """Main discovery process with progressive display."""
        connector = aiohttp.TCPConnector(limit=10)  # Limit concurrent connections
        self.session = aiohttp.ClientSession(connector=connector)
        
        try:
            # Calculate total tests  
            self.results.tests_total = len(self.http_services) * 2 + len(self.udp_services)
            
            # Phase 1: Quick HTTP discovery
            http_coros = [self.test_http_service(service) for service in self.http_services[:4]]
            await self.run_test_batch(http_coros, "Quick HTTP Discovery")
            
            if self.interrupted:
                return
            
            # Phase 2: UDP/STUN testing
            udp_coros = [self.test_udp_stun(service) for service in self.udp_services]
            await self.run_test_batch(udp_coros, "UDP/STUN Testing")
            
            if self.interrupted:
                return
                
            # Phase 3: Extended HTTP testing
            extended_http_coros = [self.test_http_service(service) for service in self.http_services[4:]]
            await self.run_test_batch(extended_http_coros, "Extended HTTP Testing")
            
            if self.interrupted:
                return
                
            # Phase 4: Verification round (retest some services)
            verification_coros = [self.test_http_service(service) for service in self.http_services[:3]]
            await self.run_test_batch(verification_coros, "Verification Round")
            
        finally:
            if self.session:
                await self.session.close()
    
    def generate_final_report(self):
        """Generate the final comprehensive report."""
        self.display.clear_previous()
        
        print(f"\n{Colors.HEADER}{Colors.BOLD}{'='*60}")
        print(f"🎯 IP EXIT ENUMERATION - FINAL REPORT")
        print(f"{'='*60}{Colors.ENDC}")
        
        elapsed = time.time() - self.results.start_time
        print(f"{Colors.OKCYAN}Scan completed in {elapsed:.1f} seconds")
        print(f"Total tests: {self.results.tests_completed}")
        print(f"Successful tests: {sum(1 for r in self.results.results if r.success)}{Colors.ENDC}\n")
        
        if not self.results.ips_found:
            print(f"{Colors.FAIL}❌ No external IPs discovered!{Colors.ENDC}")
            print(f"{Colors.WARNING}This might indicate network connectivity issues.{Colors.ENDC}")
            return
        
        # IP Summary
        print(f"{Colors.BOLD}📊 DISCOVERED EXTERNAL IPs:{Colors.ENDC}")
        total_hits = sum(self.results.ips_found.values())
        for i, (ip, count) in enumerate(self.results.ips_found.most_common(), 1):
            percentage = (count / total_hits * 100)
            print(f"   {Colors.OKGREEN}{i}. {ip:<15}{Colors.ENDC} ({count} hits, {percentage:.1f}%)")
        
        print(f"\n{Colors.BOLD}🔍 LOAD BALANCING ANALYSIS:{Colors.ENDC}")
        num_ips = len(self.results.ips_found)
        
        if num_ips == 1:
            print(f"   {Colors.OKGREEN}✓ Single egress IP detected{Colors.ENDC}")
            print(f"   {Colors.OKCYAN}→ Your network uses a consistent external IP address{Colors.ENDC}")
        else:
            print(f"   {Colors.WARNING}🔄 Multiple egress IPs detected ({num_ips} different IPs){Colors.ENDC}")
            print(f"   {Colors.OKCYAN}→ Your network appears to use load balancing or multiple exit points{Colors.ENDC}")
            
            # Distribution analysis
            most_common_count = self.results.ips_found.most_common(1)[0][1]
            if most_common_count / total_hits > 0.8:
                print(f"   {Colors.WARNING}→ Primary IP with some secondary routing{Colors.ENDC}")
            else:
                print(f"   {Colors.WARNING}→ Active load balancing across multiple IPs{Colors.ENDC}")
        
        # Protocol breakdown
        if len(self.results.protocol_ips) > 1:
            print(f"\n{Colors.BOLD}🔧 PROTOCOL BREAKDOWN:{Colors.ENDC}")
            for protocol in sorted(self.results.protocol_ips.keys()):
                ip_counter = self.results.protocol_ips[protocol]
                print(f"   {Colors.OKBLUE}{protocol}:{Colors.ENDC}")
                for ip, count in ip_counter.most_common():
                    total_protocol = sum(ip_counter.values())
                    pct = (count / total_protocol * 100) if total_protocol > 0 else 0
                    print(f"      {ip} ({count}/{total_protocol}, {pct:.1f}%)")
        
        # Recommendations
        print(f"\n{Colors.BOLD}💡 RECOMMENDATIONS:{Colors.ENDC}")
        if num_ips == 1:
            ip = list(self.results.ips_found.keys())[0]
            print(f"   • Use {Colors.OKGREEN}{ip}{Colors.ENDC} for firewall allowlist rules")
            print(f"   • Network configuration appears consistent")
        else:
            print(f"   • Consider all {num_ips} IPs for firewall allowlist rules:")
            for ip in self.results.ips_found.keys():
                print(f"     - {Colors.WARNING}{ip}{Colors.ENDC}")
            print(f"   • Review load balancer/proxy configuration if unexpected")
            print(f"   • Monitor for time-based IP rotation patterns")
        
        print(f"\n{Colors.OKCYAN}Confidence Level: {self.results.confidence_level}{Colors.ENDC}")
        
        if self.verbose:
            self.print_verbose_details()
    
    def print_verbose_details(self):
        """Print detailed test results for verbose mode."""
        print(f"\n{Colors.BOLD}📋 DETAILED TEST RESULTS:{Colors.ENDC}")
        
        successful_tests = [r for r in self.results.results if r.success]
        failed_tests = [r for r in self.results.results if not r.success]
        
        if successful_tests:
            print(f"\n{Colors.OKGREEN}✓ Successful Tests ({len(successful_tests)}):{Colors.ENDC}")
            for result in successful_tests:
                print(f"   {result.service:<20} | {result.protocol:<5} | {result.ip:<15} | {result.latency_ms:>6.1f}ms")
        
        if failed_tests:
            print(f"\n{Colors.FAIL}✗ Failed Tests ({len(failed_tests)}):{Colors.ENDC}")
            for result in failed_tests:
                print(f"   {result.service:<20} | {result.protocol:<5} | Error: {result.error}")

async def main():
    parser = argparse.ArgumentParser(
        description="Discover all public IP addresses used by your system for outbound connections",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 ip_exit_enum.py                 # Standard scan with live progress
  python3 ip_exit_enum.py --verbose       # Detailed output with test results
  python3 ip_exit_enum.py --quiet         # Minimal output, final results only
        """
    )
    
    parser.add_argument('-v', '--verbose', action='store_true',
                       help='Show detailed test results and timing information')
    parser.add_argument('-q', '--quiet', action='store_true',
                       help='Suppress live progress, show only final results')
    
    args = parser.parse_args()
    
    if args.quiet and args.verbose:
        print("Error: --quiet and --verbose cannot be used together")
        sys.exit(1)
    
    print(f"{Colors.HEADER}{Colors.BOLD}")
    print("🌐 IP Exit Enumeration Tool")
    print("Discovering your system's external IP addresses...")
    print(f"{Colors.ENDC}")
    
    enumerator = IPExitEnumerator(verbose=args.verbose)
    
    try:
        await enumerator.discover_ips()
    except KeyboardInterrupt:
        pass
    finally:
        enumerator.generate_final_report()

if __name__ == "__main__":
    # Check for required dependencies
    try:
        import aiohttp
    except ImportError as e:
        print(f"{Colors.FAIL}Missing required dependency: {e}")
        print(f"{Colors.OKCYAN}Install with: pip3 install aiohttp{Colors.ENDC}")
        sys.exit(1)
    
    # Run the async main function
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print(f"\n{Colors.WARNING}Interrupted by user.{Colors.ENDC}")
        sys.exit(130)
