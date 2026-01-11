# ip_exit_enum

`ip_exit_enum` is a command-line network diagnostics tool that enumerates public IPv4 and IPv6 **egress (exit) IP addresses** by correlating results from multiple independent HTTP and STUN services.

It is designed to detect **non-deterministic outbound behavior**—such as load-balanced NAT, carrier-grade NAT, or ISP routing policies—that single-request “what’s my IP” tools cannot reliably identify.

## Why

Most public IP discovery tools do a single request and report the IP address used for that connection. In networks with load balancing, shared NAT, or policy-based routing, that can be misleading; different outbound connections can use different public IP addresses.

`ip_exit_enum` queries multiple independent services concurrently and aggregates the results into a set of observed exit IPs, along with a confidence score indicating whether multiple outbound addresses are in use.

It is useful for diagnosing:
- Load-balanced or carrier-grade NAT environments
- Inconsistent firewall or IP allowlist behavior
- Shared or opaque networks (hotels, ISPs, managed networks, cloud egress)

---

## How It Works

`ip_exit_enum` performs concurrent queries against a collection of:
- HTTP-based IP echo services
- STUN (Session Traversal Utilities for NAT) servers

By combining results from multiple protocols and independent endpoints, the tool reduces reliance on any single network path. The aggregated responses are analyzed to:

- Identify distinct IPv4 and IPv6 exit addresses
- Detect non-deterministic egress behavior
- Assign a confidence score indicating the likelihood of multiple outbound IPs

The tool has been validated on dual-stack (IPv4/IPv6) networks and environments with unstable or shared connectivity.

---

## Features

- **Concurrent Queries**: Multiple services queried in parallel for fast, representative results
- **Multiple Protocols**: Uses both HTTP and STUN to diversify observation paths
- **IPv4 & IPv6 Support**: Enumerates exit addresses for both IP versions
- **Confidence Scoring**: Indicates how likely multiple exit IPs are in use
- **Verbose Mode**: `-v` flag provides detailed per-service results and diagnostics
- **Single Binary**: Built as a standalone Go binary with no runtime dependencies

---

## Live UI Snapshot

Example TUI output (illustrative) highlighting two discovered IPv4 exits and one IPv6 exit:

```text
🔍 IP Exit Discovery – Live Results
Phase: HTTP(S) Discovery – sample 2/3 | Elapsed: 4.8s

Overall Progress: [██████████████            ] 18/30 (60.0%)

📊 IPs Discovered:
 IPv4:
   ✓ 198.51.100.10                           (3 hits, 60.0%)
   ✓ 203.0.113.7                             (2 hits, 40.0%)
   🔄 IPv4: load balancing across 2 IPs

 IPv6:
   ✓ 2001:db8::1                             (4 hits, 100.0%)
   📍 IPv6: single egress IP

📈 Confidence: High (Strong Consensus)
```

---

## Installation

### Requirements
- **Go** 1.22.5 or newer

### Build from Source

```sh
git clone https://github.com/sinnet3000/ip_exit_enum.git
cd ip_exit_enum
make build
```

The compiled binary will be available in the `bin/` directory.

---

## Usage

```sh
./bin/ip_exit_enum
```

For detailed output:

```sh
./bin/ip_exit_enum -v
```

---

## Legacy Python Version

The original Python implementation is preserved in the `legacy/` directory for reference and historical context. It is not feature-equivalent to the Go version.

To run it:

```sh
cd legacy
pip install -r requirements.txt
python ip_exit_enum.py
```

---

## License

This project is licensed under the **GNU Affero General Public License v3.0 (AGPL-3.0)**.

Copyright © 2025  
**Luis Colunga (@sinnet3000)**

See the [LICENSE](LICENSE) file for full details.
