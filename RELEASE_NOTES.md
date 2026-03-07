# First Release

`ip_exit_enum` is a CLI tool that enumerates your public IPv4/IPv6 egress IPs by querying multiple independent HTTP and STUN services concurrently.

It detects non-deterministic outbound behavior — such as load-balanced NAT, carrier-grade NAT, or ISP routing policies — that single-request "what's my IP" tools miss.

## Highlights

- **Multi-protocol discovery** — queries both HTTP echo services and STUN servers
- **IPv4 & IPv6** — enumerates exit addresses for both IP versions
- **Confidence scoring** — indicates likelihood of multiple outbound IPs
- **Live TUI** — real-time progress with per-phase status
- **Verbose mode** — `-v` flag for detailed per-service diagnostics
- **Single binary** — no runtime dependencies

## Pre-built Binaries

| Platform | Architecture | Binary |
|----------|-------------|--------|
| Linux | amd64 | `ip_exit_enum_linux_amd64` |
| Linux | arm64 | `ip_exit_enum_linux_arm64` |
| Linux | arm | `ip_exit_enum_linux_arm` |
| macOS | Apple Silicon | `ip_exit_enum_darwin_arm64` |
| macOS | Intel | `ip_exit_enum_darwin_amd64` |
| Windows | amd64 | `ip_exit_enum_windows_amd64.exe` |

## Usage

```sh
# Basic
./ip_exit_enum

# Verbose output
./ip_exit_enum -v
```
