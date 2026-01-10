# Architecture

## Purpose
`ip_exit_enum` enumerates public IPv4 and IPv6 egress IP addresses by correlating results from multiple HTTP and STUN services. It detects non-deterministic outbound behavior (load-balanced NAT, CGNAT, policy routing).

## High-level flow
1) `main.go` defines HTTP and STUN service lists with per-service timeouts.
2) `discovery.Engine` runs multiple samples, shuffling service order each pass.
3) Each service probe yields a `TestResult` with success, IPs, and latency.
4) Results are aggregated into maps by IP, protocol, and IP family.
5) `ui.Display` renders live progress and confidence scoring; verbose output is optional.

## Key modules
- `main.go`: CLI entry point, configures services, starts the engine.
- `internal/discovery/engine.go`: orchestration, sampling, aggregation, confidence scoring.
- `internal/discovery/http_service.go`: HTTP probing and IP extraction.
- `internal/discovery/stun_service.go`: STUN probing and IP extraction.
- `internal/ui/display.go`: live TUI output and verbose report.

## Data models and invariants
- `ServiceConfig`: identifies a service endpoint, protocol, and timeout.
- `TestResult`: captures service outcome and discovered IPs.
- IP filtering invariant: only public, non-loopback, non-private, non-link-local IPs are accepted.
- Confidence scoring uses success rate, sample size, protocol diversity, and consensus.

## Trust boundaries
- External HTTP endpoints and STUN servers are untrusted.
- Responses may be malformed, slow, or hostile; parsing and timeouts must be defensive.

## Error handling
- Each probe returns a failed `TestResult` with an error.
- Engine aggregates results and reports progress even on partial failures.
- Cancellation via context or SIGINT stops new work and ends with a final render.

## Failure modes
- Slow/unresponsive services: enforce per-service timeouts.
- Bad/malformed responses: IP extraction yields zero results.
- Network path instability: multiple exit IPs may appear across samples.
- UI rendering under lock can serialize updates if stdout is slow.

## Concurrency model
- `Engine.runBatch` uses a bounded worker pool (4 goroutines) per sample.
- Shared state is protected by a mutex; UI updates occur after each result.

## Testing
- Use `go test ./...`.
- Prefer tight, isolated tests in `internal/discovery` for network behavior.
