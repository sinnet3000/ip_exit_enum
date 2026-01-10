# AGENTS.md

This repository is a Go CLI tool that enumerates public IPv4/IPv6 egress IPs by querying HTTP and STUN services.

## Local workflow
- Read: `README.md`, `internal/discovery/*`, `internal/ui/*`.
- Build/test: `go test ./...`.
- Run: `go run .` or `./bin/ip_exit_enum`.

## Architecture quick map
- `main.go` defines service lists and runs `discovery.Engine`.
- `internal/discovery` handles sampling, HTTP/STUN probes, aggregation, and confidence scoring.
- `internal/ui` renders live terminal output and verbose results.

## Invariants and expectations
- Only public, non-loopback, non-private, non-link-local IPs are counted.
- `ServiceConfig.Timeout` should bound network operations.
- Live UI progress reflects `testsCompleted/testsTotal` and current phase.

## Trust boundaries
- External HTTP and STUN services are untrusted inputs.
- Parsing and filtering must be defensive against malformed responses.

## Common pitfalls
- Timeouts must be enforced in both HTTP and STUN paths.
- Ensure IPv4/IPv6 forcing is respected per service.
- Avoid long-running UI output while holding engine locks.

## Conventions
- Keep changes minimal and focused; avoid broad refactors.
- Prefer small tests for regressions in `internal/discovery/*_test.go`.
