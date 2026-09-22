# Agent Instructions

## Project

A Go CLI that discovers public IPv4 and IPv6 egress addresses using HTTP and STUN services. See `README.md` for usage and `go.mod` for the Go version.

## Development and Verification

- Format changed Go files with `gofmt -w <paths>`.
- Run `go test ./...` and `go vet ./...` for Go changes. Add focused regression tests using the existing tests in `internal/discovery/`.
- Use `make build` when checking release builds across the supported platforms.
- Live discovery depends on the network and external HTTP/STUN services. Report which protocol and IP-family paths were exercised.
