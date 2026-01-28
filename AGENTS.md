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
# CLAUDE.md

Behavioral guidelines to reduce common LLM coding mistakes. Merge with project-specific instructions as needed.

**Tradeoff:** These guidelines bias toward caution over speed. For trivial tasks, use judgment.

## 1. Think Before Coding

**Don't assume. Don't hide confusion. Surface tradeoffs.**

Before implementing:
- State your assumptions explicitly. If uncertain, ask.
- If multiple interpretations exist, present them - don't pick silently.
- If a simpler approach exists, say so. Push back when warranted.
- If something is unclear, stop. Name what's confusing. Ask.

## 2. Simplicity First

**Minimum code that solves the problem. Nothing speculative.**

- No features beyond what was asked.
- No abstractions for single-use code.
- No "flexibility" or "configurability" that wasn't requested.
- No error handling for impossible scenarios.
- If you write 200 lines and it could be 50, rewrite it.

Ask yourself: "Would a senior engineer say this is overcomplicated?" If yes, simplify.

## 3. Surgical Changes

**Touch only what you must. Clean up only your own mess.**

When editing existing code:
- Don't "improve" adjacent code, comments, or formatting.
- Don't refactor things that aren't broken.
- Match existing style, even if you'd do it differently.
- If you notice unrelated dead code, mention it - don't delete it.

When your changes create orphans:
- Remove imports/variables/functions that YOUR changes made unused.
- Don't remove pre-existing dead code unless asked.

The test: Every changed line should trace directly to the user's request.

## 4. Goal-Driven Execution

**Define success criteria. Loop until verified.**

Transform tasks into verifiable goals:
- "Add validation" → "Write tests for invalid inputs, then make them pass"
- "Fix the bug" → "Write a test that reproduces it, then make it pass"
- "Refactor X" → "Ensure tests pass before and after"

For multi-step tasks, state a brief plan:
```
1. [Step] → verify: [check]
2. [Step] → verify: [check]
3. [Step] → verify: [check]
```

Strong success criteria let you loop independently. Weak criteria ("make it work") require constant clarification.

---

**These guidelines are working if:** fewer unnecessary changes in diffs, fewer rewrites due to overcomplication, and clarifying questions come before implementation rather than after mistakes.
