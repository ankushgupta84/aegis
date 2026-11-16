# Aegis — implementation specification

How to build Aegis. Pair with `aegis-product-spec.md`, which says what it must do. Build v0 first; v1 extends the same core.

## Stack

- Java 21, written to read end to end. Libraries allowed where they earn their place; don't hand-roll what a good library does well.
- v1 data plane: Netty (event loop, pooled buffers, HTTP codec, native epoll transport). Modular, SOLID, each module unit-tested.
- Later: Go for the L7 half and control plane; Rust with DPDK or XDP/eBPF for the packet fast path. C matches Rust on speed; Rust wins on safety.

## Architecture

- A thin, gnarly fast core; a clean, readable policy layer above it. v1 extensions live in the policy layer, not the fast core.
- One responsibility per module, behind small interfaces: firewall, WAF rule engine, load balancer, upstream transport, proxy pipeline, metrics, config loading, plugin loading. Depend on interfaces; wire implementations in one composition root.
- The WAF rule engine runs Suricata rules natively (ET Open / ET Pro as-is); no rule-conversion step.
- Each module has unit tests (JUnit 5; Netty handlers via EmbeddedChannel, no network needed). The composition root itself is not unit-tested.
- Architecture, tests, and benchmark harness carry over to the later Go/Rust rewrite unchanged in shape.

## v0 prototype

One process:

- TLS listener on port 8443.
- Firewall: CIDR deny list in `config/firewall.conf`, plus a per-IP token bucket (100 rps, burst 50).
- WAF: 9-rule CRS-style scored engine in `config/waf-rules.txt` (SQL injection, XSS, path traversal, scanner user-agents), blocking at total score 5.
- Load balancer: round-robin across two dummy backends on ports 9001 and 9002; passive health check (3 failures out, retry after 5 seconds).
- `build.sh` builds it; include a load tester with latency statistics (p50, p99) and a README with run instructions.

## Performance

- Native epoll transport where available (NIO fallback), pooled byte buffers, pooled backend connections, one parse per request.
- Multi-pattern matching from the start: a Hyperscan-style matcher, not one regex per rule. Required to hold the 10ms p99 budget at ET scale (tens of thousands of rules).
- Measure edge p50/p99 under load with the load tester. Report the real numbers, and name the cause if the budget is missed (e.g. GC pauses, scheduling noise) — don't hide it.

## Design page

A web page documenting the design — toggleable today-vs-Aegis diagram, single-pass pipeline and sequence diagrams, a working simulator running the real v0 WAF rules, request lifecycle with exit codes, component map of every source file, verbatim policy configs, measured-latency chart, cell deployment diagram, honest solves / does-not-solve section — plus a downloadable zip with all source files, both configs, PR/FAQ, README, DESIGN.md, build script, and load tester.

## Verification procedure

Verify against the acceptance criteria in the product spec, with curl checks and the load tester at sustained load.
