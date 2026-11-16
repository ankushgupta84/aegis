# Aegis — product specification

What Aegis must do. Pair with `aegis-implementation-spec.md`, which says how to build it.

## The problem

Cloud customers run firewall, WAF, and load balancer as three separate products: three configs, three bills, traffic hairpins, a TLS termination per hop. Nobody owns the path end to end. Palo Alto has NGFW plus WAF but no load balancer; F5 BIG-IP has all three, but as separately licensed modules with separate policy languages. The missing product is one policy model over the whole path.

## What it is

One service for firewall, WAF, and load balancer: one TLS termination, one parse, one policy model, single-pass inspection (Palo Alto SP3 style: a packet is parsed and decrypted once), under 10ms p99 added latency.

## Capabilities

### Core: firewall, WAF, load balancer

- Firewall: CIDR deny list plus per-IP rate limiting.
- WAF: signature and rules based, OWASP CRS style. Scores add up; a high total blocks. ET Open or ET Pro rulesets drop in as-is (see Plugins).
- Load balancer: round-robin, with a passive health check that takes a dead backend out and retries it later.
- Ingress-only for v0.

### SSH

- The box is the single front door for SSH as well as HTTPS: key-based auth, per-user and per-target authorization, full session logging. Same policy model and audit trail as HTTP.

### Egress controls

- All outbound traffic routes through Aegis; no bypass path. Destinations are per-service exact URLs and regex patterns (e.g. `https://api.stripe.com/v1/*`, `.*\.s3\.amazonaws\.com`), plus a blocklist (FQDN and IP).
- Each allowed destination is high, medium, or low risk. Low: light inspection. Medium: full inspection and logging. High: full inspection, volume caps, flagged for review, explicit approval required in `strict`. Unknown destinations: denied in `strict`, flagged in `balanced`, allowed and logged in `easy`.
- Detectors look for secrets and credentials, PII patterns, and volume anomalies. Scored like the WAF: high blocks, mid passes with a flag and full capture, low passes. Destination risk feeds the score.
- Outbound TLS is re-encrypted through the box via an operator-controlled private CA, so inspection sees the payload. Stated plainly: the box can read outbound payloads by design; that capability is logged and access-controlled.

### Plugins

- Everything beyond the core pipeline is a plugin: certificate providers, WAF rule feeds, log sinks, metrics exporters, auth providers, egress detectors. Shipped or custom, same interfaces and lifecycle (discovery, safe loading, config, logging). A bad plugin must not take the box down.
- Certificates: fetch from AWS, GCP, or OCI Certificate Manager, or any custom source including an internal CA. Auto fetch and renewal, expiry alerting, hot reload without dropping connections.
- WAF rule feeds: ET Open (free) or ET Pro (operator's Proofpoint subscription) drop in as-is. Aegis runs Suricata rules natively — no rewriting; ET's ongoing updates reach users automatically. Feeds are versioned and hot-reloaded. Matching is multi-pattern from the start, not one regex per rule.

### Console (SentinelOne-style)

- One console for visibility, investigation, and action, modeled on SentinelOne's Singularity console — a thin view over the structured logs, metrics, and incident bundles, with no second data model.
- Structured logs (JSON, one event per line) for every request, block, backend failure, certificate event, SSH session, and egress decision, with consistent fields (timestamp, client IP, route, rule id, backend, latency, status).
- Dashboard: request rate, block rate by rule, backend health and latency percentiles, certificate expiry countdown, SSH session list, with drill-down.
- Storyline: every incident as one auto-correlated timeline of the full chain — firewall decision, WAF rules matched, backend chosen, egress checks. Root cause reads instantly.
- Hunting and browsing: Google-like search across all telemetry, saved queries, hunt by rule or technique, 14–365+ day retention; sort, filter, and search by time, status, rule, backend, client, latency; free-text and regex search; pattern grouping collapses repeats into one row with a count. Live tail plus history.
- One-click actions: block an IP, add an exclusion, drain a backend, rotate a certificate. Always human-approved; the agent proposes, the human clicks.
- Rule visualization (later, UI work): every rule in plain language in one read — what it looks for, where it looks (URI, header, body), severity, CVE reference, and an example of matching traffic. No raw Suricata syntax needed.

### Agent investigation

- On any anomaly (5xx spike, unhealthy backend, WAF block spike, cert near expiry, SSH brute force, exfiltration flag), the box exposes a structured incident bundle: correlated logs, metrics over the same window, config snapshot, recent changes. The agent names the most likely cause with evidence, proposes the fix, says what it checked and could not confirm, and never changes config or blocks traffic on its own — it proposes, a human approves. Every incident and investigation is logged.

### Knobs and profiles

- Explicit knobs, not code changes: WAF block threshold and per-rule scores, rate-limit rate and burst, anomaly thresholds, log verbosity, blocking vs monitor-only per rule group.
- Profiles `strict`, `balanced`, `easy`: each a complete knob set; the operator picks one and overrides knobs on top.
- Every feature states its default opt-in/opt-out in the config. Nothing is silently on. Fresh installs start on `balanced`.

### Agent-readable config

- YAML (or JSON) with a published schema: every field has a type, a default, and a one-line description of what it does and what happens if it is wrong. Profiles, knobs, plugins, and opt-in/opt-out state all live in the config, with comments explaining intent.
- Config is validated on load, with plain-language errors (which field, what's wrong, what valid looks like). The agent can read the live config, explain the current posture in plain language, and propose changes as a diff for human approval.

### Endpoint agents (later)

- Later, Aegis manages lightweight agents on backends and endpoints, SentinelOne-style.
- Agents enforce policy locally (firewall and egress rules on the machine), collect telemetry (process, file, network events), and report it to the console for Storyline and hunting.
- The console manages agent lifecycle: deploy, upgrade, health, grouping, policy per group. One-click actions (isolate a host, block a process) flow from console to agent.
- Agents keep enforcing the last-known policy when disconnected and queue telemetry until they reconnect.

## PR/FAQ

Amazon Working Backwards style, ~5 pages: problem, what we're building, what it solves, solves / does-not-solve table, single-pass engine, customer and internal FAQs, decision ask (approve v0 plus 2–3 design partners; kill it if p99 cannot hold under 10ms).

## Acceptance criteria

- Round-robin alternates between backends.
- SQL injection, XSS, and path traversal return 403.
- Scoring: a scanner user-agent alone passes; scanner user-agent plus a quote-comment blocks.
- A deny-listed IP is denied; the token bucket allows exactly the expected number of fast requests.
- Edge p50 and p99 measured under load against the 10ms p99 budget.

## Out of scope

- No tenancy or VCN structure.
- No anomaly detection in v0 (scored rules only).
- No proof-of-work anywhere.
