# Aegis: low-level designs in progress

> **WORKING NOTES.** Not designs. Each section holds what is decided, what is open, and notes for the design pass to come. Nothing here is final. Higher layers: `product.md`, `high-level-design.md`.

## Document status

| Component | Status |
|---|---|
| Configuration and type system | Intent captured; design pass deferred |
| Plugin API | Intent captured; design pass deferred |
| Rule engine | Direction decided; keyword subset open |
| TLS and certificates | Model decided; reverse-proxy gap open |
| CISO view and taxonomy | Parked |
| Investigation agent | Parked |
| Console authentication | Parked |
| Egress | Not started |
| SSH | Not started |
| Metrics catalogue | Not started |
| Endpoint agents | Not started |
| Implementation sequencing | Parked |
| License | Open |

## Configuration and type system

**Intent (from the owner):** easy to relate to, easy to extend, hierarchical and pluggable, following object-oriented fundamentals. Readable by humans and machines, and an AI must be able to tell a story from it, for a CISO if needed.

**Direction under discussion:**
- Every object has a `type` that selects an implementation; a plugin is another type.
- `extends` for single inheritance, depth capped (profile → strategy → route). Composition by named reference for everything else.
- Floors act like `final`: children tighten but never loosen.
- Each plugin registers its schema so validation, defaults, and `aegis explain` cover it.
- Optional `intent:` text on hosts, strategies, and exemptions: settings show what, intent shows why.
- Guard: deep or multiple inheritance makes configs unreadable.

**To design:** the type catalogue; file layout; the schema format and publication; `aegis explain` output format; hot reload (atomic swap, versioning, rollback, change log); profile versioning so an upgrade never silently shifts `balanced`; false-positive workflow (per-route and per-parameter exclusions).

## Plugin API

**Decided:** first class, in-process, one API, held to the core's standard (see HLD §9).

**To design:** the API surface and versioning rules; lifecycle; the SDK and contract-test kit; how failures are surfaced and contained with no isolation (timeouts, circuit breakers, loud alerts); plugin discovery and packaging; compatibility guarantees across versions; supply-chain provenance for customer plugins.

## Rule engine

**Decided:** own Java engine; import as-is; skip unsupported rules whole; default scoring table; monitor first; parity corpus.

**Open:**
- The supported Suricata keyword subset and the order to add keywords.
- Multi-pattern library: Aho-Corasick in Java versus Vectorscan. Hyperscan's newer releases moved to a proprietary license; verify before choosing.
- Linear-time regex engine choice, and how `pcre` features without a linear-time equivalent are handled (probably classified unsupported).
- Ingress web-application coverage beyond ET. ET is strongest for egress and command and control. OWASP-style coverage comes from CRS (SecLang). Whether to support a CRS subset is undecided.
- How `flowbits`, `threshold`, and `detection_filter` state is held across requests and nodes.
- The ET severity-to-score table: tune against real traffic.

**Notes:** Suricata rules parse mechanically into a syntax tree. Macro fields (header, direction, protocol, classtype, severity, MITRE, CVE) translate losslessly. Sticky buffers plus `content` render into plain language mechanically. Partly opaque: `pcre` (show regex plus a generated example), `flowbits` (render as links), `byte_test` / `byte_jump` / `lua`. Translation is one-way: Suricata text stays the source, keyed by `sid:rev`. Aegis's own overrides (mode, score, exemptions) live beside the rule and never edit it.

## TLS and certificates

**Decided:** two modes per hostname; transparent copies the origin's certificate; blind windows with metrics; rotation detection by fingerprint comparison; provider list with stated limits.

**Open:**
- Reverse-proxy mode with no valid certificate and a plain-HTTP backend: serve expired and record a degraded window, refuse, or choose per host.
- Whether resumption after a blind window is automatic or needs operator approval by default.
- Thresholds that turn blind-window counts into alerts.
- GCP: confirm in Google's own documentation that managed certificate keys cannot be exported.
- Handling for client-certificate (mTLS) sessions: passthrough or refuse, default per profile.
- TLS library: JDK versus native BoringSSL, by measurement. Minimum TLS version, ALPN, multi-certificate by SNI.
- CA key custody if egress interception is built: KMS or HSM, short-lived leaf certificates.

## CISO view and taxonomy (parked)

**Decided scope:** four questions. What is protected and how strongly; where the holes are; what is loosened; whether it works and what changed. Every cell drills down to rules, each rule to the engineer view. No single score.

**Owner's note:** OWASP Top 10 and MITRE tactics are too coarse even for a CISO. The owner is still forming the vision and asked to return to it.

**Direction raised, not decided:** a zoomable hierarchy: service and direction → OWASP or MITRE category → attack class (CWE) → known exploit (CVE, CISA KEV) against software actually running → rules. Data chain: ET `reference:cve`, NVD CVE-to-CWE, OWASP's CWE mapping, with our own mapping for rules that carry no CVE. Cost: the operator declares each service's software stack. Three cell states beyond rule counts: covered, hole, and outside the edge's reach (some OWASP categories cannot be fixed at a network edge). Alternative axis to consider: business risk (payment data, customer PII) instead of attack type.

## Investigation agent (parked)

Incident bundles hold IPs, PII, captured payloads, and internal config, so where the model runs is itself an egress decision. Options raised: bring-your-own endpoint with redaction before anything leaves; self-hosted only; a bundled hosted model. Agent never changes configuration or blocks traffic on its own; a human approves. To design: bundle schema, trigger thresholds as knobs, approval flow (approver identity, proposal expiry, recorded rollback).

## Console authentication (parked)

No authentication for now. Interim constraint: console and admin interface bind to localhost or a separate admin port and are off by default. To decide later: single sign-on, roles (viewer, operator, security-admin, capture-reader), audit of every action.

## Egress (not started)

Open points collected so far: how a calling service is identified (source address, mutual TLS, workload identity); enforcing no-bypass (a network deployment requirement, not a feature flag); non-HTTP traffic (databases, mail, raw TCP) and DNS exfiltration; URL pattern semantics (glob versus regex, anchoring, canonicalization, so `x.s3.amazonaws.com.evil.com` cannot match); interception breaking pinned clients and a no-decrypt SNI-only mode for low-risk destinations; approval per destination, not per request; capture of flagged bodies as a separate opt-in, access-controlled store; CA key custody; detector scoring; outage impact, since all outbound depends on Aegis (needs at least two nodes).

## SSH (not started)

Open points: source of user keys (a plugin, or SSH certificate authority); policy for port forwarding, file transfer, and agent forwarding; session recordings hold typed passwords, so retention and access control are required. A large scope on its own.

## Metrics catalogue (not started)

Required: blind-window count, seconds, and per hostname; certificate mismatch events and duration; partial and skipped inspections by cause; plugin health and failure counts; rule match and block rates by rule and by ruleset; backend health and latency percentiles; rate-limit decisions. Format: a standard open metrics format. Operator-defined metrics. Cardinality guard.

## Endpoint agents (not started)

Enforce local policy, collect process, file, and network telemetry, report to the console, managed from the console, keep enforcing the last policy when disconnected and queue telemetry.

## Implementation sequencing (parked)

The product and design documents describe the whole product with no versions. This is the earlier phase idea, kept only as a starting point for later planning:

1. Ingress core: firewall, WAF on a full ET Open file, load balancer, TLS, Netty, load tester.
2. Schema and profiles, certificate plugins, plugin runtime, logs, basic console, ET feed updates.
3. Egress.
4. SSH, investigation agent, Storyline-style correlation view.
5. Endpoint agents.

The ET-scale kill test applies to the first slice, so the full rule engine and a hand-downloaded ET Open file are needed from the start.

## License (open)

Software is free with no gated features. Choose an open-source license.

## Seed material

`../seed/` holds the two original specs. Findings from the gap review that are not yet absorbed into the documents: the Suricata-versus-CRS question for ingress, a benign-traffic false-positive corpus, exact per-rule scores for the acceptance tests, the "why not Envoy plus Coraza plus an egress proxy" answer the PR/FAQ must give, and the design page (diagrams, simulator through a local admin endpoint, generated component map) as a later deliverable.
