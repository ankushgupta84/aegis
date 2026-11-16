# Aegis: product

> **DRAFT.** Built from the decisions made so far. Anything undecided is marked **Open**. The original specs are in `../seed/`. Next layer down: `high-level-design.md`.

## 1. Goal

Aegis is one free, open service that does the work of a firewall, a WAF, and a load balancer on a single path, with one decryption, one parse, and one view of what protects what.

It is built for **legacy estates**: systems with scattered certificates, poorly kept passwords, custom old software that is hard to replace, and no single place to see what is happening. New systems built on modern frameworks are mostly safe already. Legacy systems are where the exposure lives, and they are where no commercial product fits well.

## 2. The problem

- **Three products, three configs.** Customers run a firewall, a WAF, and a load balancer separately: three bills, three policy languages, a traffic hairpin and a TLS termination per hop. Nobody owns the path end to end.
- **Nobody can see the protection.** A security leader cannot tell what thousands of detection rules add up to. An engineer cannot easily tune one rule in depth without losing the picture.
- **Commercial products are closed where it hurts.** Palo Alto metrics cannot be customized. NGINX's richer metrics are in the paid product. Neither adapts to a customer's odd internal systems.
- **Rule effort is duplicated.** The community already maintains large rulesets (Suricata, Emerging Threats). Every product that cannot read them asks users to redo that work.

## 3. Who it is for

| Persona | Needs | Gets |
|---|---|---|
| **CISO** (macro) | A visual answer to "what protection do we actually have, where are the holes, what has been loosened, is it working?" | A coverage view derived from the rules and live traffic, with drill-down to the rules behind every cell |
| **Security engineer** (micro) | Full power to read, define, and tune each rule | Suricata rules as the native language, plus knobs, overrides, and exemptions at every scope |
| **Platform / legacy owner** | To adapt Aegis to systems nobody can replace | First-class plugins written against a stable API |

*Why two personas from one source of truth:* a separate executive dashboard drifts from the rules and cannot be trusted. Deriving the macro view from the same rules, bindings, and live hits keeps both honest.

## 4. Tenets

When two tenets conflict, the earlier one wins.

1. **Safe by default, customizable everywhere.** Defaults are strict enough to be safe. Every behavior is a knob, and every knob can be overridden at a narrower scope.
2. **Loosening is visible.** Weakening protection requires a stated reason and owner, and shows up in one list. A global floor can forbid it entirely.
3. **Reuse the community's rules, as they are.** Users import Suricata rules unchanged. We never fork or rewrite them.
4. **One source of truth, two levels of view.** The macro picture and the micro detail derive from the same data.
5. **Failure is explicit.** Nothing is skipped, swallowed, or guessed silently. Partial inspection, unsupported rules, and blind windows are logged and counted.
6. **Pluggable, with plugins first class.** Legacy estates need adapters. Plugins are as critical as the core and are held to its standard.
7. **Readable by people and machines.** Configuration is easy to read, validated with plain-language errors, and explainable by an AI to a non-engineer.
8. **Free, with no gated features.** Observability is not a paid tier.
9. **Fast enough to be invisible.** Under 10 ms added p99 latency, measured honestly.

## 5. How the tenets are met (product level)

| Tenet | Product commitment | Detail in |
|---|---|---|
| 1 Safe by default | Three profiles (`strict`, `balanced`, `easy`), each a complete knob set. Fresh installs start on `balanced`, with every value written out. | HLD §6 |
| 2 Loosening visible | Every exemption and override carries `reason` and owner. A "what's loosened" view lists them all. Floors forbid loosening below a set level. | HLD §6 |
| 3 Reuse rules | Import the full ET Open or ET Pro ruleset as-is. Unsupported rules are reported, never partly applied. | HLD §5 |
| 4 One truth, two views | The CISO view and the engineer view read the same rules and logs. | §6 below, LLD |
| 5 Explicit failure | Per-case fail knobs, counted events, blind-window metrics. | HLD §7 |
| 6 Pluggable | Certificates, rule feeds, log sinks, metrics, auth, and detectors are plugins on one API. | HLD §9 |
| 7 Readable | Published schema, `aegis explain`, an optional `intent` on major objects. | HLD §6 |
| 8 Free | Every capability ships in the free product. | §9 below |
| 9 Fast | Kill criterion in §8. | HLD §11 |

## 6. Capabilities

Described as the whole product. Sequencing is a separate, later question (`lld-in-progress.md`).

### Core path
- **Firewall.** An IP access list with allow and deny lists and per-client rate limiting. Honest scope: this is an L7 IP ACL, not an L3/L4 network firewall. **Open:** geo rules, port and protocol rules.
- **WAF.** Runs imported Suricata rules. Rule matches add to a score, and a total at the threshold blocks. Imported rulesets start in monitor mode and are promoted per ruleset or per rule.
- **Load balancer.** Round-robin, with a passive health check that ejects a failing backend and retries it later. Retries are safe only (see HLD §8).
- **TLS, two modes.** *Transparent* (Palo Alto style): Aegis holds a copy of the origin's certificate, so clients see the origin's identity. *Reverse proxy* (NGINX style): Aegis terminates with its own certificate. The mode is chosen per hostname.

### Egress and SSH
- **Egress controls:** outbound traffic through Aegis, with destination allow lists, risk levels, and detectors for secrets, PII, and volume. **Open: design pending.** Open points: service identity, URL pattern semantics, non-HTTP and DNS exfiltration, CA key custody, approval model.
- **SSH front door:** key-based auth, per-user authorization, session logging. **Open: design pending.**

### Plugins
Certificate providers, rule feeds, log sinks, metrics exporters, auth providers, and detectors. First class, in-process, one API.

### Console
A thin view over the structured logs and metrics.
- **CISO view.** Four questions: what is protected and how strongly, where the holes are, what is loosened, whether it works and what changed. Every cell drills down to its rules, and each rule to the engineer view. No single "security score": counts and modes only. **Open:** the taxonomy for the grid (see `lld-in-progress.md`).
- **Engineer view.** Each rule in plain language: what it looks for, where, severity, references, an example. Raw Suricata stays one click away.
- **Operations.** Live tail, search, and one-click actions (block an IP, add an exemption, drain a backend), always human-approved.
- **Search depth.** Local files give live tail and short-window search. Long retention and fast search over months need an integrated external store.

### Investigation agent
On an anomaly, Aegis exposes a structured incident bundle. An agent names the likely cause, proposes a fix, and says what it could not confirm. It never changes configuration or blocks traffic on its own. **Open:** where the model runs.

### Metrics
Thoughtful, free metrics at every stage, in a standard format, with operator-defined metrics.

### Endpoint agents
Lightweight agents on backends and endpoints enforcing local policy, reporting telemetry, and managed from the console. **Open: design pending.**

## 7. Solves and does not solve

| Solves | Does not solve |
|---|---|
| One decryption, one parse, one policy over the path | L3/L4 volumetric DDoS |
| Importing community rules without rewriting | Bot management |
| A readable picture of coverage for non-engineers | Application-logic flaws (OWASP "Insecure Design") |
| Surviving certificate rotation with explicit blind windows | Inspecting client-certificate (mTLS) sessions |
| Free, customizable metrics | Long-retention search without an external store |

## 8. Success and kill criteria

**Decision ask:** approve building, with 2–3 design partners with legacy estates. **Kill it** if added p99 latency cannot hold under 10 ms under the test below.

*The test:* full ET Open HTTP/TLS rules loaded; 70% GET and 30% POST (1–64 KB bodies) with 1% attack payloads; a fixed request rate (e.g. 5,000 rps) held steady regardless of response time; keep-alive connections with 5% new TLS handshakes; stated hardware (e.g. 4 vCPU, 8 GB); 10 minutes after a 2-minute warm-up. Added latency is via-Aegis minus direct-to-backend at the same load. Pass means p99 under 10 ms and zero request errors.

*Why this test:* a small-ruleset test proves nothing about the case that matters, which is tens of thousands of rules.

**If the test misses:** name the cause from profiling, do one optimization round, and consider a different implementation language only if the cause is the JVM itself.

## 9. Acceptance criteria

- Round-robin alternates between backends.
- SQL injection, XSS, and path traversal return 403.
- Scoring: a scanner user agent alone passes; scanner user agent plus a quote-comment blocks.
- A denied IP is denied. The rate limiter allows exactly the expected number of fast requests.
- Replaying a traffic corpus through Aegis and real Suricata yields matching alerts for supported rules.
- A benign corpus (e.g. "O'Brien", `--` in comments) produces no blocks.
- Encoded and double-encoded attack payloads are still caught.
- Ambiguous HTTP framing (conflicting length headers) is rejected.
- A certificate rotation produces a measured blind window, or none, and the metric reflects it.

## 10. Business model

The software is free, with no gated features. Any revenue would come from consultancy: using it effectively and running it reliably. Money is not the current motivation. **Open:** open-source license.

## 11. Open product questions

CISO view taxonomy and granularity · investigation agent model · console authentication (until decided, the console is local-only and off by default) · egress and SSH design · endpoint agents · license.
