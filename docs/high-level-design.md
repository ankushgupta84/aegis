# Aegis: high-level design

> **DRAFT.** Built from the decisions made so far. Each decision gives its reason and what was rejected. Anything undecided is marked **Open**. Goals and tenets are in `product.md`. Parked detail is in `lld-in-progress.md`.

## 1. Architecture in one picture

```
client ──TLS──► [ Aegis node ] ──TLS──► origin
                 decrypt once
                 parse once
                 firewall → WAF (Suricata rules) → load balance
                 log + metrics at every stage
                 plugins: certs, rule feeds, sinks, auth, detectors
```

- One process, Java 21 with Netty (event loop, pooled buffers, native epoll where available).
- A **thin, fast core** (TLS, HTTP parse, matching) under a **readable policy layer** (profiles, strategies, exemptions, config).
- **Stateless nodes** behind a cloud network load balancer for scale and availability.

*Why Java:* readability, a large library ecosystem, and fast enough if the test in §11 passes. *Rejected:* a Go/Rust rewrite now (unproven need; splitting the data plane across languages would parse twice and break single-pass). Revisit only if profiling shows the JVM itself is the limit.

## 2. Design tenets

Product tenets (`product.md` §4) drive these design tenets:

1. **One parse.** A request is decoded and normalized once into one immutable object. Every stage reads it.
2. **Policy resolves ahead of time.** Inheritance and overrides compile into one flat policy per route at load. The hot path never walks a chain.
3. **Every decision is attributable.** Each block, skip, and pass records the rule, the scope that set it, and the reason.
4. **Failure has a knob.** Every way inspection can fail has an explicit, logged, counted behavior.
5. **Plugins are core.** One API, one lifecycle, one standard.
6. **Source text stays the source.** Imported rules are never rewritten. Views derive from them.

## 3. How the tenets are met

| Tenet | Mechanism | Section |
|---|---|---|
| One parse | `ParsedRequest` with lazily decoded, cached fields mapped to Suricata buffers | §4 |
| Resolve ahead | Load-time compile of config into flat per-route policy | §6 |
| Attributable | Decision records and `aegis explain` | §6, §10 |
| Failure knob | Per-case fail modes | §7 |
| Plugins are core | Versioned API, SDK, contract tests | §9 |
| Source stays source | Import classifies and indexes by `sid:rev`; overrides live beside rules | §5 |

## 4. Data plane

**Protocols.** HTTP/1.1, HTTP/2 (ALPN), and WebSocket to clients; HTTP/1.1 to backends. HTTP/2 and WebSocket are decoded to the same request object. For WebSocket, the upgrade request is inspected; message inspection is a knob. **Built so far:** HTTP/1.1 only. *Why first:* it is the smallest surface on which framing safety and single parse can be proven. **Open:** HTTP/3.

**Single parse.** Method, URI (raw and normalized), headers, and a bounded body prefix are decoded once. Normalization matches Suricata's HTTP parser, so imported rules see what they were written against: percent-decode exactly once, collapse repeated slashes, and leave `.` and `..` segments in place so traversal stays visible to rules. Each buffer is computed on first use and cached per request. Suricata transforms (`url_decode`, `to_lowercase`, `compress_whitespace`, `strip_whitespace`) give a rule a changed view of a buffer, also cached. *Rejected:* decoding repeatedly until stable (rules written for Suricata would see different bytes than they expect; double encoding is detected by a rule instead).

**Request bodies** are buffered whole up to `max_body_bytes` (10 MB by default; larger is refused with 413), and rules see the first `body_scan_limit` bytes. *Why buffer:* a verdict must exist before the first byte reaches a backend. *Cost:* memory per in-flight request, bounded by the limit. *Rejected for now:* streaming with prefix inspection (more moving parts for the same guarantee).

**Framing safety.** Ambiguous framing (conflicting length headers, malformed chunking) is rejected with 400. *Why:* request smuggling exploits disagreement between proxy and backend.

**Client IP.** The TCP peer by default, nothing else trusted. Opt in to PROXY protocol, or to `X-Forwarded-For` from named trusted proxy ranges, taking the rightmost untrusted hop. Rate limits are token buckets (100 requests per second, burst 50 by default) keyed on IPv4 /32 and IPv6 /64, all knobs. The bucket map is bounded and evicts the least recently used client, who then starts with a full bucket: a bounded leniency chosen over unbounded memory. PROXY protocol is not built yet. *Rejected:* always trusting `X-Forwarded-For` (spoofable).

**Block response.** 403 with an incident ID. Rule details are never returned to the client.

**Timeouts** are knobs with defaults: header 10 s, idle 60 s, connect 2 s, response 30 s, drain 30 s. TLS uses the JDK provider, TLS 1.2 and 1.3 only.

**Open:** TLS library choice (JDK vs native BoringSSL) pending measurement.

## 5. Rule engine

**Own engine in Java.** It parses Suricata rule syntax, runs all `content` patterns through one multi-pattern prefilter, and confirms candidates with a linear-time regex engine. Keywords are supported incrementally.

*Why own, not embedded Suricata:* embedding means a second parse of every request, inter-process calls on the hot path, and a C dependency. That breaks single-pass and likely the latency budget. *Rejected also:* a hybrid with Suricata running out of band (two engines to run and reconcile).

**Import as-is.** The whole ET Open or ET Pro file is accepted unchanged. Each rule is classified: *active*, *not applicable* (traffic Aegis never sees), or *unsupported* (uses a keyword we do not implement). Counts are reported. An unsupported rule is skipped whole, never partly applied, because dropping one condition widens the match.

**Scoring.** The block threshold is 5 by default. *Why 5:* one high-confidence attack rule blocks alone; weak signals such as a scanner user agent must combine. Suricata rules alert or drop; they do not score. Default score comes from a published table of severity by classtype (attack classes score 5/5/3/1 for Critical/Major/Minor/Info; recon 3/3/2/0; policy 2/2/1/0; misc 1/1/0/0). Overridable per classtype or per `sid`. Rules we write carry an explicit `metadata: score N`. Scores add; reaching the threshold blocks.

**Monitor first.** Imported rulesets start in monitor mode. Promotion to block is per ruleset or per rule. *Why:* tens of thousands of rules written for network IDS will produce false positives against a given application.

**Safety.** Linear-time regex, not backtracking, so hostile input cannot cause ReDoS. A per-request time budget applies as well (§7).

**Parity.** A traffic corpus replayed through real Suricata and Aegis, with alerts diffed, proves the engine. Suricata's own engine analysis output checks the parser. A target Suricata keyword version is pinned, because ET publishes rule files per version.

**Ingress coverage.** ET is strongest for egress and command-and-control, so Aegis ships `aegis-core.rules`: web-attack rules written by us in Suricata syntax, each with `metadata: score N`, enabled in block mode. *Why:* without it no decided ruleset blocks SQL injection, XSS, or path traversal, and the acceptance criteria cannot be met. *Rejected for now:* a CRS (SecLang) importer, a second rule language and engine semantics to match. It stays open as a later addition.

**Multi-pattern prefilter.** Our own Aho-Corasick automaton in Java, built as a flat table with byte-class compression, one per buffer view. *Why:* existing Java libraries are char-keyed tries, slow and large at tens of thousands of patterns; Vectorscan adds a native dependency and a licensing question. *Cost:* code we own and must test. Revisit Vectorscan only if profiling names the prefilter as the limit.

**Regex.** RE2/J. A `pcre` that needs backtracking (lookaround, backreferences) makes its rule unsupported.

**Supported keywords (Suricata 7 syntax).** `content` with `nocase`, `offset`, `depth`, `distance`, `within`, `startswith`, `endswith`, `fast_pattern`; `pcre`; the HTTP request sticky buffers and their legacy modifiers; the four transforms above; `flow` toward the server; and the descriptive keywords (`msg`, `sid`, `rev`, `classtype`, `priority`, `reference`, `metadata`). Support is an allow-list: any other keyword makes the rule unsupported.

**Not inspected yet: responses.** Rules that match server-to-client traffic or response buffers are classified unsupported. *Why:* response inspection means buffering responses, a separate latency and memory decision.

**Not supported: cross-request state.** `flowbits`, `xbits`, `threshold`, and `detection_filter` make a rule unsupported. *Why:* they need state shared across requests and nodes, which contradicts stateless nodes (§12). *Rejected:* per-node state (the same request would match on one node and not on another).

**Open:** a CRS importer; shared rule state; response inspection; tuning the score table against real traffic.

## 6. Policy and configuration

**Hierarchy.** Built-in profile → global → host/route. `strict`, `balanced`, and `easy` are the built-in **profiles**: each is a complete knob set. Named objects, defined once and referenced by name:
- **Lists:** typed sets (CIDR, host, URL pattern), inline, from file, or from a plugin.
- **Rule sets:** imported or authored Suricata rules.
- **Strategies:** an operator-defined bundle of rule sets and knobs that routes can share. Not built yet.

**Built so far:** one YAML file; profile, global, and route scopes; rule sets; exemptions; `aegis explain`. Floors, strategies, lists from plugins, and hot reload are not built.

**Overrides.** The narrowest scope that sets a knob wins. Overrides use explicit verbs (set, add, remove, disable), never implicit deep merge.

**Floors.** Global config can mark a knob as a floor. Narrower scopes may tighten but never loosen below it, and a config that tries fails validation with a plain-language error. Every knob declares its strictness order so a floor can be checked. Floors also bind exemptions.

**Exemptions.** A safe-list entry skips *only what it names* (a stage, a ruleset, a `sid`) and requires a reason. There is no blanket bypass. *Rejected:* "safe list skips everything" (a compromised internal host gets a free pass) and "deny always wins" (a legitimate internal scanner could never be exempted).

**Readable by people and machines.** A published schema gives every field a type, default, and a one-line description including what happens if it is wrong. `aegis explain` outputs the resolved configuration with the source of every value and any floor that binds it. That resolved view, not the raw files, is what an AI turns into a story for a CISO. An optional `intent` on major objects records *why* it exists.

**Extensibility, direction.** Every config object has a `type` selecting its implementation, so a plugin is another type. Single inheritance with a capped depth, composition by reference, each plugin registering its own schema. **Open: this is the subject of a dedicated design pass** (`lld-in-progress.md`).

*Rejected:* a ZPR-style or SQL-like policy language (a second language to learn, and the macro view should be derived rather than authored); one flat global rule list (no per-service control).

## 7. Failure modes

Each way inspection can fail has its own knob, set by profile:

| Case | `strict` | `balanced` | `easy` |
|---|---|---|---|
| Body over scan limit (128 KB default) | block | scan prefix, pass, log | scan prefix, pass, log |
| Inspection exceeds time budget (5 ms) | block | block | pass, log |
| Engine error | block | block | pass, log |

Every partial or skipped inspection is a logged, counted event. Overrides per route are allowed (e.g. an upload route raises the scan limit).

*Why per-case knobs:* always fail-closed makes an engine bug an outage; always fail-open lets an attacker pad a payload past the limit.

## 8. TLS and the load balancer

### TLS modes (per hostname)

| | Transparent (Palo Alto style) | Reverse proxy (NGINX style) |
|---|---|---|
| Certificate presented | A copy of the origin's own | Aegis's own |
| Backend | Always terminates TLS | Plain HTTP or TLS, any certificate |
| Clients that pin the origin's certificate | Keep working | Break |

**Transparent mode.** Aegis holds a copy of the origin's certificate, key, and chain. Modern key exchange (ECDHE and all of TLS 1.3) does not permit passive decryption, so Aegis proxies: one session with the client, one pooled session to the origin. Decrypt once, inspect once, re-encrypt. Aegis verifies the origin's certificate (CA check, or a pinned fingerprint for self-signed legacy origins). Client-certificate (mTLS) sessions cannot be inspected; a knob chooses passthrough or refusal, always logged. *Why this model:* clients see the origin's identity, so nothing about the client side changes.

**Certificate gaps and blind windows.** Certificate sources often do not overlap: the origin may have the new certificate before Aegis does. Order of behavior: serve the old certificate while valid; then, by knob, pass the connection through undecrypted (possible because the origin terminates TLS) rather than drop it. Each passthrough period is recorded as a **blind window**, because Aegis does not know what happened in it. Short, rare windows are normal. Frequent ones indicate a problem, so metrics capture count, total seconds, and per hostname, with alert thresholds. Decryption resumes automatically or on operator approval (knob). Layer-4 controls still apply during a window; the WAF does not. A floor can forbid passthrough (`strict`).

**Rotation detection.** On each new connection to the origin, Aegis compares the origin's certificate fingerprint with its own copy. A mismatch means the origin rotated, so Aegis fetches the new certificate through the certificate plugin and opens a blind window if the fetch lags.

**Built so far:** both modes, certificates from `file_watch` with hot reload, and upstream verification by CA or pinned fingerprint. A hostname with no configured certificate fails the handshake; there is no default certificate, because presenting another host's identity is worse than refusing. Blind-window passthrough and rotation detection are not built; until they are, a certificate gap in either mode refuses connections.

**Reverse proxy mode. Open:** with no valid certificate and a plain-HTTP backend, passthrough is impossible. Options: serve the expired certificate and record a degraded window, refuse, or choose per host.

**Certificate providers** (each a plugin, each limit stated):
- `aws_acm`: only certificates requested with export enabled (paid, chosen at request time, not changeable afterward).
- `gcp_secret`: certificate and key from Secret Manager. Google-managed certificates have no documented key export (confirm in Google's docs).
- `oci_certs`: bundle including the private key, by API or CLI only.
- `acme`: Let's Encrypt or any ACME CA.
- `file_watch`: PEM files on disk, covering an internal CA.

### Load balancer
Round-robin. A passive health check ejects a backend after 3 failures for 5 seconds. Failures are connect error, connect timeout, and response timeout; 5xx responses are logged but do not count unless a knob says so. At most one retry on another backend, and only if the request never reached the backend or its method is idempotent (GET, HEAD, OPTIONS, PUT, DELETE). POST and PATCH are never retried after bytes were sent. *Why:* a retried POST can double a side effect, such as a charge. With all backends down, return 503 and log an event.

## 9. Plugins

Legacy estates need adapters: for vaults, odd certificate stores, custom authentication, old logging systems. Customers will write plugins. They are **first class**: in-process, part of the system, as critical as the core, and held to the same standard.

*Why in-process:* without these plugins the system fails, so isolation would only hide a dependency. A separate process adds a hop to every data-plane call. *Rejected:* sandboxed or out-of-process third-party plugins (against the intent that plugins are core); first-party-only plugins (no room for the customer's own systems).

**Commitments:** a stable, versioned API; an SDK with a contract-test kit that holds plugins to the core's engineering bar; one lifecycle (discovery, config, start, health, stop); config validated against the plugin's own registered schema; every plugin failure surfaced loudly in logs and metrics.

**Built so far:** certificate providers and log sinks are discovered with Java's `ServiceLoader` and selected by `type`. This is the seed of the API, not the API.

**Open:** the plugin API shape, the type catalogue, and how failure is contained when nothing isolates it (timeouts, circuit breakers) (`lld-in-progress.md`).

## 10. Observability

**Logs.** Aegis always writes structured JSON lines to rotating local files, one event per line, with consistent fields. Optional sinks ship the same events to a store the operator already runs. Files are the source of truth, so the console needs no second data model. *Rejected:* building our own search store (a multi-year effort of its own). Consequence: live tail and short-window search scan local files; search over months needs an external store.

**Redaction by default.** `Authorization`, `Cookie`, `Set-Cookie`, and known token parameters are masked. Query values are kept only for allow-listed names. Request bodies are never logged: a hash, a length, and a short snippet around the rule match (with card and secret patterns masked inside it). Revealing more is a knob that a floor can forbid.

**Metrics.** Free and customizable, in a standard open format, at every stage, with operator-defined metrics. A cardinality guard refuses unbounded labels such as client IP. *Why:* closed metrics are a stated pain with both Palo Alto and NGINX. Blind-window metrics are required (§8).

**Correlation.** A request ID is propagated end to end so one request's firewall, WAF, backend, and later egress events join.

**Console safety.** Authentication is undecided (**Open**). Until it is, the console and admin interface bind to localhost or a separate admin port and are off by default, because the console can block IPs, drain backends, and change rules. **Built so far:** a read-only admin port serving `/metrics` and `/healthz`, bound to localhost. It can change nothing.

## 11. Performance and the kill test

The test is in `product.md` §8. Design consequences:
- Native epoll, pooled buffers, pooled upstream connections (including upstream TLS).
- One multi-pattern prefilter, so rule count does not multiply cost.
- Load generated open-loop at a fixed rate with high-resolution latency histograms. A generator that waits for each response understates tail latency.
- Report rate, connections, handshake share, payload sizes, rule count, GC pauses, and CPU. If the budget is missed, name the cause.

## 12. Availability

Nodes are identical and stateless, behind the cloud's network load balancer. They share configuration but no state, and upgrade one at a time, each draining on shutdown. Rate limits are per node, so a client can reach up to N times the configured rate; this is documented. Each node tracks backend health on its own. Egress, when built, requires at least two nodes. **Open:** an optional shared rate-limit store. Initial single-node operation is a stated limitation.

## 13. Test strategy

- Unit tests per module; no network needed for pipeline handlers.
- Parity corpus against real Suricata.
- A benign corpus to measure false positives, and encoded-attack and framing-attack corpora.
- Concurrency tests with an injectable clock: rate limiter under contention, round-robin under contention, health state changing mid-request.
- An end-to-end test that boots the composition root on ephemeral ports.
- The kill test as a repeatable benchmark.

## 14. Decisions at a glance

| Decision | Chosen | Rejected |
|---|---|---|
| Language | Java 21 + Netty | Go/Rust rewrite now |
| Rule engine | Own Java engine, Suricata syntax | Embedded Suricata; hybrid |
| Imports | As-is, classify, skip unsupported rules whole | Rewrite or partial apply |
| Policy | Named lists, rule sets, strategies; floors; named exemptions | New policy language; flat rule list |
| Safe list | Skips only what it names | Skip all; deny always wins |
| TLS | Two modes per hostname; transparent copies origin cert | Reverse proxy only |
| Plugins | First class, in-process, one API | Sandboxed or first-party only |
| Logs | Local JSON files, optional sinks | Own search store |
| Fail modes | Per-case knobs by profile | Always closed; always open |
| Client IP | Peer by default, explicit trust | Trust forwarded headers |
| LB retries | One, safe methods or unsent only | None; retry everything |
| Availability | Stateless nodes behind cloud LB | Active-passive pair |
