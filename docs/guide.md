# Aegis user guide

How to run, configure, and operate the Aegis ingress core. Every command and output below was run against this build. For why Aegis exists and how it is designed, see [`product.md`](product.md) and [`high-level-design.md`](high-level-design.md).

1. [Getting started](#getting-started)
2. [Measuring overhead](#measuring-overhead)
3. [Configuration](#configuration)
4. [Rules](#rules)
5. [Operating Aegis](#operating-aegis)
6. [Troubleshooting](#troubleshooting)

## Getting started

### Prerequisites

Aegis needs Java 21 or later (`pom.xml` sets `maven.compiler.release` to 21) and Maven to build it. The certificate script calls `openssl`, and `scripts/kill-test.sh` calls `python3`. Every command below runs from the repository root.

### Build the jar

```sh
mvn -q package -DskipTests
```

The build writes `target/aegis-0.1.0-SNAPSHOT.jar`. Its manifest names `io.aegis.Aegis` as the main class, so `java -jar` runs the `run`, `explain` and `check` commands. The same jar holds the load tools, started with `java -cp`.

### Create development certificates

```sh
scripts/dev-certs.sh
```

```text
Wrote config/certs/localhost.crt and localhost.key (valid 30 days).
```

The script writes a self-signed ECDSA (P-256) certificate for `localhost` and `127.0.0.1` to `config/certs/`, and sets the key to mode 600. Clients must be told to trust it, as `--cacert` does below. The sample configuration points at these two files.

### Start the backends and Aegis

```sh
JAR=target/aegis-0.1.0-SNAPSHOT.jar
java -cp $JAR io.aegis.loadtest.DummyBackend --port 9001 --name backend-a &
java -cp $JAR io.aegis.loadtest.DummyBackend --port 9002 --name backend-b &
java -jar $JAR run config/aegis.yaml
```

Each backend prints `backend backend-a listening on port 9001`. Aegis prints:

```text
aegis listening on port 8443
```

On Java 25 each process also prints four `WARNING: A restricted method in java.lang.System has been called` lines from Netty's native-library loader. They are harmless. Adding `--enable-native-access=ALL-UNNAMED` to the `java` command silences them.

Aegis listens on 8443 (TLS) and, for the admin endpoints, on 127.0.0.1:9090. `/healthz` answers `ok`.

### Send a clean request and an attack

Curl resolves `localhost` to `::1` first, so the client address in the log below is the IPv6 loopback.

```sh
CURL="curl -s -i --cacert config/certs/localhost.crt"
$CURL https://localhost:8443/
$CURL https://localhost:8443/
```

```text
HTTP/1.1 200 OK
X-Backend: backend-a
content-length: 10
X-Request-Id: LSZC14SJDDmSCEc4

backend-a

HTTP/1.1 200 OK
X-Backend: backend-b
content-length: 10
X-Request-Id: 5CYQeZAorH98z5tZ

backend-b
```

The balancer alternates between the two backends. Every response carries an `X-Request-Id`.

```sh
$CURL "https://localhost:8443/?id=1'+union+select+1"
```

```text
HTTP/1.1 403 Forbidden
content-type: text/plain; charset=utf-8
X-Request-Id: QUU_weKsLr99zZ0s
content-length: 47

Request blocked. Incident ID: QUU_weKsLr99zZ0s
```

The incident ID in the body is the request ID. The request never reached a backend. Search `logs/aegis.log` for that ID to see why it was blocked. The log holds one JSON object per line: startup events, then one `request` event per request. The blocked request reads (the `body` field, which holds the SHA-256 and length of the empty body, is trimmed):

```json
{"ts":"2026-11-17T01:49:42.369Z","type":"request","request_id":"QUU_weKsLr99zZ0s","client_ip":"0:0:0:0:0:0:0:1","peer_ip":"0:0:0:0:0:0:0:1","method":"GET","target":"/?id=[redacted]","host":"localhost:8443","user_agent":"curl/8.18.0","route":"default","status":403,"decision":"waf_blocked","reason":"waf","waf_score":5,"waf_hits":[{"sid":9000001,"rev":1,"msg":"AEGIS CORE SQLI UNION SELECT in URI","rule_set":"aegis-core","mode":"block","score":5}],"inspection_gaps":[],"exemptions":[],"retried":false,"request_bytes":0,"response_bytes":0,"upstream_ms":0.0,"total_ms":2.8}
```

Rule 9000001 scored 5, which meets `block_threshold`. The query value is masked in `target` because `id` is not listed in `log.logged_query_params`. The allowed requests show `"decision":"allowed"`, `"waf_score":0`, and the `backend` that served them.

The admin port serves Prometheus metrics:

```sh
curl -s http://127.0.0.1:9090/metrics
```

```text
aegis_requests_total{decision="allowed",route="default"} 2.0
aegis_requests_total{decision="waf_blocked",route="default"} 1.0
aegis_waf_rule_hits_total{mode="block",rule_set="aegis-core",sid="9000001"} 1.0
aegis_backend_requests_total{backend="127.0.0.1:9001",result="success"} 1.0
aegis_backend_requests_total{backend="127.0.0.1:9002",result="success"} 1.0
aegis_firewall_decisions_total{verdict="allow"} 3.0
```

The admin listener is unauthenticated. Keep it bound to localhost.

### Stop Aegis

Send SIGTERM or press Ctrl-C. Aegis stops accepting connections, closes idle keep-alive connections, marks later responses `Connection: close`, and waits up to `listener.drain_timeout` (30s in the sample) for requests in flight. It then logs a `shutdown` event, closes the log, and exits 0.

To observe this, the backends were restarted with `--delay-ms 3000`. One request went out, and SIGTERM followed a second later. The in-flight request completed after 3.07 s with `connection: close`, a new connection was refused (curl exit 7), and the process exited 2.2 s after the last log line:

```text
{"ts":"2026-11-17T01:50:34.716Z","type":"shutdown","requests_cut_off":0}
```

`requests_cut_off` counts the requests still running when the drain timeout expired. Anything other than 0 means clients lost responses. Stop the backends with `kill`.

### Read a configuration without serving traffic

`explain` prints every knob with its value and the layer that supplied it: `set in file`, `global waf`, `profile balanced`, or `rule_sets declaration`. It ends with everything loosened.

```sh
java -jar $JAR explain config/aegis.yaml
```

```text
profile = balanced   (set in file)
listener.port = 8443   (set in file)
listener.idle_timeout = 1m   (set in file)
routes.default.waf.block_threshold = 5   (global waf)
routes.default.waf.body_scan_limit = 128KB   (profile balanced)
routes.default.waf.on_body_over_limit = pass   (profile balanced)
routes.default.waf.inspection_budget = 5ms   (profile balanced)
routes.default.waf.on_budget_exceeded = block   (profile balanced)
routes.default.rule_sets.aegis-core = block   (rule_sets declaration)

Loosened
  exemption internal-scanner: clients 10.20.0.5/32 skip rate_limit, rule_set:aegis-core. Reason: Weekly authenticated vulnerability scan. Owner: security-team@example.com.
```

`check` loads the configuration and its rule files and reports how each rule was classified:

```sh
java -jar $JAR check config/aegis.yaml
```

```text
rule set aegis-core: 126 active, 0 not applicable, 0 unsupported
```

Both commands, like `run`, take exactly one configuration path. A bad configuration prints its errors and exits 2. A usage error also exits 2, and a startup failure such as a busy port exits 1.

## Measuring overhead

`scripts/kill-test.sh` runs the latency test from `docs/product.md` §8. It sends the same open-loop load straight to a backend, then through Aegis, and reports the difference in p50 and p99. The load generator times each request from its intended send time, so a slow server cannot hide its own tail.

```sh
scripts/kill-test.sh [config] [rate] [duration] [warmup]
```

| Argument | Default |
|---|---|
| `config` | `config/aegis.yaml` |
| `rate` (requests per second) | `5000` |
| `duration` (measured phase) | `600s` |
| `warmup` (unrecorded phase) | `120s` |

Environment variables override the rest: `DIRECT_URL` (`http://127.0.0.1:9001`), `AEGIS_URL` (`https://localhost:8443`), `TRUST` (`config/certs/localhost.crt`, the certificate the TLS run trusts), and `OUT` (`target/kill-test`, where the two JSON reports go).

Start the backends and Aegis first. The script prints the rule counts with `check`, runs the direct load with no attacks, then runs the load through Aegis with 1% attack requests, which must come back 403. Both runs use 64 connections, 5% new connections, 30% POSTs with bodies of 1KB to 64KB, and seed 1. The script exits 0 and prints `PASS` when all of these hold, and exits 1 and prints `MISS` with the reasons otherwise:

- added p99 is under 10 ms;
- neither run has errors or unexpected non-2xx responses;
- each run achieves at least 99% of the configured rate;
- every attack request is blocked.

With the defaults, each of the two runs lasts 12 minutes (2 warmup, 10 measured), 24 in all. A short run against the sample configuration (`scripts/kill-test.sh config/aegis.yaml 200 5s 2s`, with `OUT` pointed at a scratch directory) took 15 seconds and printed (trimmed):

```text
label:            direct
target:           http://127.0.0.1:9001
rate:             200 configured, 200.2 achieved (over 5.0 s, 64 connections, seed 1)
requests:         1000 measured, 400 warm-up
responses:        200=1000
attacks:          0 sent, 0 blocked as expected (403)
other non-2xx:    0
errors:           none
latency ms:       p50 0.788  p90 1.496  p99 3.069  p99.9 4.127  max 4.235
max queue depth:  0

label:            via-aegis
responses:        200=490 403=10 429=500
attacks:          14 sent, 8 blocked as expected (403)
other non-2xx:    502
latency ms:       p50 1.380  p90 4.667  p99 14.399  p99.9 19.103  max 21.855

== Added latency (via Aegis minus direct) ==
p50: direct 0.788 ms, via Aegis 1.380 ms, added 0.592 ms
p99: direct 3.069 ms, via Aegis 14.399 ms, added 11.330 ms
MISS:
  added p99 is 11.330 ms, over the 10 ms budget
  via Aegis: 0 errors, 502 unexpected non-2xx
  6 of 14 attack requests were not blocked
```

Two effects spoil that run. First, the sample configuration rate-limits each client to 100 requests per second with a burst of 50, and the test sends 200 from one address, so Aegis answered 500 requests with 429. Measure with a copy of the configuration whose `firewall.rate_limit.enabled` is `false`.

Second, benign POSTs were blocked with `"inspection_gaps":["time_budget_exceeded"]` and a WAF score of 0. The rate-limit fix and a longer warmup do not cure this. With the rate limit off, at 1000 requests per second for 20 s after a 15 s warmup, Aegis added 0.59 ms at p50 and 9.6 ms at p99, but blocked 454 benign requests, about 2%. Matching itself is cheap: the core ruleset scans a 64KB body in 0.6 ms. The `inspection_budget` (5ms) counts wall-clock time, however, and the JVM's garbage-collection pauses reached 5.2 ms in that run. One pause pushes every inspection in progress past its deadline, and `balanced` blocks on an overrun. Until the budget stops counting pauses, a kill test under `balanced` or `strict` reports these blocks as unexpected non-2xx responses, and production traffic sees them as false positives. `aegis_inspection_gaps_total` counts them. Setting `waf.on_budget_exceeded: pass` trades them for requests that pass partly inspected.

### Load tester flags

`io.aegis.loadtest.LoadTester` takes `--url` and the following flags. Durations take `ms`, `s`, `m` or `h`. Sizes take `B`, `KB` or `MB`. `--url` holds scheme, host and port only, because the request mix picks the paths.

| Flag | Meaning | Default |
|---|---|---|
| `--url URL` | `http(s)://host[:port]` target (required) | none |
| `--rate N` | requests per second, held steady whatever the server does | 5000 |
| `--duration D` | measured phase | 600s |
| `--warmup D` | unrecorded phase before it | 120s |
| `--connections N` | keep-alive connections | 64 |
| `--new-connection-share F` | fraction of requests on a fresh connection, TLS handshake included, closed afterwards | 0.05 |
| `--post-share F` | fraction of POST requests | 0.30 |
| `--body-min S`, `--body-max S` | POST body size range | 1KB, 64KB |
| `--attack-share F` | fraction of requests carrying an attack payload | 0.01 |
| `--host-header NAME` | Host header | host and port of `--url` |
| `--tls-trust FILE` | PEM CA bundle or server certificate to trust for https | the JVM trust store |
| `--timeout D` | per-request limit, from the intended send time | 5s |
| `--label TEXT` | name of the run, printed in the report | empty |
| `--seed N` | seed of the request mix; the same seed repeats a run | random, printed in the report |
| `--json FILE` | also write the report as JSON | none |

`io.aegis.loadtest.DummyBackend` takes:

| Flag | Meaning | Default |
|---|---|---|
| `--port N` | listening port; 0 picks an ephemeral one | 0 |
| `--name NAME` | identity returned in the body and the `X-Backend` header (required) | none |
| `--delay-ms N` | wait before every answer, to simulate a slow origin | 0 |
| `--tls-cert FILE`, `--tls-key FILE` | PEM certificate chain and PKCS#8 key; both or neither | plain HTTP |

## Configuration

Aegis reads one YAML file. `aegis check <file>` validates it and counts the rules it will apply; `aegis explain <file>` prints the value in force for every knob and the scope that set it. Both exit with status 2 and list every problem at once when the file is wrong. Relative paths in the file (rule files, certificates, the log directory, a trusted CA) resolve against the working directory of the process, not against the file's location. The loader does not open them; `check` and `run` do.

### The shape of the file

| Section | Purpose |
|---|---|
| `profile` | Required. Picks the built-in starting values for the WAF: `strict`, `balanced`, or `easy`. |
| `listener` | The client-facing socket: address, port, TLS on or off, size and time limits. |
| `admin` | The `/metrics` and `/healthz` endpoint. It has no authentication; keep it on localhost. |
| `log` | Log directory, rotation, and which query parameter values may be logged. |
| `client_ip` | Which upstream proxies may speak for the client through `X-Forwarded-For`. |
| `firewall` | Layer-7 allow and deny lists and the per-client rate limit. |
| `rule_sets` | Suricata rule files to import, each with a name and a mode. |
| `waf` | Global WAF knobs that override the profile. |
| `exemptions` | Named clients that skip named protections, with a reason and an owner. |
| `tls` | Which certificate to present for which host name. |
| `routes` | Required. Host and path matching, backends, health, timeouts, per-route WAF overrides. |

The smallest file that passes `check` turns listener TLS off and defines one route:

```yaml
profile: balanced
listener:
  tls: false
routes:
  - name: default
    backends: [127.0.0.1:9001]
```

`check` exits 0 and prints nothing, because no rule set is declared. Leave out `listener.tls: false` and it fails: `listener.tls is true but there is no 'tls' entry to say which certificate to present.` Add a `tls` entry (see below) to serve HTTPS. With the shipped rule file declared under `rule_sets`, `check` prints `rule set aegis-core: 126 active, 0 not applicable, 0 unsupported`.

### Profiles

A profile supplies the complete WAF knob set. Only three knobs differ between profiles; the other three are identical.

| Knob | strict | balanced | easy |
|---|---|---|---|
| `block_threshold` | 5 | 5 | 5 |
| `body_scan_limit` | 128KB | 128KB | 128KB |
| `inspection_budget` | 5ms | 5ms | 5ms |
| `on_body_over_limit` | block | pass | pass |
| `on_budget_exceeded` | block | block | pass |
| `on_engine_error` | block | block | pass |

Profiles touch nothing outside `waf`. Listener, firewall, and health defaults are the same under all three.

### Scopes and precedence

Each WAF knob resolves through three scopes, narrowest first: the route's `waf` block, the global `waf` section, the profile. The first scope that sets the knob wins. Rule set modes resolve the same way: a route's `rule_sets` map overrides the mode declared under the top-level `rule_sets`. `explain` records the winning scope beside every value.

Example: profile `strict`, a global `waf` that raises the scan limit and the budget, and a route that overrides the scan limit and one fail mode.

```yaml
profile: strict
waf:
  body_scan_limit: 256KB
  inspection_budget: 10ms
routes:
  - name: api
    path_prefix: /api
    backends: [127.0.0.1:9001]
    waf:
      body_scan_limit: 1MB
      on_body_over_limit: pass
  - name: default
    backends: [127.0.0.1:9002]
```

```text
routes.api.waf.block_threshold = 5   (profile strict)
routes.api.waf.body_scan_limit = 1MB   (route api)
routes.api.waf.on_body_over_limit = pass   (route api)
routes.api.waf.inspection_budget = 10ms   (global waf)
routes.api.waf.on_budget_exceeded = block   (profile strict)
routes.default.waf.body_scan_limit = 256KB   (global waf)
routes.default.waf.on_body_over_limit = block   (profile strict)
routes.default.waf.inspection_budget = 10ms   (global waf)
```

The `api` route takes its scan limit from itself, its budget from the global section, and its threshold from the profile. The `default` route, which sets nothing, inherits the global limit and the profile's fail mode.

Every other `explain` line ends in `(set in file)` or `(built-in default)`; rule set modes end in `(rule_sets declaration)` or `(route <name>)`.

### Value syntax

| Type | Syntax |
|---|---|
| Duration | Whole number plus unit: `ms`, `s`, `m`, `h` (`500ms`, `5s`, `2m`). Up to 9 digits, greater than zero. A bare number is refused. `explain` prints the largest exact unit, so `60s` shows as `1m`. |
| Size | Whole number with `B`, `KB`, `MB`, or `GB` (powers of 1024), or a bare number of bytes. Greater than zero. Settings stored as a 32-bit integer (listener limits, `body_scan_limit`) accept at most 2147483647 bytes. |
| Address list | IPv4 or IPv6 literals, bare (`192.0.2.7`, a block of one) or CIDR (`10.0.0.0/8`, `2001:db8::/32`). Host names are rejected. |
| Backend | `host:port` or `[ipv6]:port`; port 1 to 65535. |
| Host name | Lowercased on read. A name, `*.example.com`, or `*`. |
| Fail action | `block` or `pass`. |
| Rule mode | `block`, `monitor`, or `disabled`. |

### Reference

Keys not listed here are rejected. Defaults shown are the values `explain` reports as `built-in default`.

#### listener

| Key | Type | Default | Meaning |
|---|---|---|---|
| `bind` | text | `0.0.0.0` | Address to listen on. |
| `port` | 0 to 65535 | `8443` | Port; 0 asks the operating system for a free one. |
| `tls` | boolean | `true` | Clients connect over TLS. When true, at least one `tls` entry is required. |
| `max_header_bytes` | size | `16KB` | Request line and headers together may not exceed this. |
| `max_body_bytes` | size | `10MB` | A longer request body is refused with 413. |
| `header_timeout` | duration | `10s` | Longest a client may take to send the request head. |
| `idle_timeout` | duration | `60s` | An idle keep-alive connection closes after this long. |
| `drain_timeout` | duration | `30s` | On shutdown, in-flight requests get this long to finish. |

#### tls

A list; each entry names a host and a certificate. `hostname` values must be unique.

| Key | Type | Default | Meaning |
|---|---|---|---|
| `hostname` | host name | required | The SNI name. `*.example.com` matches one label. |
| `mode` | `reverse_proxy` or `transparent` | `reverse_proxy` | Parsed and printed by `explain`, but nothing reads it yet: every host presents its configured certificate. `transparent`, which would present a copy of the origin's certificate, is not built. |
| `certificate.type` | text | required | Certificate provider. `file_watch` is the provider in this build. |
| `certificate.*` | text | | The provider's own settings, listed by name only in `explain` because values may be secrets. |

`file_watch` accepts `cert_file` and `key_file` (both required, PEM) and `poll_interval` (duration, default `5s`). It rejects other names when the server starts.

SNI selection is exact match first, then a single-label wildcard (`a.example.com` falls back to `*.example.com`). There is no default certificate: a client that sends no server name, or a name with no match, has its handshake fail. Nothing presents another host's certificate.

#### client_ip

| Key | Type | Default | Meaning |
|---|---|---|---|
| `trusted_proxies` | address list | `[]` | Proxies in front of Aegis that you control. |

The TCP peer is the client unless it falls inside a trusted block. Then Aegis reads `X-Forwarded-For` from the right and takes the first hop that is not itself trusted. An unparseable hop ends the walk and yields the hop to its right. If every hop is trusted, the leftmost hop is the client. Leave the list empty when nothing sits in front of Aegis: the header is then ignored.

#### firewall

| Key | Type | Default | Meaning |
|---|---|---|---|
| `allow` | address list | `[]` | When non-empty, only these clients are admitted. |
| `deny` | address list | `[]` | These clients are refused. Deny wins over allow. |
| `rate_limit.enabled` | boolean | `true` | Turns the limiter on or off. |
| `rate_limit.requests_per_second` | number > 0 | `100` | Steady refill rate of each client's bucket. |
| `rate_limit.burst` | integer >= 1 | `50` | Bucket capacity: requests that may arrive at once. |
| `rate_limit.ipv4_prefix` | 0 to 32 | `32` | IPv4 clients sharing this prefix share a bucket. |
| `rate_limit.ipv6_prefix` | 0 to 128 | `64` | IPv6 clients sharing this prefix share a bucket. |
| `rate_limit.max_tracked_clients` | integer >= 1 | `100000` | Most buckets held at once; idle ones are evicted first. |

Each node keeps its own buckets, so a client spread over N nodes can reach N times the rate. This is a layer-7 access list, not a network firewall.

#### rule_sets

A list of Suricata rule files, imported unchanged. `name` values must be unique.

| Key | Type | Default | Meaning |
|---|---|---|---|
| `name` | text | required | How routes and exemptions refer to the set. |
| `file` | path | required | Rule file. |
| `mode` | `block`, `monitor`, `disabled` | required | Mode its rules run in unless a route says otherwise. There is no default; the reference file advises `monitor` for imported sets. |

A rule's mode is its sid override if a route sets one, else its rule set's mode. In `block` mode a match adds the rule's score; a total at or above `block_threshold` blocks. In `monitor` mode a match is logged and counted but adds no score. A `disabled` rule is not evaluated.

#### waf (global and per route)

The same six keys are valid in the global `waf` section and in a route's `waf` block. Unset keys fall through to the next scope.

| Key | Type | Default | Meaning |
|---|---|---|---|
| `block_threshold` | integer >= 1 | 5 (all profiles) | A request whose block-mode hits total this score or more is blocked. |
| `body_scan_limit` | size | `128KB` (all profiles) | How much of a request body is inspected. |
| `on_body_over_limit` | `block`/`pass` | profile: block, pass, pass | Action when the body exceeds the scan limit. |
| `inspection_budget` | duration | `5ms` (all profiles) | Longest inspection of one request may take. |
| `on_budget_exceeded` | `block`/`pass` | profile: block, block, pass | Action when inspection runs out of budget. |
| `on_engine_error` | `block`/`pass` | profile: block, block, pass | Action when the rule engine fails. |

Whichever action applies, a request that could not be inspected in full is logged and counted.

#### routes

A list; the first route in file order whose host and path prefix fit a request serves it. Put specific routes before general ones. `name` values must be unique.

| Key | Type | Default | Meaning |
|---|---|---|---|
| `name` | text | required | Label in logs and `explain`. |
| `host` | host name | `*` | Host header to match, port ignored. `*.example.com` matches one label below the suffix. |
| `path_prefix` | path | `/` | Must start with `/`. Matched after dot segments are resolved, so `/public/../admin` is routed as `/admin`. |
| `backends` | list of `host:port` | required, at least one | Servers behind this route. |
| `connect_timeout` | duration | `2s` | Longest a connection attempt may take. |
| `response_timeout` | duration | `30s` | Longest silence Aegis accepts from a backend: armed when the request is sent, re-armed at the response head and at each body chunk. |
| `health.failures_to_eject` | integer >= 1 | `3` | Consecutive failures that take a backend out of rotation. |
| `health.ejection_time` | duration | `5s` | How long an ejected backend sits out. |
| `health.count_server_errors` | boolean | `false` | Whether a 5xx counts as a failure. Connect errors and timeouts always do. |
| `upstream_tls.enabled` | boolean | `false` | Connect to backends over TLS. |
| `upstream_tls.trusted_ca` | path | none | PEM file of CA certificates. Requires `enabled: true`. |
| `upstream_tls.pinned_sha256` | 64 hex digits | none | Fingerprint of the backend's leaf certificate; colons allowed. Requires `enabled: true`. |
| `waf` | mapping | | The six WAF keys above. |
| `rule_sets` | map of name to mode | | Per-route mode for a declared rule set. Undeclared names are errors. |
| `rules` | list | | Per-sid overrides, below. |

Health is passive: Aegis judges a backend by the requests it serves. A failed request is resent to another backend at most once: always when it never reached a backend, and after bytes were sent only for GET, HEAD, OPTIONS, PUT, and DELETE. There is no retry key.

With upstream TLS on, the backend certificate is always verified: against the pin if set, otherwise against `trusted_ca` if set, otherwise against the JVM trust store. No setting disables verification.

Each `rules` entry:

| Key | Type | Default | Meaning |
|---|---|---|---|
| `sid` | integer >= 1 | required | The rule to override. |
| `mode` | `block`, `monitor`, `disabled` | none | Replaces the rule set's mode for this rule on this route. |
| `score` | integer >= 1 | none | Replaces the rule's own score on this route. |

#### admin

| Key | Type | Default | Meaning |
|---|---|---|---|
| `enabled` | boolean | `true` | Serve `/metrics` and `/healthz`. |
| `bind` | text | `127.0.0.1` | Address to listen on. |
| `port` | 0 to 65535 | `9090` | Port. |

#### log

| Key | Type | Default | Meaning |
|---|---|---|---|
| `directory` | path | `logs` | Folder for `aegis.log` and its rotated predecessors. |
| `rotate_at` | size | `100MB` | Rotate a file once it reaches this size. |
| `keep_files` | integer >= 1 | `10` | Rotated files to keep. |
| `logged_query_params` | list of text | `[page, limit, sort]` | Query parameters whose values may be logged; all others are masked. |

### Exemptions

An exemption lets named clients skip named protections. It skips only what it lists; there is no blanket bypass. It applies to every route.

```yaml
exemptions:
  - name: internal-scanner
    sources: [10.20.0.5]
    skip: [rate_limit, "rule_set:aegis-core", "sid:2019401"]
    reason: Weekly authenticated vulnerability scan
    owner: security-team@example.com
```

| Key | Type | Meaning |
|---|---|---|
| `name` | text | Unique label. |
| `sources` | address list, at least one | Clients the exemption covers. |
| `skip` | list, at least one | What they skip. |
| `reason` | text | Why the exemption exists. Required. |
| `owner` | text | Who answers for it. Required. |

A `skip` entry is one of:

| Entry | Skips |
|---|---|
| `rate_limit` | The per-client rate limit. |
| `waf` | The whole WAF stage. |
| `rule_set:<name>` | One declared rule set. An undeclared name is an error. |
| `sid:<number>` | One rule. |

Quote entries that contain a colon. Omitting `reason` or `owner` fails the load, which is how a loosening cannot go unexplained.

The end of every `explain` is a `Loosened` list. It holds each exemption with its clients, skips, reason, and owner, plus every rule set or rule that a route runs below `block`. For a file that adds the exemption above to the `strict` example, declares `aegis-core` in `block` mode and `et-open` in `monitor` mode, and has the `api` route set `rule_sets: {aegis-core: monitor}` and a `rules` entry with `sid: 9000001, mode: disabled`:

```text
Loosened
  exemption internal-scanner: clients 10.20.0.5/32 skip rate_limit, rule_set:aegis-core, sid:2019401. Reason: Weekly authenticated vulnerability scan. Owner: security-team@example.com.
  route api runs rule set aegis-core in monitor mode
  route api runs rule set et-open in monitor mode
  route api runs rule 9000001 in disabled mode
  route default runs rule set et-open in monitor mode
```

A file that loosens nothing prints `nothing`.

### Errors

Aegis reports every problem it finds in one pass, numbered, each naming its location. Nothing is ignored and no invalid value is replaced by a default. An unknown key gets a "did you mean" when a valid key is within two edits; otherwise the message lists the valid keys for that section. Given a file with several mistakes, `check` printed:

```text
The configuration has 8 problems:
  1. exemptions[0].reason is required but missing. Loosening protection must be explained: say why this exemption exists.
  2. exemptions[0].owner is required but missing. Loosening protection must be owned: name the team or person who answers for it.
  3. exemptions[0].skip: 'et-open' is not a declared rule set. No rule sets are declared under rule_sets.
  4. listener.idle_timeout: '60' is not a duration. Write a number and a unit, e.g. 500ms, 5s, 2m.
  5. routes[0].backends[0]: '127.0.0.1' is not a backend address. Write host:port, e.g. 10.0.0.5:8080 or [::1]:8080.
  6. routes[0].waf.on_engine_error: 'allow' is not one of: block, pass.
  7. Unknown key 'max_body_byts' under listener. Did you mean 'max_body_bytes'?
  8. Unknown key 'burts' under firewall.rate_limit. Did you mean 'burst'?
```

Other messages worth knowing:

```text
profile: 'relaxed' is not one of: strict, balanced, easy.
routes is required: add at least one route with a name and backends.
routes[0].upstream_tls.enabled is false, so trusted_ca and pinned_sha256 would be ignored. Set enabled: true or remove them.
```

Duplicate YAML keys are a parse error, and duplicate `name`, `hostname`, or `sid` values within one list are reported with the index of the first use. A file that cannot be parsed reports `The file is not valid YAML (line N)`; an empty file reports `The file is empty`. Problems in the syntax of the file stop the load before the rest is checked.

## Rules

Aegis reads rules in Suricata 7 syntax, scores each match, and blocks a request when the scores add up to the threshold. The WAF is the only consumer: it reads each request once, in its decoded HTTP form, and never sees responses.

### How a request is judged

Judging runs in four steps.

1. **Prefilter.** Every active rule contributes one literal, its fast pattern: the content flagged `fast_pattern`, else the longest non-negated content. One Aho-Corasick pass per view of the request marks every rule whose literal occurs. The cost depends on the request's length, not on the number of rules. A rule with no non-negated content (a `pcre` alone, for example) has no literal and is a candidate on every request.
2. **Confirmation.** Each candidate rule is checked in full: every content and pcre in order, with `offset`, `depth`, `distance`, `within`, `startswith` and `endswith` applied. A content that occurs several times is tried at each occurrence until the rest of the rule holds. A `pcre` takes its first match only.
3. **Score.** Each confirmed rule adds its score once, however often it matched, but only if its mode is `block`. A `monitor` hit is logged with 0 points. A `disabled` rule is never evaluated.
4. **Verdict.** The request is blocked when the total reaches `waf.block_threshold` (whole number of 1 or more; 5 in every profile), or when an inspection gap occurs whose policy is `block`.

A gap is a way inspection fell short, and each one is logged and counted:

| Gap | Cause | Policy knob |
|---|---|---|
| `body_over_scan_limit` | Body longer than `body_scan_limit` (128KB by default); only the prefix is inspected | `on_body_over_limit` |
| `time_budget_exceeded` | Inspection spent its `inspection_budget` (5ms by default) of wall-clock time; undecided rules count as not matched. A garbage-collection pause counts against the budget, so this gap also fires on benign requests (see Measuring overhead). | `on_budget_exceeded` |
| `engine_error` | The engine threw; no result for this request is trusted | `on_engine_error` |

Each knob is `block` or `pass`. `strict` blocks on all three gaps, `balanced` passes an oversized body and blocks the other two, `easy` passes all three. `aegis explain config/aegis.yaml` prints the value in force.

#### Where a rule's score comes from

A Suricata rule alerts but does not score, so Aegis derives points in this order:

1. `metadata: score N`, a whole number from 0 to 100, always wins. Any other value makes the rule unsupported.
2. Otherwise the points of the classtype's category at the rule's severity (table below).
3. Severity is `metadata: signature_severity` (Critical, Major, Minor, Informational; `Unknown` counts as absent; any other value makes the rule unsupported). Without it, severity comes from the rule's `priority`, and without that from the classtype's default priority. Priority 1 is Major, 2 is Minor, 3 and above is Informational. Only `signature_severity` can yield Critical.

Points by category and severity:

| Category | Critical | Major | Minor | Informational |
|---|---|---|---|---|
| ATTACK | 5 | 5 | 3 | 1 |
| RECON | 3 | 3 | 2 | 0 |
| POLICY | 2 | 2 | 1 | 0 |
| MISC | 1 | 1 | 0 | 0 |

Classtypes by category and default priority. A classtype missing from the table, or no classtype at all, is MISC at priority 3, which scores 0.

| Category | Priority | Classtypes |
|---|---|---|
| ATTACK | 1 | attempted-admin, attempted-user, successful-admin, successful-user, unsuccessful-user, web-application-attack, trojan-activity, shellcode-detect, exploit-kit, command-and-control, domain-c2, client-side-exploit, credential-theft, targeted-activity |
| ATTACK | 2 | attempted-dos, denial-of-service, successful-dos, misc-attack, default-login-attempt, suspicious-login, system-call-detect, social-engineering |
| RECON | 2 | attempted-recon, successful-recon-limited, successful-recon-largescale, rpc-portmap-decode |
| RECON | 3 | network-scan |
| POLICY | 1 | policy-violation, inappropriate-content |
| POLICY | 2 | pup-activity, coin-mining, external-ip-check |
| MISC | 2 | bad-unknown, non-standard-protocol, suspicious-filename-detect, unusual-client-port-connection, web-application-activity |
| MISC | 3 | unknown, misc-activity, icmp-event, not-suspicious, protocol-command-decode, string-detect |
| MISC | 4 | tcp-connection |

A `web-application-attack` rule with no severity and no priority is ATTACK, priority 1, Major: 5 points, enough to block alone. An ET rule marked `signature_severity Minor` in the same classtype scores 3.

### Declaring rule sets

Each rule file is a named rule set under `rule_sets`:

```yaml
rule_sets:
  - name: aegis-core
    file: config/rules/aegis-core.rules
    mode: block
  - name: et-open
    file: config/rules/emerging-all.rules
    mode: monitor
```

`name`, `file` and `mode` are all required. A relative `file` resolves against the working directory of the process, not against the YAML file. `mode` is one of:

| Mode | Effect of a match |
|---|---|
| `block` | Adds the rule's score to the request total |
| `monitor` | Logged and counted, adds 0 points |
| `disabled` | The rule is not evaluated |

A rule's mode is, in order: the route's setting for its sid, the route's setting for its rule set, the rule set's declared mode. A route changes modes under `rules` (per sid) and `rule_sets` (per set). A sid entry may also set `score`, a whole number of 1 or more that replaces the rule's default:

```yaml
routes:
  - name: default
    # ...
    rule_sets:
      et-open: monitor        # a declared name; an undeclared one is a config error
    rules:
      - sid: 2013504
        mode: block           # promote one rule in a monitor set
        score: 5
      - sid: 9000001
        mode: disabled        # switch one rule off on this route
```

A `rules` entry needs a `sid`, and a sid may appear once per route. A sid mode beats a set mode both ways: a `block` sid inside a `monitor` set scores, and a `disabled` sid inside a `block` set does not. An `exemptions` entry skips by `rule_set:<name>` or `sid:<number>` for chosen client addresses; it needs a reason and an owner.

### The shipped core ruleset

`config/rules/aegis-core.rules` holds 126 rules, all active, all classtype `web-application-attack`, `attempted-admin` or `attempted-recon`. Sids run from 9000001 to 9000808 inside the block 9000001–9000899. The file declares one block per class:

| Class | First sid | Rules | Targets |
|---|---|---|---|
| SQLI | 9000001 | 25 | Union select, quote-then-tautology, stacked statements, time functions, schema probing |
| XSS | 9000101 | 18 | Script and iframe tags, event handlers, `javascript:` calls, `data:text/html` |
| TRAVERSAL | 9000201 | 12 | Dot-dot segments and the system files they reach |
| INCLUSION | 9000301 | 9 | Cloud metadata addresses, loopback and private addresses in URLs, exotic schemes, URL values in file parameters |
| CMDI | 9000401 | 15 | A shell separator followed by a common command and an argument; reverse-shell and shell-invocation strings |
| EXPLOIT | 9000501 | 18 | Log4Shell, Shellshock, Spring4Shell, PHP stream wrappers, Struts OGNL, template injection, XXE |
| EVASION | 9000601 | 7 | Encoding tricks with no honest use; all score 3 |
| SCANNER | 9000701 | 14 | Scanner user agents, read from the User-Agent only; all score 3 |
| PROBE | 9000801 | 8 | Requests for secrets, VCS metadata, config, backups, debug endpoints |
| **Total** | | **126** | |

Most attack-class rules exist in separate variants for each view: the URI (`http.uri; url_decode; to_lowercase`), the body (`http.request_body; url_decode; url_decode; to_lowercase`) and the headers (`http.header; url_decode; url_decode; to_lowercase`). The lowercase view means contents and regexes are written in lowercase.

Every rule sets `score` explicitly in its metadata: 90 rules score 5 and 36 score 3. A 5 blocks alone at the default threshold. A 3 is plausible in legitimate traffic and blocks only with a second signal: a scanner user agent plus a quote-comment, or two 3s together.

#### Known gaps

`src/test/resources/corerules/known-gaps.tsv` records 20 requests the ruleset gets wrong, each with its reason. Nine attacks it misses:

- Overlong UTF-8 separators (`%c0%af`, `%c1%1c`) in a traversal; only the weak C0 evasion rule fires.
- A triple-encoded script tag. The view decodes exactly twice, once by the parser and once by `url_decode`.
- Traversal carried in a header such as `X-Original-URL`. Traversal and file rules read the URI and body only.
- The cloud metadata address written as a decimal integer, hex or octal; only the dotted form is a literal.
- A DNS name that resolves to loopback.
- Newline-separated shell commands with no `;`, `|`, `&&`, `$(` or backtick.
- A double-quote followed by a SQL comment; the quote-comment rules read single quotes only, because JSON strings legitimately end in a double quote.
- SQL tautologies built on `<`, `>` or `LIKE`; tautology rules key on `=`.

Eleven benign requests it blocks or scores: HTML or JSX snippets in a forum post (script tag, iframe embed, event-handler attribute), prose about `UNION SELECT`, a shell pipeline or two shell commands in a post, a search for the hosts file path in a URI, a plain-text body beginning with `1=1`, an OAuth redirect to a local dev server, a `file` parameter holding a CDN URL, and C code with `sleep(` after a semicolon.

### Importing Emerging Threats Open

1. Download the Suricata 7 file into the rules directory:

   ```sh
   curl -o config/rules/emerging-all.rules \
     https://rules.emergingthreats.net/open/suricata-7.0/emerging-all.rules
   ```

2. Declare it with `mode: monitor`, as in the `rule_sets` example above.
3. Run `aegis check config/aegis.yaml`. It opens no sockets and prints, per rule set, the three counts and the ten most common reasons a rule was skipped.
4. Start Aegis. Each rule set logs a `rule_set_loaded` event with the same counts. Watch what the monitored rules match on your traffic.
5. Promote single sids to `block` under a route's `rules`, or switch the whole set to `block` under `rule_sets`.

The importer never fails on a file: every rule line becomes one result, and a malformed line is counted as unsupported. Blank lines and `#` comments (including commented-out rules) are dropped; a trailing backslash continues a rule on the next line. An unreadable file stops startup.

Every rule gets exactly one status:

| Status | What puts a rule there |
|---|---|
| active | Evaluated in full |
| not applicable | The protocol is anything but `http` or `tcp` (DNS, TLS and the like); or a `content` or `pcre` appears before any buffer is named, so it would match raw TCP payload |
| unsupported | Everything else that cannot be applied in full (see below) |

The classifier reads the whole rule before deciding, and not applicable wins over unsupported: a DNS rule that also uses an unknown keyword is not applicable. A rule without a `sid` is unsupported. A skipped rule is never partly applied, because dropping one condition would widen its match.

Unsupported reasons the code produces:

- A keyword outside the supported set (named in the reason).
- A response-side keyword or flow: the rule inspects responses.
- A `pcre` the linear-time engine refuses (lookaround, backreferences, possessive quantifiers), or one with an unsupported flag.
- A `flow` setting outside the supported list.
- `offset`, `depth`, `distance` or `within` with a non-numeric value (a `byte_extract` variable).
- A modifier with no `content` directly before it, a sticky transform with no buffer before it, or a content naming its buffer twice.
- A `content` that is empty, unquoted, uses an escape other than `\\ \" \; \: \|`, or holds a non-ASCII character (write `|hex|` instead).
- A bad `sid`, `rev` or `priority`, a bad `score` or `signature_severity`, an unknown header action or direction, and a header that is not seven fields plus parenthesised options.
- No `content` or `pcre` at all.

The Rule engine section of `docs/lld-in-progress.md` records a measurement on ET Open for Suricata 7 (51,697 rules, November 2026): 13,564 active, 29,012 not applicable, 9,121 unsupported.

### Supported keywords

Only keywords named here are supported. Every other keyword makes the rule unsupported, so a keyword added to Suricata later is never ignored silently.

**Header.** Actions `alert`, `drop`, `reject`, `rejectsrc`, `rejectdst`, `rejectboth`, `pass`, `config` are accepted and stored; the WAF decides by score and mode, not by action. Directions `->` and `<>`. Protocols `http` and `tcp` are inspected. Addresses and ports are checked for shape only and have no effect: every request is client to server on an HTTP port.

**Descriptive options** (they do not change what a rule matches):

| Keyword | Restriction |
|---|---|
| `sid`, `rev`, `gid`, `priority` | Positive whole number |
| `msg` | Quoted; escapes `\\ \" \; \:` removed |
| `classtype` | Looked up in the score table |
| `reference`, `target` | Value required |
| `metadata` | `key value, key value`; `score` and `signature_severity` have meaning (see above) |

**Sticky buffers.** A buffer keyword sets the buffer for every `content` and `pcre` after it, until the next buffer keyword. Each presents the request as one byte per char.

| Keyword | Legacy modifier | Content |
|---|---|---|
| `http.method` | `http_method` | Request method as sent |
| `http.uri` | `http_uri` | Target, percent-decoded once, repeated slashes collapsed, dot segments kept |
| `http.uri.raw` | `http_raw_uri` | Target exactly as sent |
| `http.header` | `http_header` | All headers as `Name: value\r\n` lines, in order sent |
| `http.host` | `http_host` | Host header, lowercased, without the port |
| `http.user_agent` | `http_user_agent` | User-Agent value |
| `http.cookie` | `http_cookie` | Cookie value |
| `http.content_type` | `http_content_type` | Content-Type value |
| `http.request_body` | `http_client_body` | Body up to the scan limit |
| `http.request_line` | none | Method, raw target and version as sent |

A legacy modifier binds to the one content it follows and overrides the sticky buffer for that content. Transforms do not apply to it.

**Transforms**, placed after a sticky buffer and applied in the order written to every later condition on that buffer; a new buffer keyword clears them:

| Transform | Effect |
|---|---|
| `url_decode` | Percent-decode once, `+` becomes a space; a malformed escape stays as written |
| `to_lowercase` | Fold ASCII letters |
| `compress_whitespace` | Collapse each whitespace run to one space |
| `strip_whitespace` | Remove all whitespace |

**Content and its modifiers.** Modifiers must directly follow their `content`; one after a `pcre` does not reach back.

| Keyword | Restriction |
|---|---|
| `content:"..."` | Quoted, ASCII only, non-empty; `\|hex\|` sections; `!` negates |
| `nocase` | ASCII case folding |
| `offset:N`, `depth:N` | Literal numbers; count from the buffer start; the match must start at or after `offset` and end at or before `offset + depth` |
| `distance:N`, `within:N` | Literal numbers; count from the end of the previous match in the same buffer; `within` counts from the end of the `distance` gap |
| `startswith` | Match begins at the buffer start, or at the previous match's end if the content is relative |
| `endswith` | Match ends at the buffer end |
| `fast_pattern` | Any argument form (`only`, `2,3`) sets the flag; the argument is ignored |

A negated content holds when the pattern is absent from its window. It never serves as the prefilter literal.

**pcre.** `pcre:"/regex/flags"`, `!` negates.

| Flag | Meaning |
|---|---|
| `i`, `s`, `m` | Case-insensitive, dot matches newline, multiline |
| `R` | Start at the end of the previous match in this buffer |
| `U` `I` `H` `P` `C` `M` `V` `W` | Buffer: `http.uri`, `http.uri.raw`, `http.header`, `http.request_body`, `http.cookie`, `http.method`, `http.user_agent`, `http.host`. At most one; it overrides the sticky buffer and takes no transforms |

Any other flag makes the rule unsupported. The expression must compile on the RE2/J engine.

**flow.** The settings `to_server`, `from_client`, `established`, `stateless`, `only_stream` and `no_stream` are accepted and have no effect. `to_client` and `from_server` make the rule unsupported (responses); any other setting also does.

**Named as unsupported.** The code and its tests name these as rejected keywords: `flowbits`, `xbits`, `threshold`, `detection_filter`, `byte_test`, `byte_jump`, `byte_extract`, `isdataat`, `dsize`, `urilen`, `bsize`, `lua`, `http.header_names`, `http.accept`, `http.referer`, `tag`, `app-layer-protocol`, `noalert`, `rawbytes`. Response buffers are rejected as response inspection: `http.stat_code`, `http.stat_msg`, `http.response_body`, `http.response_line`, `http.server`, `http.location`, `file.data`, `file_data`, and the modifiers `http_stat_code`, `http_stat_msg`, `http_server_body`. Every other unlisted keyword is rejected the same way.

### Writing your own rule

Put a rule in its own file, declare it, and run `check`. This example works in a scratch copy of the config. `config/rules/my-site.rules`:

```text
# Site rules.
alert http any any -> any any (msg:"MYSITE admin path from outside"; flow:to_server,established; \
    http.uri; content:"/admin/"; nocase; depth:7; \
    http.user_agent; content:"curl/"; startswith; \
    classtype:attempted-recon; sid:9100001; rev:1; \
    metadata:score 3;)
alert http any any -> any any (msg:"MYSITE export with debug flag"; flow:to_server,established; \
    http.uri; content:"/export"; startswith; pcre:"/[?&]debug=(?:1|true)\b/i"; \
    classtype:web-application-attack; sid:9100002; rev:1; \
    metadata:signature_severity Major;)
alert dns any any -> any any (msg:"MYSITE dns rule"; dns.query; content:"evil"; sid:9100003; rev:1;)
alert http any any -> any any (msg:"MYSITE uses threshold"; http.uri; content:"/x"; threshold:type limit, track by_src, count 1, seconds 60; sid:9100004; rev:1;)
```

The first rule matches a URI starting `/admin/` (case-insensitive) from a `curl/` user agent, and scores 3 by its explicit `score`. The second matches `/export` at the start of the URI with a `debug=1` or `debug=true` parameter, and scores 5 (`web-application-attack` is ATTACK priority 1, Major). The last two are deliberate failures: a DNS rule and a `threshold` rule.

Declare the file in the config copy, after `aegis-core`:

```yaml
rule_sets:
  - name: aegis-core
    file: config/rules/aegis-core.rules
    mode: block
  - name: my-site
    file: config/rules/my-site.rules
    mode: monitor
```

Run the check from the directory that holds `config/`, since relative paths resolve against the working directory:

```sh
java -jar target/aegis-0.1.0-SNAPSHOT.jar check config/aegis.yaml
```

```text
rule set aegis-core: 126 active, 0 not applicable, 0 unsupported
rule set my-site: 2 active, 1 not applicable, 1 unsupported
  1 x protocol 'dns' carries traffic Aegis never sees
  1 x uses keyword 'threshold', which Aegis does not support
```

Both working rules are active, and each skipped rule names its reason. Both start in `monitor`. To enforce sid 9100001 on a route, add it under that route:

```yaml
    rules:
      - sid: 9100001
        mode: block
```

A mode that is not `block`, `monitor` or `disabled` fails the check with exit status 2:

```text
The configuration has 1 problem:
  1. rule_sets[1].mode: 'warn' is not one of: block, monitor, disabled.
```

The code and docs state no sid-range convention for user rules beyond the core file's own block, 9000001–9000899. Pick sids that do not collide with a rule set you import: a per-route `rules` entry and an exemption both name a rule by sid alone.

### Caveats

- **Linear-time regex.** `pcre` runs on RE2/J, so no rule can be turned into a ReDoS. A `pcre` that needs lookaround or backreferences makes its whole rule unsupported.
- **First match only.** A `pcre` takes its first match. A `content` retries each occurrence when a later relative condition fails; a `pcre` does not.
- **Not verified against Suricata.** Matching follows Suricata's semantics but has not been compared with Suricata itself on a replayed traffic corpus.
- **Requests only.** Response rules are unsupported, and so are rules that need state across requests (`flowbits`, `threshold`, `detection_filter`).
- **Decoded HTTP, not raw payload.** Rules that match raw TCP bytes are not applicable.
- **Ordinary text can score.** The core ruleset scores structure, not keywords, but its known-gaps file lists benign requests it still blocks (documentation snippets, SQL questions). Run it in `monitor` on a route that serves such content, or lower the score of the offending sid.

## Operating Aegis

### The path of a request

A request passes through the stages below in this order. The first stage that refuses it ends the request, and no later stage sees it. Every refusal that Aegis writes itself has the same shape: `Content-Type: text/plain; charset=utf-8`, an `X-Request-Id` header, and a one-line body, `<reason phrase>. Incident ID: <id>`. The 403 reason phrase is replaced by `Request blocked`. The incident ID is the request ID: 96 random bits, URL-safe base64, 16 characters. The body never names a rule, a score, or a backend. A refused `HEAD` request gets the headers and no body.

| Stage | Refuses with | `decision` in the log | Connection after |
|---|---|---|---|
| TLS handshake | No HTTP response: the handshake fails and the connection closes. A client that sends no server name, or a name with no configured certificate, fails here. | none (see `connection_error` below) | closed |
| Head read | 408 when the head is not complete within `listener.header_timeout` of its first byte | `bad_request` | closed |
| Head parse | 414 when the request line exceeds the smaller of 8192 bytes and `listener.max_header_bytes`; 431 when the headers exceed `listener.max_header_bytes`; 400 for any other malformed request | `bad_request` | closed |
| Body read | 413 when the body exceeds `listener.max_body_bytes` | `bad_request` | closed |
| Framing and hygiene | 400 for ambiguous framing (below) and for a target that does not start with `/` or holds a byte outside printable ASCII; 405 for `CONNECT`; 501 for any request carrying an `Upgrade` header | `bad_request` | open, except 400 |
| Client IP | never refuses; it chooses the address the next stages use | | |
| Firewall | 403 for a deny-listed client, or for any client outside a non-empty allow list; 429 when the client's rate-limit bucket is empty | `firewall_denied`, `rate_limited` | open |
| Routing | 404 when no route matches the host and path | `no_route` | open |
| WAF | 403 when the score reaches `block_threshold`, or when an inspection gap is set to block | `waf_blocked` | open |
| Balancer | 503 when every backend of the route is ejected | `no_backend` | open |
| Upstream | 502 for `connect_error`, `tls_error`, `reset`, `invalid_response`; 504 for `connect_timeout`, `response_timeout` | `upstream_failed`, `upstream_timeout` | open |
| Response | If the backend fails after the first response byte reached the client, no error page is possible: Aegis closes the client connection. The log shows the backend's status and the failure's decision. | `upstream_failed`, `upstream_timeout` | closed |
| Any stage | 500 for a bug inside Aegis; the request is refused rather than guessed at | `internal_error` | closed |

The framing check refuses a request with a header name that holds whitespace or a control character, with both `Content-Length` and `Transfer-Encoding`, with more than one `Content-Length`, `Transfer-Encoding`, or `Host`, with a `Content-Length` that is not plain digits, or with a `Transfer-Encoding` other than `chunked`. It refuses repeated headers even when the copies agree. The 408, 413, and (for an undecodable head) 414 and 431 refusals happen before a request exists, so their log events have no `client_ip` and the route `none`.

A client that disconnects before its response ends is logged with `decision: client_aborted`; nothing is sent. A proxied response carries the backend's status. Aegis replaces the backend's `X-Request-Id` with its own, so the ID in the response header always finds the log event.

### The event log

Aegis writes one JSON object per line to `<log.directory>/aegis.log` (default `logs/`, created at startup). Events are queued and written by one thread, so the data path never waits on the disk. The queue holds 65,536 events. When it is full, Aegis drops new events and counts them; the writer then logs a `log_events_dropped` event with the count. If the file cannot be written, Aegis counts the failure and prints `aegis event log: <what>: <cause>` to standard error at most once a minute.

**Rotation.** After each line, if the file has reached `log.rotate_at` bytes (default 100MB), `aegis.log` becomes `aegis.log.1`, `.1` becomes `.2`, and so on. Files past `log.keep_files` (default 10, at least 1) are deleted. A file may exceed `rotate_at` by one line. After a restart, Aegis appends to the existing `aegis.log`.

Every line starts with `ts` (UTC, millisecond precision, `2026-11-16T09:30:00.123Z`) and `type`. A field with no value is omitted.

**Event types.**

| `type` | Written when | Fields after `ts` and `type` |
|---|---|---|
| `request` | every request ends, whatever the outcome | table below |
| `startup` | listeners are bound | `profile`, `port`, `admin_port` (omitted if the admin listener is off), `tls`, `routes` (names), `rules` (rules compiled, all sets) |
| `rule_set_loaded` | once per rule set at startup | `rule_set`, `active`, `not_applicable`, `unsupported` |
| `certificate` | a certificate loads, reloads, or fails to reload | `hostname`, `kind` (`loaded`, `reloaded`, `reload_failed`), `detail` (SHA-256 fingerprint and `notAfter`, or the reason) |
| `backend_failure` | an attempt is charged to a backend's health | `request_id`, `backend`, `cause`, `detail` (exception class and message, when there is one) |
| `backend_ejected` | a failure takes a backend out of rotation | `request_id`, `backend`, `route` |
| `engine_error` | the rule engine throws | `route`, `exception`, `message` |
| `connection_error` | a client connection fails outside a request and the cause is not an I/O error | `peer_ip`, `cause` (class name), `detail` |
| `internal_error` | a bug while handling a request | `request_id`, `cause`, `detail` |
| `log_events_dropped` | the queue overflowed | `count` |
| `shutdown` | the drain ended | `requests_cut_off` |

**Fields of a `request` event.**

| Field | Meaning |
|---|---|
| `request_id` | the ID in the `X-Request-Id` header and the incident ID |
| `client_ip` | the address the firewall and exemptions used (see client IP below); absent if the request never got that far |
| `peer_ip` | the TCP peer |
| `method`, `host`, `user_agent` | as sent. `user_agent` is cut to 200 characters. |
| `target` | the raw request target with query values redacted |
| `route` | the matched route name, or `none` |
| `status` | the status the client received, or the backend's; `0` if none was sent |
| `decision` | `allowed`, `bad_request`, `firewall_denied`, `rate_limited`, `no_route`, `waf_blocked`, `no_backend`, `upstream_failed`, `upstream_timeout`, `internal_error`, `client_aborted` |
| `reason` | why Aegis refused: `deny_listed`, `not_allow_listed`, `rate limit`, `waf`, `every backend is ejected`, an upstream failure label, or the parse or framing message |
| `waf_score` | sum of the scores of block-mode hits (present when the request reached the WAF; `waf_hits`, `inspection_gaps`, and `exemptions` then appear as empty lists when they are empty) |
| `waf_hits` | list of `{sid, rev, msg, rule_set, mode, score}`; monitor-mode hits are listed with score 0 |
| `inspection_gaps` | any of `body_over_scan_limit`, `time_budget_exceeded`, `engine_error` |
| `exemptions` | names of exemptions that skipped something for this client |
| `backend` | the last backend tried, as `host:port` |
| `retried` | `true` if the request went to a second backend |
| `request_bytes`, `response_bytes` | body sizes |
| `upstream_ms` | time spent on the backend exchange |
| `total_ms` | time from the moment the whole request was read to its end |
| `body` | `{length, sha256}` of the request body; present only when the WAF blocked the request |

**What the redactor removes.** The log is safe without configuration. Query values are masked as `[redacted]` unless the parameter name is in `log.logged_query_params` (default `page`, `limit`, `sort`); the match is on the raw, exact name, so `Page` and `%70age` do not match. The path and every parameter name stay. Only `User-Agent` is logged as a header; a header value is masked when the name is `authorization`, `proxy-authorization`, `cookie`, or `set-cookie`, or contains `token`, `secret`, `api-key`, `apikey`, or `password`. A body is never logged: a blocked request gets its length and SHA-256, which lets you compare bodies without keeping them.

### Admin endpoints

The admin listener has its own socket (`admin.bind`, default `127.0.0.1`, and `admin.port`, default `9090`) and thread, never proxies traffic, and has no authentication. Set `admin.enabled: false` to turn it off. It answers `GET` only and ignores query strings. Each response carries `Allow: GET` and closes the connection. Error bodies end with a newline.

| Request | Response |
|---|---|
| `GET /metrics` | 200, `text/plain; version=0.0.4; charset=utf-8`, Prometheus text |
| `GET /healthz` | 200, body `ok`. It proves the process answers; it does not check backends, certificates, or rules. |
| any other path | 404, body `not found` |
| any other method | 405, body `method not allowed` |
| undecodable request | 400, body `bad request` |

There is no readiness endpoint.

### Metrics

Counters appear with the `_total` suffix; each histogram has `_bucket`, `_sum`, and `_count` series. Latency buckets run from 50 microseconds to 1 second.

| Metric | Type | Labels | Meaning |
|---|---|---|---|
| `aegis_requests_total` | counter | `route`, `decision` | requests by route and how they ended |
| `aegis_request_duration_seconds` | histogram | `route` | from the moment the whole request is read to the end of the response |
| `aegis_waf_inspection_seconds` | histogram | none | WAF time per inspected request |
| `aegis_waf_rule_hits_total` | counter | `rule_set`, `sid`, `mode` | rule matches; `mode` is `block` or `monitor` |
| `aegis_inspection_gaps_total` | counter | `gap`, `blocked` | requests not inspected in full; `gap` is `body_over_scan_limit`, `time_budget_exceeded`, or `engine_error`; `blocked` is `true` or `false` |
| `aegis_firewall_decisions_total` | counter | `verdict` | `allow`, `deny_listed`, `not_allow_listed`, `rate_limited` |
| `aegis_backend_requests_total` | counter | `backend`, `result` | attempts: `success`, `server_error` (a 5xx), `client_aborted`, or a failure label (see load balancing) |
| `aegis_backend_failures_total` | counter | `backend`, `cause` | attempts charged to a backend's health |
| `aegis_backend_ejections_total` | counter | `backend` | times a backend left rotation |
| `aegis_certificate_events_total` | counter | `hostname`, `kind` | `loaded`, `reloaded`, `reload_failed` |
| `aegis_rules_loaded_total` | counter | `rule_set`, `status` | rules per set at startup: `active`, `not_applicable`, `unsupported` |
| `aegis_connection_errors_total` | counter | `cause` | client connections that failed outside a request, by exception class (simple name) |
| `aegis_rate_limit_tracked_clients` | gauge | none | clients holding a rate-limit bucket |
| `aegis_log_events_dropped` | gauge | none | events dropped because the queue was full |
| `aegis_log_write_failures` | gauge | none | events that could not be written to the local file |
| `aegis_log_sink_failures` | gauge | none | events a log sink refused (always 0 in this release; see plugins) |
| `aegis_metrics_series_overflow_total` | counter | `metric` | observations folded into `other` by the series guard |

The series guard limits every counter and histogram to 10,000 distinct label combinations. Past that, new combinations are recorded with every label set to `other`, and `aegis_metrics_series_overflow_total{metric="<name>"}` counts each fold. Existing combinations keep counting. Only `cause` on `aegis_connection_errors_total` follows traffic; every other label is bounded by your configuration and rule files.

### Load balancing

**Selection.** Each route round-robins over its `backends`, in configured order, skipping ejected ones. With every backend healthy the split is exactly even. When one is ejected, the backend after it takes a double share until it returns.

**Passive health.** Aegis judges a backend by the requests it serves; it sends no probes. `failures_to_eject` consecutive failures (default 3) eject a backend for `ejection_time` (default 5s). A failure is a connect error, a connect timeout, a TLS error, a response timeout, an invalid response, or a connection reset. A 5xx response counts only with `health.count_server_errors: true`; otherwise it counts as a success. A success resets the count. When the time passes, the backend rejoins on probation: one more failure ejects it again for a full `ejection_time`, and one success restores it fully. A failure reported while the backend is already ejected is ignored. A reset on a reused idle connection before any response byte is not charged, because the backend most likely closed that connection while it sat idle. When every backend is ejected, requests get 503 `no_backend` until one returns.

**Retry.** A request is retried at most once, on a different healthy backend. It is retried when the failure came before any response byte went to the client, and either the request was not yet sent (connect failure, connect timeout, TLS failure) or the method is `GET`, `HEAD`, `OPTIONS`, `PUT`, or `DELETE` (case-sensitive). `POST`, `PATCH`, and any other method are not retried once sent, since the backend may have acted. A route with one backend, or with no other healthy backend, has no retry. The log shows `retried: true`. A 5xx from the backend is relayed, never retried.

Separately, if a write fails on a pooled connection the backend closed while idle, Aegis opens one fresh connection to the same backend. This is not the retry above and charges nothing.

**Failure labels** (`cause` and `result`): `connect_error`, `connect_timeout` (also a TLS handshake that exceeds `connect_timeout`), `tls_error`, `response_timeout`, `reset`, `invalid_response`, `server_error`.

**Timeouts.**

| Knob | Default | Effect |
|---|---|---|
| `connect_timeout` | 2s | connect plus, for TLS backends, the handshake |
| `response_timeout` | 30s | armed when the request is sent and re-armed at the response head and at each body chunk; it limits silence from the backend, not total duration. It pauses while the client's socket is full. |

**Connections.** Each event-loop thread keeps idle keep-alive connections per backend: at most 32 per backend, none idle longer than 15 seconds, most recently used first. Backend host names resolve once at startup, so a changed DNS record needs a restart. Aegis reads the whole client request (up to `max_body_bytes`) before it contacts a backend, then streams the response back and pauses reading from the backend while the client is slow. It always speaks HTTP/1.1 to backends, ignores `1xx` interim responses, and drops response trailers. A client connection serves one request at a time; pipelined requests wait and are served in order. A client connection idle for `listener.idle_timeout` (default 60s) closes.

**Headers.** In both directions Aegis removes `Connection`, `Keep-Alive`, `Proxy-Authenticate`, `Proxy-Authorization`, `TE`, `Trailer`, `Transfer-Encoding`, `Upgrade`, and every header that `Connection` names, except `Host` and `Content-Length`. Toward the backend it also:

- removes `Expect`, since Aegis already answered `100-continue`;
- appends the TCP peer to `X-Forwarded-For`, keeping whatever the client sent;
- sets `X-Forwarded-Proto` to `https` or `http`, by the listener's TLS setting;
- sets `X-Request-Id` to the request ID;
- rebuilds `Content-Length` from the body it holds;
- passes `Host` through unchanged.

Toward the client it replaces `X-Request-Id`, sets `Transfer-Encoding: chunked` on a response that has no length when the client speaks HTTP/1.1, and closes the connection after such a response for an HTTP/1.0 client.

**Client IP.** The TCP peer is the client. If the peer is inside `client_ip.trusted_proxies`, Aegis reads `X-Forwarded-For` from the right and takes the first hop that is not trusted. An unparseable hop stops the walk at the hop to its right. If every hop is trusted, the leftmost hop is the client. The firewall, exemptions, rate limit, and log all use this address.

### TLS

**Listener.** With `listener.tls: true`, Aegis speaks TLS 1.3 and 1.2 and advertises only `http/1.1` through ALPN. It picks the certificate by the client's server name: an exact match on a `tls` entry's `hostname`, then a single-label wildcard (`a.example.com` matches `*.example.com`; `a.b.example.com` does not). Names compare in lowercase. There is no default certificate: a client that sends no server name, or an unmatched one, fails the handshake and never sees another host's certificate. Keys must be unencrypted PKCS#8, RSA or EC.

`tls[].mode` is parsed and printed by `aegis explain`, but no runtime code reads it. `transparent` does not work: every host presents its own configured certificate, as `reverse_proxy` does, and Aegis never copies the origin's certificate.

**Certificate providers.** The built-in type is `file_watch` with `cert_file`, `key_file`, and `poll_interval` (default `5s`; units `ms`, `s`, `m`, `h`). At startup it loads both files and checks that the key matches the certificate. It then polls and compares a SHA-256 of both files' contents (not their timestamps). On a change that loads cleanly, new handshakes use the new certificate; established connections keep the old one. A change that fails, such as a half-written file or a certificate replaced before its key, produces one `reload_failed` event per bad state; the previous certificate stays in service until the files agree. No restart is needed.

**Upstream TLS.** Set `upstream_tls.enabled: true` on a route to reach its backends over TLS 1.3 or 1.2. Aegis always verifies the backend, in one of three ways (if both `pinned_sha256` and `trusted_ca` are set, the pin is used and the CA is ignored):

| Setting | Verification |
|---|---|
| `pinned_sha256` | the SHA-256 of the leaf certificate's DER encoding must equal the pin. Nothing else is checked: not the issuer, the dates, or the host name. This suits self-signed origins. |
| `trusted_ca` | the chain must verify against that PEM bundle, and the certificate must match the backend host name |
| neither | the same, against the JVM's trust store |

Aegis sends the configured backend host name as the server name (SNI) and verifies against it, never the resolved address. It sends that name even when it has no dot, such as `appserver1`, which the JDK would otherwise omit. An IP literal is not sent as a server name. Setting `trusted_ca` or `pinned_sha256` with `enabled: false` is a configuration error.

**Plugins.** `CertificateProviderFactory` (methods `type()` and `create(Map<String,String>)`) builds a `CertificateProvider` (`load()`, `watch(listener, onFailure)`, `close()`). Aegis finds factories with `java.util.ServiceLoader`: put the plugin on the classpath with a `META-INF/services/io.aegis.plugin.CertificateProviderFactory` entry, and select it with `certificate.type`. The settings under `certificate` other than `type` reach `create` as strings. Two factories with the same type stop startup. `LogSink` (`accept(String jsonLine)`, `close()`) is defined, but nothing discovers or installs a sink in this release; the server starts its event log with an empty sink list.

### Startup and shutdown

`aegis run <config>` validates, then opens parts in dependency order, and if any step fails it closes what it opened and exits. It checks, in order:

1. The configuration: every problem is reported together, then exit 2.
2. Each rule file is read and classified; one that cannot be read stops startup.
3. Each route's `upstream_tls` files load and its backend host names resolve.
4. Certificates load and match their keys (only when `listener.tls` is true).
5. The listener port and the admin port bind.

It logs one `rule_set_loaded` event per set (`active`, `not_applicable`, `unsupported`), one `certificate` event per host, and a `startup` event, and prints `aegis listening on port <port>` on standard output. `aegis check <config>` prints the rule counts per set plus, for each set, the ten most common reasons rules were skipped, and opens no sockets or certificates. It does not validate certificates or resolve backends. `aegis explain <config>` prints every knob's value and its source, then a `Loosened` list.

| Exit code | Meaning |
|---|---|
| 0 | stopped by SIGTERM or SIGINT after the drain |
| 1 | startup failure; standard error starts `Cannot start: ` |
| 2 | wrong arguments (`Usage: aegis run\|explain\|check <config.yaml>`) or a configuration error |

A failure to load a certificate, or a bad `upstream_tls` file, is not a `StartupException`: the CLI does not catch it and the JVM prints a stack trace.

**Shutdown.** On SIGTERM or SIGINT Aegis stops accepting connections, closes idle client connections, and marks every later response `Connection: close`. It waits up to `listener.drain_timeout` (default 30s) for requests in flight to finish, then writes a `shutdown` event with `requests_cut_off`, stops the worker threads (up to 5 more seconds), closes the admin listener and certificate watchers, flushes the log, and exits 0. Requests still running at the deadline are cut off.

### Limits of this release

The README's list of what is not built: HTTP/2 and WebSocket (a request with an `Upgrade` header gets 501), response inspection, blind-window passthrough, floors, hot reload of configuration, the console, egress controls, SSH, the investigation agent, and endpoint agents. Configuration is read once. `AegisServer.start` takes an immutable configuration, rule files are parsed once, backend names resolve once, and the only signal handler is the shutdown hook. A change to the YAML, a rule file, or a backend's DNS takes effect on restart. Certificate files are the one exception. Beyond the README: `tls[].mode: transparent` has no effect, and no `LogSink` can be installed.

## Troubleshooting

Start with the request ID. Every refusal returns it in `X-Request-Id` and the body; `grep <id> logs/aegis.log` finds the `request` event, whose `decision` and `reason` name the stage.

| Symptom | Likely cause | What to check |
|---|---|---|
| `The configuration has N problems:` and exit 2 | invalid YAML values or unknown keys; all are listed with their location | fix each numbered line; `aegis explain` shows the result once it loads |
| `listener.tls is true but there is no 'tls' entry to say which certificate to present...` | TLS on, no `tls` list | add a `tls` entry, or set `listener.tls: false` behind a TLS terminator |
| `Cannot start: Cannot listen on 0.0.0.0:8443: ...` | port in use or not permitted | `listener.port`, another process, privileges below 1024 |
| `Cannot start: Cannot listen on 127.0.0.1:9090 for the admin endpoint: ...` | admin port in use | `admin.port`, or `admin.enabled: false` |
| `Cannot start: Cannot read rule file <file> for rule set '<name>': ...` | wrong path (relative to the working directory) or unreadable file | the `rule_sets[].file` path and permissions |
| `Cannot start: Cannot resolve backend host '<host>'` | name does not resolve at startup | DNS and `/etc/hosts` on the Aegis host |
| Stack trace with the message `TLS host <name>: cert_file <path> cannot be read: ...` | missing or unreadable certificate file | paths in `certificate`, file permissions |
| Stack trace with `key_file <path> does not match the certificate in cert_file <path>` | key and certificate come from different pairs | regenerate or copy both together |
| Stack trace with `the key is encrypted; provide an unencrypted PKCS#8 key` or `no PKCS#8 'BEGIN PRIVATE KEY' block found` | key format | convert to unencrypted PKCS#8 PEM |
| Stack trace with `uses unknown certificate provider type '<type>'; available types: [file_watch]` | misspelled type, or a plugin jar missing from the classpath | `certificate.type`, plugin `META-INF/services` entry |
| Stack trace with `two certificate provider factories claim the type <type>` | two plugins register one type | remove one from the classpath |
| Stack trace with `TLS hostname <name> is configured twice` | duplicate `tls` hostname | the `tls` list |
| `aegis check` passes but `run` fails | `check` loads rules only | run `run` on a scratch port; certificates and backends are validated only there |
| Client TLS handshake fails | no SNI (client connected by IP address), or a name with no `tls` entry | connect by host name, add the name or a `*.` wildcard; look for `connection_error` events and `aegis_connection_errors_total` |
| Browser keeps the old certificate after renewal | established connections are not replaced | new connections use it; confirm a `certificate` event with `kind: reloaded` |
| `certificate` event with `kind: reload_failed` | new files are unreadable, mismatched, or half-written | the `detail` field; the old certificate keeps serving until the files agree |
| 400, reason starts `malformed request:` | a request Netty cannot parse | `reason` in the event |
| 400, reason mentions `Content-Length`, `Transfer-Encoding`, or `Host` | ambiguous framing, repeated `Content-Length`, `Transfer-Encoding`, or `Host`, or a bad value | the client or an upstream proxy rewriting framing |
| 400, reason `request target must start with '/' and hold only printable ASCII` | absolute-form URL, or non-ASCII bytes in the target | send an origin-form target, percent-encode |
| 414, 431 | request line over 8192 bytes, or headers over `listener.max_header_bytes` | raise `max_header_bytes` (the request line limit stays at most 8192) |
| 413 | body over `listener.max_body_bytes` (default 10MB) | raise it, or fix the client |
| 408 | head not complete within `listener.header_timeout` (default 10s) | slow client or a stalled proxy |
| 405 `CONNECT is not supported` / 501 `WebSocket upgrade is not supported` | `CONNECT` is refused, and any `Upgrade` header (WebSocket, h2c) gets 501 | use plain HTTP/1.1 requests without `Upgrade` |
| 403 with `Incident ID` | WAF block, deny list, or allow list | `decision` is `waf_blocked` or `firewall_denied`; for the WAF read `waf_hits` and `waf_score` against `block_threshold` |
| 403 for everyone, `reason: not_allow_listed` | `firewall.allow` is non-empty and the client is outside it, often because the client IP is a proxy | `client_ip` vs `peer_ip` in the event; set `client_ip.trusted_proxies` |
| 403 `waf_blocked` with no hits and `inspection_gaps` set | a gap is set to block: oversized body, 5ms budget, or engine error. A `time_budget_exceeded` gap with a WAF score of 0 is usually a garbage-collection pause, not a slow rule | profile defaults; `waf.on_body_over_limit`, `on_budget_exceeded`, `on_engine_error`; `engine_error` events |
| Attack passes in a monitor-mode set | monitor hits score 0 | `waf_hits[].mode` is `monitor`; promote the set or rule to `block` |
| 429 | rate-limit bucket empty (default 100 per second, burst 50, per /32 or /64) | `rate_limit` knobs; `client_ip` may be a shared proxy; an exemption can skip `rate_limit` |
| 404 with `Incident ID` | no route matches the host and path (first match in file order; dot segments are resolved first) | `route`, `host`, `target` in the event; `routes[].host` and `path_prefix` |
| 503 `reason: every backend is ejected` | every backend failed `failures_to_eject` times within `ejection_time` | `backend_ejected` and `backend_failure` events; the backends; wait `ejection_time` |
| 502, reason `connect_error` | backend refuses or is unreachable | `backend_failure.detail`, address and port |
| 502, reason `tls_error` | backend certificate rejected: wrong pin, untrusted CA, or name mismatch | `detail`; `pinned_sha256`, `trusted_ca`, and that the backend certificate covers the host name in `backends` |
| 502, reason `reset` or `invalid_response` | backend closed mid-request, or answered with a malformed or over-large head (status line over 4096 bytes, headers over 16KB) | the backend's logs |
| 504, reason `connect_timeout` | connect or TLS handshake slower than `connect_timeout` (2s) | network path, backend load, the timeout |
| 504, reason `response_timeout` | no response bytes for `response_timeout` (30s) | slow backend; raise the timeout for long operations |
| Backend returns 5xx but is never ejected | `count_server_errors` is false by default | set it to `true` to eject on 5xx |
| A POST fails with 502 where a GET succeeds | only non-sent requests and idempotent methods are retried | `retried` in the event |
| Backend sees only the proxy's address | Aegis connects from its own address | read `X-Forwarded-For`; Aegis appends the TCP peer |
| New backend address ignored after a DNS change | names resolve once | restart |
| Config or rule edit has no effect | no hot reload | restart |
| `aegis_log_events_dropped` rises, or a `log_events_dropped` event appears | the 65,536-event queue overflowed; the disk is too slow | disk speed, `log.directory` |
| `aegis event log: cannot write aegis.log: ...` on stderr | disk full or permission error | `log.directory`; `aegis_log_write_failures` |
| A metric shows only `other` label values | the 10,000-series limit was hit | `aegis_metrics_series_overflow_total{metric=...}` names the metric |
| Requests cut off at shutdown | in-flight work outlived `drain_timeout` | `requests_cut_off` in the `shutdown` event; raise `listener.drain_timeout` |
