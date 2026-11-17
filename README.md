# Aegis

A firewall, a WAF, and a load balancer on one path: one TLS termination, one parse, one policy. Aegis runs Suricata rules as they are, so Emerging Threats rulesets import unchanged.

How to run, configure, and operate it: [`docs/guide.md`](docs/guide.md). Why it exists, and for whom: [`docs/product.md`](docs/product.md). How it is designed, with the reason for each decision: [`docs/high-level-design.md`](docs/high-level-design.md). What is still undecided: [`docs/lld-in-progress.md`](docs/lld-in-progress.md).

## What is built

The ingress core:

```
client ──TLS──► Aegis ──► backend
                 │
                 ├─ firewall   IP allow and deny lists, token-bucket rate limit per client
                 ├─ WAF        Suricata rules, scored; a total of 5 or more blocks
                 ├─ balancer   round-robin, passive health checks, one safe retry
                 └─ logs and metrics at every stage
```

Not built yet: HTTP/2 and WebSocket, response inspection, blind-window passthrough, floors, hot reload of configuration, the console, egress controls, SSH, the investigation agent, endpoint agents. Each is described in the docs as part of the whole product.

## Run it

Requires Java 21 or later and Maven.

```sh
mvn -q package -DskipTests          # builds target/aegis-0.1.0-SNAPSHOT.jar
scripts/dev-certs.sh                # a self-signed certificate for localhost

JAR=target/aegis-0.1.0-SNAPSHOT.jar
java -cp $JAR io.aegis.loadtest.DummyBackend --port 9001 --name backend-a &
java -cp $JAR io.aegis.loadtest.DummyBackend --port 9002 --name backend-b &
java -jar $JAR run config/aegis.yaml
```

Then, from another shell:

```sh
CURL="curl -s --cacert config/certs/localhost.crt"
$CURL https://localhost:8443/                         # backend-a, then backend-b, alternating
$CURL "https://localhost:8443/?id=1'+union+select+1"  # 403 with an incident ID
$CURL http://127.0.0.1:9090/metrics                   # Prometheus metrics
tail -f logs/aegis.log                                # one JSON event per request
```

Two more commands read a configuration without serving traffic:

```sh
java -jar $JAR explain config/aegis.yaml   # every knob's value in force and where it came from
java -jar $JAR check config/aegis.yaml     # how many rules are active, not applicable, unsupported
```

## Configuration

One YAML file; [`config/aegis.yaml`](config/aegis.yaml) is the commented reference. Three ideas carry it:

- **Profiles.** `strict`, `balanced`, or `easy` supplies every knob. A global section overrides the profile, and a route overrides the global section. The narrowest scope wins.
- **Fail modes are knobs.** A body over the scan limit, an inspection that runs out of time, and an engine error each have their own block-or-pass setting. Whichever is chosen, the event is logged and counted.
- **Loosening is visible.** An exemption names exactly what it skips and must give a reason and an owner. `aegis explain` ends with a list of everything loosened.

Unknown keys and bad values are errors, reported together in plain language. Nothing is ignored or guessed.

## Rules

Aegis ships [`config/rules/aegis-core.rules`](config/rules/aegis-core.rules): web-attack rules in Suricata syntax, in block mode. To add Emerging Threats:

```sh
curl -o config/rules/emerging-all.rules \
  https://rules.emergingthreats.net/open/suricata-7.0/emerging-all.rules
```

Declare it under `rule_sets` with `mode: monitor`, and promote rules or the whole set to `block` once you have seen what they match on your traffic.

Each imported rule is classified, and the counts are logged at startup:

| Status | Meaning |
|---|---|
| active | Evaluated in full |
| not applicable | Written for traffic Aegis never sees (DNS, raw TCP, ...) |
| unsupported | Uses a keyword Aegis does not implement; skipped whole, never partly applied |

Of ET Open's 51,697 rules, 13,564 are active today. The breakdown and the keywords worth adding next are in [`docs/lld-in-progress.md`](docs/lld-in-progress.md).

**Caveats.** Matching follows Suricata's semantics but has not been verified against Suricata itself with a replayed traffic corpus. Regular expressions run on a linear-time engine, so a `pcre` that needs lookaround or backreferences makes its rule unsupported. A `pcre` takes its first match only.

## Performance

`scripts/kill-test.sh` runs the test defined in `docs/product.md` §8: the same open-loop load sent straight to a backend and then through Aegis, with the difference in p99 as the result. The load generator measures each request from its intended send time, so a slow server cannot hide its own tail latency.

The sample configuration does not pass it yet. Its 100 requests-per-second rate limit throttles the load generator, so measure with `firewall.rate_limit.enabled: false`. With that change, at 1,000 rps on a 20-core machine, Aegis adds 0.6 ms at p50 and 9.6 ms at p99, but blocks about 2% of benign requests: the 5 ms inspection budget counts garbage-collection pauses, and `balanced` blocks on an overrun. The [guide](docs/guide.md#measuring-overhead) has the details.

## Layout

One package per concern under `src/main/java/io/aegis/`:

| Package | Concern |
|---|---|
| `http` | The single parse: request buffers, URI normalization, framing checks, client IP |
| `firewall` | IP access list and rate limiter |
| `rules` | Suricata rule parser, classifier, score table |
| `waf` | Multi-pattern prefilter, rule engine, verdicts under policy |
| `lb` | Round-robin, passive health, retry policy |
| `policy` | The resolved configuration every stage reads |
| `config` | YAML loading, validation, profile resolution, `explain` |
| `observe` | JSON event log, redaction, metrics |
| `tls` | Certificate providers, SNI, verified upstream TLS |
| `plugin` | Interfaces for certificate providers and log sinks |
| `proxy` | The Netty pipeline and the composition root |
| `loadtest` | Open-loop load generator and dummy backend |

`mvn test` runs everything, including end-to-end tests on ephemeral ports.
