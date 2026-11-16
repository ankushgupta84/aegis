#!/usr/bin/env bash
# The latency kill test from docs/product.md §8: the same open-loop load is sent straight to a
# backend and then through Aegis, and the difference in p99 is the latency Aegis adds.
#
#   scripts/kill-test.sh [config] [rate] [duration] [warmup]
#
# Start the backends named in the config and Aegis itself before running this. See README.md.
set -euo pipefail

cd "$(dirname "$0")/.."
CONFIG="${1:-config/aegis.yaml}"
RATE="${2:-5000}"
DURATION="${3:-600s}"
WARMUP="${4:-120s}"
DIRECT_URL="${DIRECT_URL:-http://127.0.0.1:9001}"
AEGIS_URL="${AEGIS_URL:-https://localhost:8443}"
TRUST="${TRUST:-config/certs/localhost.crt}"
OUT="${OUT:-target/kill-test}"
JAR=target/aegis-0.1.0-SNAPSHOT.jar

[ -f "$JAR" ] || { echo "Build first: mvn -q package -DskipTests" >&2; exit 2; }
mkdir -p "$OUT"

load() {  # label url extra-args...
  local label="$1" url="$2"; shift 2
  java -cp "$JAR" io.aegis.loadtest.LoadTester --url "$url" --rate "$RATE" \
    --duration "$DURATION" --warmup "$WARMUP" --connections 64 --new-connection-share 0.05 \
    --post-share 0.30 --body-min 1KB --body-max 64KB --seed 1 \
    --label "$label" --json "$OUT/$label.json" "$@"
}

echo "== Rules loaded =="
java -jar "$JAR" check "$CONFIG"

# The direct run carries no attack payloads: the bare backend would answer them 200, which says
# nothing about latency. Through Aegis, 1% of requests are attacks and must come back 403.
load direct "$DIRECT_URL" --attack-share 0
load via-aegis "$AEGIS_URL" --attack-share 0.01 --tls-trust "$TRUST"

python3 - "$OUT" <<'PY'
import json, sys
out = sys.argv[1]
direct = json.load(open(f"{out}/direct.json"))
aegis = json.load(open(f"{out}/via-aegis.json"))

print("\n== Added latency (via Aegis minus direct) ==")
for percentile in ("p50", "p99"):
    d, a = direct["latencyMs"][percentile], aegis["latencyMs"][percentile]
    print(f"{percentile}: direct {d:.3f} ms, via Aegis {a:.3f} ms, added {a - d:.3f} ms")

added_p99 = aegis["latencyMs"]["p99"] - direct["latencyMs"]["p99"]
unblocked = aegis["attackRequests"] - aegis["expectedAttackBlocks"]
problems = []
if added_p99 >= 10:
    problems.append(f"added p99 is {added_p99:.3f} ms, over the 10 ms budget")
for name, report in (("direct", direct), ("via Aegis", aegis)):
    if report["errors"] or report["otherNon2xx"]:
        problems.append(f"{name}: {report['errors']} errors, {report['otherNon2xx']} unexpected non-2xx")
    if report["achievedRate"] < 0.99 * report["configuredRate"]:
        problems.append(f"{name}: achieved {report['achievedRate']:.0f} rps of {report['configuredRate']}")
if unblocked:
    problems.append(f"{unblocked} of {aegis['attackRequests']} attack requests were not blocked")
print("PASS" if not problems else "MISS:\n  " + "\n  ".join(problems))
sys.exit(1 if problems else 0)
PY
