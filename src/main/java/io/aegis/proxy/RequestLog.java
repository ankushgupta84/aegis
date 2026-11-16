package io.aegis.proxy;

import io.aegis.observe.Event;
import io.aegis.observe.Redactor;
import io.aegis.waf.RuleHit;
import io.aegis.waf.WafVerdict;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/** Builds the one {@code request} event written per request, whatever way it ended. */
final class RequestLog {

    private static final int MAX_LOGGED_HEADER = 200;

    private RequestLog() {
    }

    static Event event(RequestRecord r, Redactor redactor) {
        long now = System.nanoTime();
        Event event = Event.of("request")
                .with("request_id", r.id)
                .with("client_ip", r.clientIp == null ? null : r.clientIp.getHostAddress())
                .with("peer_ip", r.peer == null ? null : r.peer.getHostAddress())
                .with("method", r.method)
                .with("target", r.rawTarget == null ? null : redactor.target(r.rawTarget))
                .with("host", r.host)
                .with("user_agent", r.userAgent == null ? null
                        : truncate(redactor.headerValue("User-Agent", r.userAgent)))
                .with("route", r.routeName)
                .with("status", r.status)
                .with("decision", r.decision.label())
                .with("reason", r.reason);
        addVerdict(event, r.verdict);
        return event
                .with("backend", r.backend)
                .with("retried", r.retried)
                .with("request_bytes", r.requestBytes)
                .with("response_bytes", r.responseBytes)
                .with("upstream_ms", millis(r.upstreamNanos))
                .with("total_ms", millis(now - r.startNanos))
                .with("body", r.blockedBody == null ? null
                        : Map.of("length", r.blockedBody.length(), "sha256", r.blockedBody.sha256Hex()));
    }

    private static void addVerdict(Event event, WafVerdict verdict) {
        if (verdict == null) {
            return;
        }
        event.with("waf_score", verdict.score())
                .with("waf_hits", verdict.hits().stream().map(RequestLog::hit).toList())
                .with("inspection_gaps", verdict.gaps().stream().map(g -> g.name().toLowerCase(Locale.ROOT)).toList())
                .with("exemptions", List.copyOf(verdict.appliedExemptions()));
    }

    private static Map<String, Object> hit(RuleHit hit) {
        Map<String, Object> fields = new LinkedHashMap<>();
        fields.put("sid", hit.sid());
        fields.put("rev", hit.rev());
        fields.put("msg", hit.msg());
        fields.put("rule_set", hit.ruleSet());
        fields.put("mode", hit.mode().name().toLowerCase(Locale.ROOT));
        fields.put("score", hit.score());
        return fields;
    }

    private static double millis(long nanos) {
        return Math.round(nanos / 1e3) / 1e3;
    }

    private static String truncate(String value) {
        return value.length() <= MAX_LOGGED_HEADER ? value : value.substring(0, MAX_LOGGED_HEADER);
    }
}
