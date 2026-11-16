package io.aegis.proxy;

import io.aegis.firewall.Firewall;
import io.aegis.observe.CounterHandle;
import io.aegis.observe.EventLog;
import io.aegis.observe.HistogramHandle;
import io.aegis.observe.Metrics;
import io.aegis.firewall.FirewallVerdict;
import io.aegis.policy.BackendAddress;
import io.aegis.rules.RuleSet;
import io.aegis.rules.RuleStatus;
import io.aegis.tls.CertificateEvent;
import io.aegis.waf.InspectionGap;
import io.aegis.waf.RuleHit;
import java.util.Locale;

/**
 * Owns every metric handle of the proxy, so the stages report facts by name and none of them
 * knows a metric name or label order.
 */
final class ProxyMetrics {

    /** From 50 microseconds to one second: the latency budget is under 10 ms, so resolve that range finely. */
    private static final double[] LATENCY_SECONDS = {
        0.00005, 0.0001, 0.00025, 0.0005, 0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1};

    private final Metrics metrics;
    private final CounterHandle requests;
    private final HistogramHandle requestSeconds;
    private final HistogramHandle wafSeconds;
    private final CounterHandle ruleHits;
    private final CounterHandle gaps;
    private final CounterHandle firewallDecisions;
    private final CounterHandle backendRequests;
    private final CounterHandle backendFailures;
    private final CounterHandle backendEjections;
    private final CounterHandle certificateEvents;
    private final CounterHandle rules;
    private final CounterHandle connectionErrors;

    ProxyMetrics(Metrics metrics) {
        this.metrics = metrics;
        requests = metrics.counter("aegis_requests_total", "Requests by route and decision", "route", "decision");
        requestSeconds = metrics.histogram("aegis_request_duration_seconds", "Request duration, from head to last byte",
                LATENCY_SECONDS, "route");
        wafSeconds = metrics.histogram("aegis_waf_inspection_seconds", "Time the WAF spent on one request", LATENCY_SECONDS);
        ruleHits = metrics.counter("aegis_waf_rule_hits_total", "Rule matches", "rule_set", "sid", "mode");
        gaps = metrics.counter("aegis_inspection_gaps_total", "Requests that were not inspected in full",
                "gap", "blocked");
        firewallDecisions = metrics.counter("aegis_firewall_decisions_total", "Firewall verdicts", "verdict");
        backendRequests = metrics.counter("aegis_backend_requests_total", "Attempts to reach a backend by outcome",
                "backend", "result");
        backendFailures = metrics.counter("aegis_backend_failures_total", "Attempts charged to a backend's health",
                "backend", "cause");
        backendEjections = metrics.counter("aegis_backend_ejections_total", "Backends taken out of rotation", "backend");
        certificateEvents = metrics.counter("aegis_certificate_events_total", "Certificate loads and reloads",
                "hostname", "kind");
        rules = metrics.counter("aegis_rules_loaded_total", "Rules per rule set and classification at startup",
                "rule_set", "status");
        connectionErrors = metrics.counter("aegis_connection_errors_total",
                "Client connections that failed outside a request, by exception class", "cause");
    }

    /** Gauges read at scrape time; registered once the objects they read exist. */
    void registerGauges(Firewall firewall, EventLog events) {
        metrics.gauge("aegis_rate_limit_tracked_clients", "Clients holding a rate-limit bucket", firewall::trackedClients);
        metrics.gauge("aegis_log_events_dropped", "Events dropped because the log queue was full", events::droppedEvents);
        metrics.gauge("aegis_log_write_failures", "Events that could not be written to the local log", events::writeFailures);
        metrics.gauge("aegis_log_sink_failures", "Events a log sink failed to accept", events::sinkFailures);
    }

    void requestFinished(String route, Decision decision, long nanos) {
        requests.increment(route, decision.label());
        requestSeconds.observe(nanos / 1e9, route);
    }

    void firewallDecided(FirewallVerdict verdict) {
        firewallDecisions.increment(verdict.name().toLowerCase(Locale.ROOT));
    }

    void wafInspected(long nanos) {
        wafSeconds.observe(nanos / 1e9);
    }

    void ruleHit(RuleHit hit) {
        ruleHits.increment(hit.ruleSet(), Integer.toString(hit.sid()), hit.mode().name().toLowerCase(Locale.ROOT));
    }

    void inspectionGap(InspectionGap gap, boolean blocked) {
        gaps.increment(gap.name().toLowerCase(Locale.ROOT), Boolean.toString(blocked));
    }

    void backendAttempt(BackendAddress backend, String result) {
        backendRequests.increment(backend.toString(), result);
    }

    void backendFailure(BackendAddress backend, String cause) {
        backendFailures.increment(backend.toString(), cause);
    }

    void backendEjected(BackendAddress backend) {
        backendEjections.increment(backend.toString());
    }

    void certificate(CertificateEvent event) {
        certificateEvents.increment(event.hostname(), event.kind().name().toLowerCase(Locale.ROOT));
    }

    void ruleSetLoaded(RuleSet set) {
        for (RuleStatus status : RuleStatus.values()) {
            rules.add(set.count(status), set.name(), status.name().toLowerCase(Locale.ROOT));
        }
    }

    void connectionError(Throwable cause) {
        connectionErrors.increment(cause.getClass().getSimpleName());
    }
}
