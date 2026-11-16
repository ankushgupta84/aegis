package io.aegis.loadtest;

import java.util.Locale;
import java.util.Map;
import java.util.stream.Collectors;

/** Formats a {@link Report} for a person to read. */
final class ReportText {

    private ReportText() {
    }

    static String format(Report r) {
        return String.format(Locale.ROOT, """
                label:            %s
                target:           %s
                rate:             %d configured, %.1f achieved (over %.1f s, %d connections, seed %d)
                requests:         %d measured, %d warm-up
                responses:        %s
                attacks:          %d sent, %d blocked as expected (403)
                other non-2xx:    %d
                errors:           %s
                latency ms:       p50 %.3f  p90 %.3f  p99 %.3f  p99.9 %.3f  max %.3f
                max queue depth:  %d
                """,
                r.label(), r.target(),
                r.configuredRate(), r.achievedRate(), r.measuredSeconds(), r.connections(), r.seed(),
                r.requests(), r.warmupRequests(),
                joined(r.responsesByStatus()),
                r.attackRequests(), r.expectedAttackBlocks(),
                r.otherNon2xx(),
                r.errors() == 0 ? "none" : r.errors() + " (" + nonZero(r.errorsByCause()) + ")",
                r.latencyMs().p50(), r.latencyMs().p90(), r.latencyMs().p99(), r.latencyMs().p999(),
                r.latencyMs().max(),
                r.maxQueueDepth());
    }

    private static String joined(Map<Integer, Long> byStatus) {
        return byStatus.isEmpty() ? "none" : byStatus.entrySet().stream()
                .map(e -> e.getKey() + "=" + e.getValue())
                .collect(Collectors.joining(" "));
    }

    private static String nonZero(Map<ErrorCause, Long> byCause) {
        return byCause.entrySet().stream()
                .filter(e -> e.getValue() > 0)
                .map(e -> e.getKey() + "=" + e.getValue())
                .collect(Collectors.joining(" "));
    }
}
