package io.aegis.loadtest;

import java.util.Collections;
import java.util.EnumMap;
import java.util.Map;
import java.util.TreeMap;
import org.HdrHistogram.Histogram;

/**
 * Accumulates the outcome of every measured request. Every error is recorded into the histogram at
 * the timeout value, so failures can never make the percentiles look better than they were.
 * Used only from the dispatcher's thread.
 */
final class Measurements {

    private static final double MICROS_PER_MILLI = 1000.0;

    private final Histogram latencyMicros = new Histogram(3);
    private final long errorMicros;
    private final Map<Integer, Long> responsesByStatus = new TreeMap<>();
    private final Map<ErrorCause, Long> errorsByCause = new EnumMap<>(ErrorCause.class);
    private long requests;
    private long attackRequests;
    private long expectedAttackBlocks;
    private long otherNon2xx;
    private long errors;
    private int maxQueueDepth;
    private long firstIntendedNanos = Long.MAX_VALUE;
    private long lastCompletedNanos = Long.MIN_VALUE;

    Measurements(long timeoutNanos) {
        this.errorMicros = timeoutNanos / 1000;
        for (ErrorCause cause : ErrorCause.values()) {
            errorsByCause.put(cause, 0L);
        }
    }

    void response(PendingRequest request, int status, long completedNanos) {
        counted(request, request.latencyNanos(completedNanos) / 1000, completedNanos);
        responsesByStatus.merge(status, 1L, Long::sum);
        boolean attackBlocked = request.spec().attack() && status == 403;
        if (request.spec().attack()) {
            attackRequests++;
        }
        if (attackBlocked) {
            expectedAttackBlocks++;
        } else if (status < 200 || status > 299) {
            otherNon2xx++;
        }
    }

    void failure(PendingRequest request, ErrorCause cause, long completedNanos) {
        counted(request, errorMicros, completedNanos);
        errorsByCause.merge(cause, 1L, Long::sum);
        errors++;
        if (request.spec().attack()) {
            attackRequests++;
        }
    }

    void queueDepth(int depth) {
        maxQueueDepth = Math.max(maxQueueDepth, depth);
    }

    Report report(LoadTestOptions options, long warmupRequests) {
        double seconds = requests == 0 ? 0 : (lastCompletedNanos - firstIntendedNanos) / 1e9;
        return new Report(
                options.label(),
                options.url().toString(),
                options.rate(),
                seconds == 0 ? 0 : requests / seconds,
                seconds,
                options.seed(),
                options.connections(),
                requests,
                warmupRequests,
                Collections.unmodifiableMap(new TreeMap<>(responsesByStatus)),
                attackRequests,
                expectedAttackBlocks,
                otherNon2xx,
                Collections.unmodifiableMap(new EnumMap<>(errorsByCause)),
                errors,
                latencies(),
                maxQueueDepth);
    }

    private void counted(PendingRequest request, long micros, long completedNanos) {
        requests++;
        latencyMicros.recordValue(micros);
        firstIntendedNanos = Math.min(firstIntendedNanos, request.intendedNanos());
        lastCompletedNanos = Math.max(lastCompletedNanos, completedNanos);
    }

    private Report.LatencyMs latencies() {
        return new Report.LatencyMs(
                percentileMs(50), percentileMs(90), percentileMs(99), percentileMs(99.9),
                latencyMicros.getMaxValue() / MICROS_PER_MILLI);
    }

    private double percentileMs(double percentile) {
        return latencyMicros.getValueAtPercentile(percentile) / MICROS_PER_MILLI;
    }
}
