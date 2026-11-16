package io.aegis.loadtest;

import java.util.concurrent.ScheduledFuture;

/**
 * A request from the moment it falls due until it is settled by a response, an error, or a
 * timeout. Latency counts from the intended send time, so time spent waiting for a free
 * connection is part of it. Used only from the dispatcher's thread.
 */
final class PendingRequest {

    private final RequestSpec spec;
    private final long intendedNanos;
    private final boolean recorded;
    private boolean settled;
    private ClientConnection connection;
    private ScheduledFuture<?> timeout;

    PendingRequest(RequestSpec spec, long intendedNanos, boolean recorded) {
        this.spec = spec;
        this.intendedNanos = intendedNanos;
        this.recorded = recorded;
    }

    RequestSpec spec() {
        return spec;
    }

    long intendedNanos() {
        return intendedNanos;
    }

    /** False for warm-up requests, which are sent but not measured. */
    boolean recorded() {
        return recorded;
    }

    /**
     * Time from the intended send time to completion. Measuring from the actual send time instead
     * would hide every delay the generator itself absorbed, which is coordinated omission.
     */
    long latencyNanos(long completedNanos) {
        return completedNanos - intendedNanos;
    }

    /** Marks the request settled; false if it already was, so late events are ignored. */
    boolean settle() {
        if (settled) {
            return false;
        }
        settled = true;
        if (timeout != null) {
            timeout.cancel(false);
        }
        return true;
    }

    boolean isSettled() {
        return settled;
    }

    void expireWith(ScheduledFuture<?> scheduledTimeout) {
        timeout = scheduledTimeout;
    }

    void serveWith(ClientConnection serving) {
        connection = serving;
    }

    /** The connection carrying the request, or null while it waits for one. */
    ClientConnection connection() {
        return connection;
    }
}
