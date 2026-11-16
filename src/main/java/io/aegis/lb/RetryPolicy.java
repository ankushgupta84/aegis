package io.aegis.lb;

import java.util.Set;

/**
 * Decides whether a failed request may be sent to another backend.
 *
 * <p>A request that never reached a backend is always safe to resend. Once bytes were sent, only
 * idempotent methods are: a retried POST can double a side effect such as a charge, and the
 * backend may have acted before the failure. Methods are compared case-sensitively, as HTTP
 * defines them. The caller enforces "at most one retry".
 */
public final class RetryPolicy {

    private static final Set<String> IDEMPOTENT_METHODS = Set.of("GET", "HEAD", "OPTIONS", "PUT", "DELETE");

    private RetryPolicy() {
    }

    public static boolean mayRetry(String method, boolean requestBytesSent) {
        return !requestBytesSent || IDEMPOTENT_METHODS.contains(method);
    }
}
