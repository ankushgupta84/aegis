package io.aegis.lb;

import java.util.concurrent.atomic.AtomicReference;

/**
 * Passive health of one backend: consecutive failures and, once they reach the threshold, the
 * instant the ejection ends.
 *
 * <p>The failure count stays at the threshold after an ejection expires. That puts the backend
 * on probation: one more failure ejects it for a full ejection time, while a success restores
 * it completely. Without probation a still-dead backend would receive {@code failuresToEject}
 * live requests every cycle.
 *
 * <p>State is one immutable value swapped by compare-and-set, so readers never see a count from
 * one transition paired with a deadline from another. A failure reported while the backend is
 * already ejected (a request that was in flight) is ignored, so it cannot extend the ejection.
 */
final class BackendHealth {

    private record State(int consecutiveFailures, long ejectedUntilNanos) {
    }

    private static final State HEALTHY = new State(0, 0);

    private final int failuresToEject;
    private final long ejectionNanos;
    private final AtomicReference<State> state = new AtomicReference<>(HEALTHY);

    BackendHealth(int failuresToEject, long ejectionNanos) {
        this.failuresToEject = failuresToEject;
        this.ejectionNanos = ejectionNanos;
    }

    boolean isEjected(long nowNanos) {
        return isEjected(state.get(), nowNanos);
    }

    void recordSuccess() {
        state.set(HEALTHY);
    }

    void recordFailure(long nowNanos) {
        state.updateAndGet(current -> afterFailure(current, nowNanos));
    }

    private State afterFailure(State current, long nowNanos) {
        if (isEjected(current, nowNanos)) {
            return current;
        }
        int failures = Math.min(current.consecutiveFailures + 1, failuresToEject);
        long ejectedUntil = failures == failuresToEject ? nowNanos + ejectionNanos : current.ejectedUntilNanos;
        return new State(failures, ejectedUntil);
    }

    private boolean isEjected(State s, long nowNanos) {
        // Subtraction, not comparison, so the check survives nanoTime wrapping.
        return s.consecutiveFailures >= failuresToEject && s.ejectedUntilNanos - nowNanos > 0;
    }
}
