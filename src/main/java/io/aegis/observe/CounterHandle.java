package io.aegis.observe;

import io.prometheus.metrics.core.metrics.Counter;

/** A registered counter; label values are checked and cardinality-guarded on every call. */
public final class CounterHandle {

    private final Counter counter;
    private final SeriesGuard guard;

    CounterHandle(Counter counter, SeriesGuard guard) {
        this.counter = counter;
        this.guard = guard;
    }

    public void increment(String... labelValues) {
        add(1, labelValues);
    }

    /** @throws IllegalArgumentException if the amount is negative or the label count is wrong */
    public void add(double amount, String... labelValues) {
        counter.labelValues(guard.resolve(labelValues)).inc(amount);
    }
}
