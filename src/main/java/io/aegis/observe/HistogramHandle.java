package io.aegis.observe;

import io.prometheus.metrics.core.metrics.Histogram;

/** A registered histogram; label values are checked and cardinality-guarded on every call. */
public final class HistogramHandle {

    private final Histogram histogram;
    private final SeriesGuard guard;

    HistogramHandle(Histogram histogram, SeriesGuard guard) {
        this.histogram = histogram;
        this.guard = guard;
    }

    /** @throws IllegalArgumentException if the label count is wrong */
    public void observe(double value, String... labelValues) {
        histogram.labelValues(guard.resolve(labelValues)).observe(value);
    }
}
