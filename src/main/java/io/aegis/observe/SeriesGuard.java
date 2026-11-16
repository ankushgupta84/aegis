package io.aegis.observe;

import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * The cardinality guard for one metric: admits at most {@code max} distinct label-value
 * combinations and folds the rest into a single {@code other} series, so an unbounded label such
 * as client IP cannot exhaust memory. The {@code other} series is not counted against the limit.
 *
 * <p>Already-admitted combinations cost one hash lookup and no allocation beyond a list view.
 */
final class SeriesGuard {

    static final String OTHER = "other";

    private final String[] labelNames;
    private final int max;
    private final Runnable onOverflow;
    private final Map<List<String>, Boolean> admitted = new ConcurrentHashMap<>();
    private final AtomicInteger admittedCount = new AtomicInteger();

    SeriesGuard(String[] labelNames, int max, Runnable onOverflow) {
        this.labelNames = labelNames;
        this.max = max;
        this.onOverflow = onOverflow;
    }

    /** @return the label values to record under: the given ones, or all {@code other} past the limit */
    String[] resolve(String[] labelValues) {
        if (labelValues.length != labelNames.length) {
            throw new IllegalArgumentException("Expected " + labelNames.length + " label values "
                    + Arrays.toString(labelNames) + " but got " + labelValues.length);
        }
        if (labelNames.length == 0 || admitted.containsKey(Arrays.asList(labelValues))) {
            return labelValues;
        }
        if (admit(labelValues)) {
            return labelValues;
        }
        onOverflow.run();
        String[] other = new String[labelNames.length];
        Arrays.fill(other, OTHER);
        return other;
    }

    private boolean admit(String[] labelValues) {
        if (admittedCount.incrementAndGet() > max) {
            admittedCount.decrementAndGet();
            return false;
        }
        if (admitted.putIfAbsent(List.of(labelValues), Boolean.TRUE) != null) {
            admittedCount.decrementAndGet(); // another thread admitted the same combination first
        }
        return true;
    }
}
