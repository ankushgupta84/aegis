package io.aegis.observe;

import io.prometheus.metrics.config.EscapingScheme;
import io.prometheus.metrics.core.metrics.Counter;
import io.prometheus.metrics.core.metrics.GaugeWithCallback;
import io.prometheus.metrics.core.metrics.Histogram;
import io.prometheus.metrics.expositionformats.PrometheusTextFormatWriter;
import io.prometheus.metrics.model.registry.PrometheusRegistry;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.DoubleSupplier;
import java.util.function.Supplier;

/**
 * Aegis's metrics, kept in the Prometheus text format. Each instance owns a private registry, so
 * nothing leaks between instances (or tests) through a global default.
 *
 * <p>Every counter and histogram is guarded: past {@code maxSeriesPerMetric} distinct label-value
 * combinations, observations fold into {@code other} and
 * {@code aegis_metrics_series_overflow_total{metric="..."}} counts them. Names are used as given,
 * except that the Prometheus client appends {@code _total} to counters on exposition.
 */
public final class Metrics {

    private record Shape(String kind, String help, List<String> labelNames, List<Double> bounds) {}

    private record Registered(Shape shape, Object handle) {}

    private final PrometheusRegistry registry = new PrometheusRegistry();
    private final Map<String, Registered> registered = new ConcurrentHashMap<>();
    private final int maxSeriesPerMetric;
    private final Counter overflow;

    public Metrics(int maxSeriesPerMetric) {
        if (maxSeriesPerMetric < 1) {
            throw new IllegalArgumentException("maxSeriesPerMetric must be at least 1, got " + maxSeriesPerMetric);
        }
        this.maxSeriesPerMetric = maxSeriesPerMetric;
        this.overflow = Counter.builder()
                .name("aegis_metrics_series_overflow_total")
                .help("Observations folded into the 'other' series by the cardinality guard")
                .labelNames("metric")
                .register(registry);
    }

    /**
     * Returns the counter, registering it on first use.
     *
     * @throws IllegalArgumentException if the name is already registered with a different shape
     */
    public CounterHandle counter(String name, String help, String... labelNames) {
        Shape shape = new Shape("counter", help, List.of(labelNames), List.of());
        return (CounterHandle) registerOnce(name, shape, () -> {
            Counter counter = Counter.builder().name(name).help(help).labelNames(labelNames).register(registry);
            return new CounterHandle(counter, guard(name, labelNames));
        });
    }

    /**
     * Returns the histogram, registering it on first use.
     *
     * @throws IllegalArgumentException if the name is already registered with a different shape
     */
    public HistogramHandle histogram(String name, String help, double[] bucketUpperBounds, String... labelNames) {
        List<Double> bounds = Arrays.stream(bucketUpperBounds).boxed().toList();
        Shape shape = new Shape("histogram", help, List.of(labelNames), bounds);
        return (HistogramHandle) registerOnce(name, shape, () -> {
            Histogram histogram = Histogram.builder().name(name).help(help).labelNames(labelNames)
                    .classicOnly().classicUpperBounds(bucketUpperBounds).register(registry);
            return new HistogramHandle(histogram, guard(name, labelNames));
        });
    }

    /**
     * Registers a gauge read when the metrics are scraped. A supplier cannot be compared, so a
     * second registration of the same name is always an error.
     */
    public void gauge(String name, String help, DoubleSupplier value) {
        Shape shape = new Shape("gauge", help, List.of(), List.of());
        Registered previous = registered.putIfAbsent(name, new Registered(shape, value));
        if (previous != null) {
            throw new IllegalArgumentException("Metric '" + name + "' is already registered; a gauge name can be registered only once");
        }
        GaugeWithCallback.builder().name(name).help(help)
                .callback(callback -> callback.call(value.getAsDouble()))
                .register(registry);
    }

    /** @return all metrics in the Prometheus text exposition format */
    public String scrape() {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        try {
            PrometheusTextFormatWriter.create().write(out, registry.scrape(), EscapingScheme.ALLOW_UTF8);
        } catch (IOException e) {
            throw new IllegalStateException("Writing to memory cannot fail", e);
        }
        return out.toString(StandardCharsets.UTF_8);
    }

    private SeriesGuard guard(String name, String[] labelNames) {
        return new SeriesGuard(labelNames, maxSeriesPerMetric, () -> overflow.labelValues(name).inc());
    }

    // computeIfAbsent makes the check-then-register atomic, so two threads cannot both register.
    private Object registerOnce(String name, Shape shape, Supplier<Object> create) {
        Registered existing = registered.computeIfAbsent(name, n -> new Registered(shape, create.get()));
        if (!existing.shape().equals(shape)) {
            throw new IllegalArgumentException("Metric '" + name + "' is already registered as " + existing.shape()
                    + " and cannot be registered again as " + shape);
        }
        return existing.handle();
    }
}
