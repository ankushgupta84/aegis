package io.aegis.observe;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;

class MetricsTest {

    private final Metrics metrics = new Metrics(100);

    @Test
    void counter_appears_in_scrape_with_labels() {
        CounterHandle requests = metrics.counter("aegis_requests_total", "Requests", "route", "status");

        requests.increment("api", "200");
        requests.add(2, "api", "200");
        requests.increment("web", "500");

        assertThat(metrics.scrape())
                .contains("# HELP aegis_requests_total Requests")
                .contains("# TYPE aegis_requests_total counter")
                .contains("aegis_requests_total{route=\"api\",status=\"200\"} 3.0")
                .contains("aegis_requests_total{route=\"web\",status=\"500\"} 1.0");
    }

    @Test
    void counter_without_labels_works() {
        metrics.counter("aegis_starts_total", "Starts").increment();

        assertThat(metrics.scrape()).contains("aegis_starts_total 1.0");
    }

    @Test
    void histogram_appears_in_scrape_with_buckets_sum_and_count() {
        HistogramHandle latency = metrics.histogram("aegis_latency_seconds", "Latency", new double[] {0.1, 1}, "route");

        latency.observe(0.05, "api");
        latency.observe(0.5, "api");

        assertThat(metrics.scrape())
                .contains("# TYPE aegis_latency_seconds histogram")
                .contains("aegis_latency_seconds_bucket{route=\"api\",le=\"0.1\"} 1")
                .contains("aegis_latency_seconds_bucket{route=\"api\",le=\"1.0\"} 2")
                .contains("aegis_latency_seconds_bucket{route=\"api\",le=\"+Inf\"} 2")
                .contains("aegis_latency_seconds_count{route=\"api\"} 2")
                .contains("aegis_latency_seconds_sum{route=\"api\"} 0.55");
    }

    @Test
    void gauge_is_sampled_at_each_scrape() {
        AtomicInteger value = new AtomicInteger(3);
        metrics.gauge("aegis_open_connections", "Open connections", value::get);

        assertThat(metrics.scrape()).contains("aegis_open_connections 3.0");
        value.set(8);
        assertThat(metrics.scrape()).contains("aegis_open_connections 8.0");
    }

    @Test
    void registering_the_same_shape_twice_returns_the_same_counter() {
        CounterHandle first = metrics.counter("aegis_x_total", "X", "a");
        CounterHandle second = metrics.counter("aegis_x_total", "X", "a");

        assertThat(second).isSameAs(first);
    }

    @Test
    void registering_a_name_with_a_different_shape_fails_clearly() {
        metrics.counter("aegis_x_total", "X", "a");

        assertThatThrownBy(() -> metrics.counter("aegis_x_total", "X", "a", "b"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("aegis_x_total")
                .hasMessageContaining("already registered");
        assertThatThrownBy(() -> metrics.histogram("aegis_x_total", "X", new double[] {1}, "a"))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void histogram_with_different_buckets_is_a_different_shape() {
        metrics.histogram("aegis_h", "H", new double[] {1});

        assertThatThrownBy(() -> metrics.histogram("aegis_h", "H", new double[] {2}))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void gauge_name_cannot_be_registered_twice() {
        metrics.gauge("aegis_g", "G", () -> 1);

        assertThatThrownBy(() -> metrics.gauge("aegis_g", "G", () -> 2))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("aegis_g");
    }

    @Test
    void wrong_number_of_label_values_fails() {
        CounterHandle counter = metrics.counter("aegis_x_total", "X", "a", "b");

        assertThatThrownBy(() -> counter.increment("only-one"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("Expected 2");
    }

    @Test
    void series_past_the_limit_fold_into_other_and_are_counted() {
        Metrics small = new Metrics(2);
        CounterHandle hits = small.counter("aegis_hits_total", "Hits", "ip");

        hits.increment("1.1.1.1");
        hits.increment("2.2.2.2");
        hits.increment("3.3.3.3");
        hits.increment("4.4.4.4");
        hits.increment("1.1.1.1");

        assertThat(small.scrape())
                .contains("aegis_hits_total{ip=\"1.1.1.1\"} 2.0")
                .contains("aegis_hits_total{ip=\"2.2.2.2\"} 1.0")
                .contains("aegis_hits_total{ip=\"other\"} 2.0")
                .doesNotContain("3.3.3.3")
                .contains("aegis_metrics_series_overflow_total{metric=\"aegis_hits_total\"} 2.0");
    }

    @Test
    void histogram_overflow_folds_into_other() {
        Metrics small = new Metrics(1);
        HistogramHandle latency = small.histogram("aegis_lat", "L", new double[] {1}, "route");

        latency.observe(0.5, "a");
        latency.observe(0.5, "b");

        assertThat(small.scrape())
                .contains("aegis_lat_count{route=\"a\"} 1")
                .contains("aegis_lat_count{route=\"other\"} 1")
                .contains("aegis_metrics_series_overflow_total{metric=\"aegis_lat\"} 1.0");
    }

    @Test
    void each_metric_has_its_own_series_budget() {
        Metrics small = new Metrics(1);
        small.counter("aegis_a_total", "A", "k").increment("1");
        small.counter("aegis_b_total", "B", "k").increment("1");

        assertThat(small.scrape()).doesNotContain("other");
    }

    @Test
    void concurrent_increments_sum_exactly() throws Exception {
        CounterHandle counter = metrics.counter("aegis_c_total", "C", "k");
        int threads = 8;
        int perThread = 10_000;
        CountDownLatch start = new CountDownLatch(1);
        List<Thread> workers = new ArrayList<>();
        for (int t = 0; t < threads; t++) {
            Thread worker = new Thread(() -> {
                awaitQuietly(start);
                for (int i = 0; i < perThread; i++) {
                    counter.increment("same");
                }
            });
            workers.add(worker);
            worker.start();
        }
        start.countDown();
        for (Thread worker : workers) {
            worker.join();
        }

        assertThat(metrics.scrape()).contains("aegis_c_total{k=\"same\"} 80000.0");
    }

    @Test
    void concurrent_new_series_never_exceed_the_limit() throws Exception {
        Metrics small = new Metrics(5);
        CounterHandle counter = small.counter("aegis_n_total", "N", "k");
        CountDownLatch start = new CountDownLatch(1);
        List<Thread> workers = new ArrayList<>();
        for (int t = 0; t < 8; t++) {
            Thread worker = new Thread(() -> {
                awaitQuietly(start);
                for (int i = 0; i < 100; i++) {
                    counter.increment("v" + i);
                }
            });
            workers.add(worker);
            worker.start();
        }
        start.countDown();
        for (Thread worker : workers) {
            worker.join();
        }

        long series = small.scrape().lines().filter(l -> l.startsWith("aegis_n_total{")).count();
        assertThat(series).isEqualTo(6); // five admitted plus "other"
        double overflowed = valueOf(small.scrape(), "aegis_metrics_series_overflow_total{metric=\"aegis_n_total\"}");
        assertThat(valueOf(small.scrape(), "aegis_n_total{k=\"other\"}")).isEqualTo(overflowed);
    }

    private static double valueOf(String scrape, String series) {
        return scrape.lines().filter(l -> l.startsWith(series + " ")).map(l -> l.substring(series.length() + 1))
                .mapToDouble(Double::parseDouble).sum();
    }

    private static void awaitQuietly(CountDownLatch latch) {
        try {
            latch.await();
        } catch (InterruptedException e) {
            throw new IllegalStateException(e);
        }
    }
}
