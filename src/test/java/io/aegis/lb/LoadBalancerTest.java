package io.aegis.lb;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;

import io.aegis.policy.BackendAddress;
import io.aegis.policy.HealthKnobs;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import org.junit.jupiter.api.Test;

class LoadBalancerTest {

    private static final BackendAddress A = new BackendAddress("a", 80);
    private static final BackendAddress B = new BackendAddress("b", 80);
    private static final BackendAddress C = new BackendAddress("c", 80);
    private static final HealthKnobs KNOBS = new HealthKnobs(3, Duration.ofSeconds(5), false);
    private static final long EJECTION_NANOS = Duration.ofSeconds(5).toNanos();

    private final AtomicLong clock = new AtomicLong(1_000);

    private LoadBalancer balancerOf(BackendAddress... backends) {
        return new LoadBalancer(List.of(backends), KNOBS, clock::get);
    }

    private void fail(LoadBalancer lb, BackendAddress backend, int times) {
        for (int i = 0; i < times; i++) {
            lb.reportFailure(backend);
        }
    }

    @Test
    void two_healthy_backends_alternate_strictly() {
        LoadBalancer lb = balancerOf(A, B);

        List<BackendAddress> picks = new ArrayList<>();
        for (int i = 0; i < 6; i++) {
            picks.add(lb.pick().orElseThrow());
        }

        assertThat(picks).containsExactly(A, B, A, B, A, B);
    }

    @Test
    void an_ejected_backend_is_skipped() {
        LoadBalancer lb = balancerOf(A, B, C);
        fail(lb, B, 3);

        assertThat(List.of(lb.pick(), lb.pick(), lb.pick(), lb.pick()))
                .extracting(Optional::get).doesNotContain(B);
    }

    @Test
    void backend_is_ejected_after_exactly_the_configured_consecutive_failures() {
        LoadBalancer lb = balancerOf(A, B);

        fail(lb, A, 2);
        assertThat(lb.isEjected(A)).isFalse();

        lb.reportFailure(A);
        assertThat(lb.isEjected(A)).isTrue();
    }

    @Test
    void a_success_resets_the_consecutive_failure_count() {
        LoadBalancer lb = balancerOf(A, B);

        fail(lb, A, 2);
        lb.reportSuccess(A);
        fail(lb, A, 2);

        assertThat(lb.isEjected(A)).isFalse();
    }

    @Test
    void backend_rejoins_exactly_when_the_ejection_time_has_passed() {
        LoadBalancer lb = balancerOf(A, B);
        fail(lb, A, 3);

        clock.addAndGet(EJECTION_NANOS - 1);
        assertThat(lb.isEjected(A)).isTrue();

        clock.addAndGet(1);
        assertThat(lb.isEjected(A)).isFalse();
    }

    @Test
    void ejection_is_correct_when_the_nano_clock_wraps() {
        clock.set(Long.MAX_VALUE - 10);
        LoadBalancer lb = balancerOf(A, B);
        fail(lb, A, 3);

        assertThat(lb.isEjected(A)).isTrue();
        clock.addAndGet(EJECTION_NANOS);
        assertThat(lb.isEjected(A)).isFalse();
    }

    @Test
    void one_failure_on_probation_ejects_for_a_full_ejection_time() {
        LoadBalancer lb = balancerOf(A, B);
        fail(lb, A, 3);
        clock.addAndGet(EJECTION_NANOS);

        lb.reportFailure(A);

        assertThat(lb.isEjected(A)).isTrue();
        clock.addAndGet(EJECTION_NANOS - 1);
        assertThat(lb.isEjected(A)).isTrue();
        clock.addAndGet(1);
        assertThat(lb.isEjected(A)).isFalse();
    }

    @Test
    void a_success_on_probation_restores_the_full_failure_allowance() {
        LoadBalancer lb = balancerOf(A, B);
        fail(lb, A, 3);
        clock.addAndGet(EJECTION_NANOS);

        lb.reportSuccess(A);
        fail(lb, A, 2);

        assertThat(lb.isEjected(A)).isFalse();
    }

    @Test
    void a_late_failure_from_an_in_flight_request_does_not_extend_the_ejection() {
        LoadBalancer lb = balancerOf(A, B);
        fail(lb, A, 3);
        clock.addAndGet(EJECTION_NANOS - 1);

        lb.reportFailure(A);

        clock.addAndGet(1);
        assertThat(lb.isEjected(A)).isFalse();
    }

    @Test
    void pick_is_empty_when_every_backend_is_ejected() {
        LoadBalancer lb = balancerOf(A, B);
        fail(lb, A, 3);
        fail(lb, B, 3);

        assertThat(lb.pick()).isEmpty();
    }

    @Test
    void pick_other_than_with_one_backend_is_empty() {
        assertThat(balancerOf(A).pickOtherThan(A)).isEmpty();
    }

    @Test
    void pick_other_than_with_two_backends_returns_the_other_every_time() {
        LoadBalancer lb = balancerOf(A, B);

        for (int i = 0; i < 4; i++) {
            assertThat(lb.pickOtherThan(A)).contains(B);
            assertThat(lb.pickOtherThan(B)).contains(A);
        }
    }

    @Test
    void pick_other_than_with_three_backends_never_returns_the_tried_one_and_uses_both_others() {
        LoadBalancer lb = balancerOf(A, B, C);

        List<BackendAddress> picks = new ArrayList<>();
        for (int i = 0; i < 6; i++) {
            picks.add(lb.pickOtherThan(A).orElseThrow());
        }

        assertThat(picks).doesNotContain(A).contains(B, C);
    }

    @Test
    void pick_other_than_is_empty_when_the_other_backend_is_ejected() {
        LoadBalancer lb = balancerOf(A, B);
        fail(lb, B, 3);

        assertThat(lb.pickOtherThan(A)).isEmpty();
    }

    @Test
    void reports_for_an_unknown_backend_are_rejected() {
        LoadBalancer lb = balancerOf(A);
        BackendAddress stranger = new BackendAddress("x", 1);

        assertThatIllegalArgumentException().isThrownBy(() -> lb.reportSuccess(stranger));
        assertThatIllegalArgumentException().isThrownBy(() -> lb.reportFailure(stranger));
        assertThatIllegalArgumentException().isThrownBy(() -> lb.isEjected(stranger));
        assertThatIllegalArgumentException().isThrownBy(() -> lb.pickOtherThan(stranger));
    }

    @Test
    void invalid_configuration_is_rejected() {
        assertThatIllegalArgumentException().isThrownBy(() -> balancerOf());
        assertThatIllegalArgumentException().isThrownBy(() -> balancerOf(A, A));
        assertThatIllegalArgumentException().isThrownBy(() -> new LoadBalancer(
                List.of(A), new HealthKnobs(0, Duration.ofSeconds(5), false), clock::get));
        assertThatIllegalArgumentException().isThrownBy(() -> new LoadBalancer(
                List.of(A), new HealthKnobs(3, Duration.ZERO, false), clock::get));
    }

    @Test
    void backends_are_listed_in_configured_order() {
        assertThat(balancerOf(C, A, B).backends()).containsExactly(C, A, B);
    }

    @Test
    void round_robin_stays_in_range_when_the_ticket_counter_wraps() {
        LoadBalancer lb = new LoadBalancer(List.of(A, B, C), KNOBS, clock::get, Long.MAX_VALUE - 2);

        for (int i = 0; i < 12; i++) {
            assertThat(lb.pick()).isPresent();
        }
    }

    @Test
    void round_robin_continues_in_order_past_two_to_the_thirty_first_picks() {
        long pastIntRange = (1L << 31) + 1; // odd, so the next index is B
        LoadBalancer lb = new LoadBalancer(List.of(A, B), KNOBS, clock::get, pastIntRange);

        assertThat(List.of(lb.pick().get(), lb.pick().get())).containsExactly(B, A);
    }

    @Test
    void concurrent_picks_over_healthy_backends_are_exactly_even() throws Exception {
        int threads = 8;
        int picksPerThread = 30_000;
        LoadBalancer lb = balancerOf(A, B, C);
        Map<BackendAddress, AtomicInteger> counts = new ConcurrentHashMap<>();
        lb.backends().forEach(b -> counts.put(b, new AtomicInteger()));

        runConcurrently(threads, () -> {
            for (int i = 0; i < picksPerThread; i++) {
                counts.get(lb.pick().orElseThrow()).incrementAndGet();
            }
        });

        int expected = threads * picksPerThread / 3;
        counts.values().forEach(count -> assertThat(count.get()).isEqualTo(expected));
    }

    @Test
    void no_pick_starting_after_an_ejecting_report_returns_the_ejected_backend() throws Exception {
        int threads = 8;
        LoadBalancer lb = balancerOf(A, B);
        AtomicBoolean ejectionReported = new AtomicBoolean();
        AtomicInteger violations = new AtomicInteger();
        CountDownLatch pickersRunning = new CountDownLatch(threads);

        Thread ejector = new Thread(() -> {
            await(pickersRunning);
            fail(lb, A, 3);
            ejectionReported.set(true);
        });
        ejector.start();

        runConcurrently(threads, () -> {
            pickersRunning.countDown();
            boolean sawReport;
            do {
                sawReport = ejectionReported.get(); // read before picking: the pick starts after the report
                if (sawReport && lb.pick().orElseThrow().equals(A)) {
                    violations.incrementAndGet();
                }
                lb.pick();
            } while (!sawReport);
            for (int i = 0; i < 10_000; i++) {
                if (lb.pick().orElseThrow().equals(A)) {
                    violations.incrementAndGet();
                }
            }
        });
        ejector.join();

        assertThat(violations).hasValue(0);
    }

    @Test
    void picks_racing_with_health_changes_always_return_a_known_backend_and_end_consistent() throws Exception {
        LoadBalancer lb = balancerOf(A, B);
        AtomicBoolean done = new AtomicBoolean();
        Thread flapper = new Thread(() -> {
            for (int i = 0; i < 2_000; i++) {
                fail(lb, A, 3);
                clock.addAndGet(EJECTION_NANOS);
                lb.reportSuccess(A);
            }
            done.set(true);
        });
        flapper.start();

        runConcurrently(4, () -> {
            while (!done.get()) {
                assertThat(lb.pick().orElseThrow()).isIn(A, B);
            }
        });
        flapper.join();

        assertThat(lb.isEjected(A)).isFalse();
        assertThat(lb.pick()).isPresent();
    }

    private static void runConcurrently(int threads, Runnable task) throws Exception {
        CountDownLatch start = new CountDownLatch(1);
        List<Thread> workers = new ArrayList<>();
        List<Throwable> failures = Collections.synchronizedList(new ArrayList<>());
        for (int i = 0; i < threads; i++) {
            Thread worker = new Thread(() -> {
                await(start);
                try {
                    task.run();
                } catch (Throwable t) {
                    failures.add(t);
                }
            });
            workers.add(worker);
            worker.start();
        }
        start.countDown();
        for (Thread worker : workers) {
            worker.join(TimeUnit.SECONDS.toMillis(60));
        }
        assertThat(failures).isEmpty();
    }

    private static void await(CountDownLatch latch) {
        try {
            latch.await();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException(e);
        }
    }
}
