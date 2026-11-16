package io.aegis.firewall;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import io.aegis.policy.RateLimit;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;

class TokenBucketLimiterTest {

    private static final long MILLI = 1_000_000L;

    private final FakeClock clock = new FakeClock();

    private static InetAddress ip(String literal) {
        try {
            return InetAddress.getByName(literal);
        } catch (UnknownHostException e) {
            throw new IllegalArgumentException(e);
        }
    }

    private TokenBucketLimiter limiter(double rate, int burst, int maxClients) {
        return new TokenBucketLimiter(new RateLimit(true, rate, burst, 32, 64, maxClients), clock);
    }

    private static int countAdmitted(TokenBucketLimiter limiter, InetAddress client, int attempts) {
        int admitted = 0;
        for (int i = 0; i < attempts; i++) {
            if (limiter.tryAcquire(client)) {
                admitted++;
            }
        }
        return admitted;
    }

    @Test
    void admitsExactlyBurstRapidRequestsThenLimits() {
        TokenBucketLimiter limiter = limiter(10, 5, 100);

        assertThat(countAdmitted(limiter, ip("192.0.2.1"), 5)).isEqualTo(5);
        assertThat(limiter.tryAcquire(ip("192.0.2.1"))).isFalse();
    }

    @Test
    void admitsExactlyOneMoreAfterOneTokenInterval() {
        TokenBucketLimiter limiter = limiter(10, 5, 100);
        countAdmitted(limiter, ip("192.0.2.1"), 5);

        clock.advanceNanos(100 * MILLI);

        assertThat(countAdmitted(limiter, ip("192.0.2.1"), 3)).isEqualTo(1);
    }

    @Test
    void doesNotAdmitBeforeOneTokenInterval() {
        TokenBucketLimiter limiter = limiter(10, 5, 100);
        countAdmitted(limiter, ip("192.0.2.1"), 5);

        clock.advanceNanos(100 * MILLI - 1);

        assertThat(limiter.tryAcquire(ip("192.0.2.1"))).isFalse();
    }

    @Test
    void keepsTheRemainderOfAPartialIntervalSoNothingDrifts() {
        TokenBucketLimiter limiter = limiter(10, 1, 100);
        limiter.tryAcquire(ip("192.0.2.1"));

        int admitted = 0;
        for (int i = 0; i < 1000; i++) {
            clock.advanceNanos(10 * MILLI);
            if (limiter.tryAcquire(ip("192.0.2.1"))) {
                admitted++;
            }
        }

        assertThat(admitted).isEqualTo(100);
    }

    @Test
    void neverRefillsBeyondBurst() {
        TokenBucketLimiter limiter = limiter(10, 3, 100);
        countAdmitted(limiter, ip("192.0.2.1"), 3);

        clock.advanceNanos(3_600_000 * MILLI);

        assertThat(countAdmitted(limiter, ip("192.0.2.1"), 10)).isEqualTo(3);
    }

    @Test
    void givesEachClientItsOwnBucket() {
        TokenBucketLimiter limiter = limiter(10, 2, 100);
        countAdmitted(limiter, ip("192.0.2.1"), 2);

        assertThat(limiter.tryAcquire(ip("192.0.2.2"))).isTrue();
    }

    @Test
    void groupsIpv6AddressesOfOneSlash64IntoOneBucket() {
        TokenBucketLimiter limiter = limiter(10, 2, 100);

        assertThat(limiter.tryAcquire(ip("2001:db8:0:1::1"))).isTrue();
        assertThat(limiter.tryAcquire(ip("2001:db8:0:1::ffff"))).isTrue();
        assertThat(limiter.tryAcquire(ip("2001:db8:0:1:aaaa::2"))).isFalse();
        assertThat(limiter.trackedClients()).isEqualTo(1);
    }

    @Test
    void separatesIpv6AddressesInDifferentSlash64s() {
        TokenBucketLimiter limiter = limiter(10, 1, 100);
        limiter.tryAcquire(ip("2001:db8:0:1::1"));

        assertThat(limiter.tryAcquire(ip("2001:db8:0:2::1"))).isTrue();
    }

    @Test
    void honorsAConfiguredIpv4Prefix() {
        TokenBucketLimiter limiter =
                new TokenBucketLimiter(new RateLimit(true, 10, 1, 24, 64, 100), clock);
        limiter.tryAcquire(ip("192.0.2.1"));

        assertThat(limiter.tryAcquire(ip("192.0.2.200"))).isFalse();
        assertThat(limiter.tryAcquire(ip("192.0.3.1"))).isTrue();
    }

    @Test
    void evictsTheLeastRecentlyUsedBucketWhenFull() {
        TokenBucketLimiter limiter = limiter(10, 1, 2);
        limiter.tryAcquire(ip("192.0.2.1"));
        limiter.tryAcquire(ip("192.0.2.2"));
        limiter.tryAcquire(ip("192.0.2.1"));

        limiter.tryAcquire(ip("192.0.2.3"));

        assertThat(limiter.trackedClients()).isEqualTo(2);
        assertThat(limiter.tryAcquire(ip("192.0.2.1"))).isFalse();
        assertThat(limiter.tryAcquire(ip("192.0.2.2"))).as("evicted client starts with a full bucket").isTrue();
    }

    @Test
    void neverTracksMoreThanTheConfiguredClients() {
        TokenBucketLimiter limiter = limiter(10, 1, 50);

        for (int i = 0; i < 500; i++) {
            limiter.tryAcquire(ip("10.0." + (i / 250) + "." + (i % 250)));
        }

        assertThat(limiter.trackedClients()).isEqualTo(50);
    }

    @Test
    void admitsExactlyBurstRequestsUnderContention() throws InterruptedException {
        int threads = 16;
        int attemptsPerThread = 1000;
        int burst = 500;
        TokenBucketLimiter limiter = limiter(1, burst, 100);
        InetAddress client = ip("192.0.2.1");
        AtomicInteger admitted = new AtomicInteger();
        CountDownLatch start = new CountDownLatch(1);

        Thread[] workers = new Thread[threads];
        for (int t = 0; t < threads; t++) {
            workers[t] = new Thread(() -> {
                awaitUninterruptibly(start);
                admitted.addAndGet(countAdmitted(limiter, client, attemptsPerThread));
            });
            workers[t].start();
        }
        start.countDown();
        for (Thread worker : workers) {
            worker.join();
        }

        assertThat(admitted.get()).isEqualTo(burst);
    }

    private static void awaitUninterruptibly(CountDownLatch latch) {
        try {
            latch.await();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException("Test worker interrupted", e);
        }
    }

    @Test
    void rejectsNonPositiveRates() {
        assertThatThrownBy(() -> limiter(0, 1, 1)).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> limiter(Double.NaN, 1, 1)).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> limiter(2e9, 1, 1)).isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void rejectsZeroBurstAndZeroCapacity() {
        assertThatThrownBy(() -> limiter(1, 0, 1)).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> limiter(1, 1, 0)).isInstanceOf(IllegalArgumentException.class);
    }
}
