package io.aegis.firewall;

import io.aegis.net.Cidr;
import io.aegis.policy.RateLimit;
import java.net.InetAddress;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.function.LongSupplier;

/**
 * One token bucket per client block, with a bounded number of buckets.
 *
 * <p><b>Exactness.</b> Time is accounted in whole nanoseconds and tokens in whole units. A token
 * costs a fixed integer number of nanoseconds, so refill is integer division and no rounding
 * error accumulates: the remainder of a partial interval stays in the bucket's timestamp instead
 * of being rounded away. The cost of one token is {@code 1e9 / requestsPerSecond} rounded to the
 * nearest nanosecond, which is off by under half a nanosecond per token.
 *
 * <p><b>Concurrency.</b> One lock guards the whole map. Each check is a few arithmetic
 * operations, so the lock is held for tens of nanoseconds; this was chosen over a lock-free
 * design because it is obviously correct and admits exactly the tokens available.
 *
 * <p><b>Bounded memory.</b> The least recently used bucket is evicted when the map is full. An
 * evicted client that returns gets a fresh, full bucket: a bounded leniency accepted in place of
 * unbounded memory.
 */
final class TokenBucketLimiter {

    private static final long NANOS_PER_SECOND = 1_000_000_000L;

    private final long nanosPerToken;
    private final int burst;
    private final int ipv4PrefixBits;
    private final int ipv6PrefixBits;
    private final LongSupplier nanoClock;
    private final Map<Cidr, Bucket> buckets;

    TokenBucketLimiter(RateLimit limit, LongSupplier nanoClock) {
        if (!(limit.requestsPerSecond() > 0) || limit.requestsPerSecond() > NANOS_PER_SECOND) {
            throw new IllegalArgumentException("requestsPerSecond must be in (0, 1e9], was " + limit.requestsPerSecond());
        }
        if (limit.burst() < 1) {
            throw new IllegalArgumentException("burst must be at least 1, was " + limit.burst());
        }
        if (limit.maxTrackedClients() < 1) {
            throw new IllegalArgumentException("maxTrackedClients must be at least 1, was " + limit.maxTrackedClients());
        }
        this.nanosPerToken = Math.round(NANOS_PER_SECOND / limit.requestsPerSecond());
        this.burst = limit.burst();
        this.ipv4PrefixBits = limit.ipv4PrefixBits();
        this.ipv6PrefixBits = limit.ipv6PrefixBits();
        this.nanoClock = nanoClock;
        int capacity = limit.maxTrackedClients();
        this.buckets = new LinkedHashMap<>(16, 0.75f, true) {
            @Override
            protected boolean removeEldestEntry(Map.Entry<Cidr, Bucket> eldest) {
                return size() > capacity;
            }
        };
    }

    /** Takes one token from the client's bucket; false when the bucket is empty. */
    boolean tryAcquire(InetAddress client) {
        Cidr key = Cidr.containing(client, client.getAddress().length == 4 ? ipv4PrefixBits : ipv6PrefixBits);
        synchronized (buckets) {
            long now = nanoClock.getAsLong();
            Bucket bucket = buckets.get(key);
            if (bucket == null) {
                bucket = new Bucket(burst, now);
                buckets.put(key, bucket);
            }
            return bucket.tryTake(now);
        }
    }

    int trackedClients() {
        synchronized (buckets) {
            return buckets.size();
        }
    }

    /** Mutable state of one bucket; only touched while holding the limiter's lock. */
    private final class Bucket {
        private long tokens;
        private long lastRefillNanos;

        Bucket(long tokens, long nowNanos) {
            this.tokens = tokens;
            this.lastRefillNanos = nowNanos;
        }

        boolean tryTake(long nowNanos) {
            refill(nowNanos);
            if (tokens == 0) {
                return false;
            }
            tokens--;
            return true;
        }

        private void refill(long nowNanos) {
            long earned = (nowNanos - lastRefillNanos) / nanosPerToken;
            if (earned <= 0) {
                return;
            }
            if (earned >= burst - tokens) {
                tokens = burst;
                lastRefillNanos = nowNanos;
            } else {
                tokens += earned;
                lastRefillNanos += earned * nanosPerToken;
            }
        }
    }
}
