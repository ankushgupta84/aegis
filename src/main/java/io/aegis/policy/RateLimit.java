package io.aegis.policy;

/**
 * A token bucket per client block. Each node keeps its own buckets, so a client spread across N
 * nodes can reach N times the rate.
 *
 * @param requestsPerSecond the steady rate at which a bucket refills
 * @param burst             the bucket's capacity: how many requests may arrive at once
 * @param ipv4PrefixBits    clients sharing this IPv4 prefix share a bucket (32 = one address)
 * @param ipv6PrefixBits    clients sharing this IPv6 prefix share a bucket (64 = one subnet)
 * @param maxTrackedClients the most buckets held at once; idle ones are evicted first
 */
public record RateLimit(
        boolean enabled,
        double requestsPerSecond,
        int burst,
        int ipv4PrefixBits,
        int ipv6PrefixBits,
        int maxTrackedClients) {
}
