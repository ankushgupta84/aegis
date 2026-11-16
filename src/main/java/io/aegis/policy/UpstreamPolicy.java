package io.aegis.policy;

import java.time.Duration;
import java.util.List;

/**
 * A route's backends and how Aegis talks to them.
 *
 * @param connectTimeout  the longest a connection attempt may take
 * @param responseTimeout the longest Aegis waits for a complete response
 */
public record UpstreamPolicy(
        List<BackendAddress> backends,
        HealthKnobs health,
        Duration connectTimeout,
        Duration responseTimeout,
        UpstreamTls tls) {

    public UpstreamPolicy {
        backends = List.copyOf(backends);
    }
}
