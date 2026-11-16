package io.aegis.lb;

import io.aegis.policy.BackendAddress;
import io.aegis.policy.HealthKnobs;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.LongSupplier;

/**
 * Round-robin selection over one route's backends, skipping those that passive health checking
 * has ejected. One instance serves all event-loop threads of a route.
 *
 * <p>Health rules: {@code failuresToEject} consecutive failures eject a backend for
 * {@code ejectionTime}; a success resets the count. When the time has passed the backend rejoins
 * on probation (see {@link BackendHealth}): a single further failure ejects it again for a full
 * {@code ejectionTime}, and a success restores it fully. Whether a 5xx response is a failure is
 * the caller's decision.
 *
 * <p>Concurrency: the pick path takes no lock. Each pick draws one ticket from an atomic counter
 * and starts scanning at {@code ticket mod size}, so with every backend healthy the distribution
 * is exactly even, however many threads pick. When backends are ejected the scan moves on to the
 * next healthy one, so the backend after an ejected one temporarily takes a double share.
 *
 * <p>Guarantee: a pick that starts after {@link #reportFailure} returned for the ejecting
 * failure never returns that backend until the ejection time has passed. A pick running
 * concurrently with the report may still return it, as if it had happened first. Nothing can be
 * promised about the backend's health by the time the caller uses it.
 */
public final class LoadBalancer {

    private final List<BackendAddress> backends;
    private final Map<BackendAddress, BackendHealth> health;
    private final LongSupplier nanoClock;
    private final AtomicLong tickets;

    public LoadBalancer(List<BackendAddress> backends, HealthKnobs health, LongSupplier nanoClock) {
        this(backends, health, nanoClock, 0);
    }

    /** Starts the ticket counter at {@code firstTicket} so tests can reach the wrap-around cheaply. */
    LoadBalancer(List<BackendAddress> backends, HealthKnobs knobs, LongSupplier nanoClock, long firstTicket) {
        requireValid(backends, knobs);
        this.backends = List.copyOf(backends);
        this.nanoClock = nanoClock;
        this.tickets = new AtomicLong(firstTicket);
        this.health = new LinkedHashMap<>();
        for (BackendAddress backend : this.backends) {
            health.put(backend, new BackendHealth(knobs.failuresToEject(), knobs.ejectionTime().toNanos()));
        }
    }

    /** The next healthy backend in round-robin order, or empty when every backend is ejected. */
    public Optional<BackendAddress> pick() {
        return firstHealthyFrom(nextTicket(), null);
    }

    /**
     * Like {@link #pick()} but never returns {@code tried}, for the single retry. Empty when no
     * other backend is healthy, which includes a route with only one backend.
     */
    public Optional<BackendAddress> pickOtherThan(BackendAddress tried) {
        healthOf(tried);
        return firstHealthyFrom(nextTicket(), tried);
    }

    public void reportSuccess(BackendAddress backend) {
        healthOf(backend).recordSuccess();
    }

    /** Records a connect error, connect timeout, or response timeout. */
    public void reportFailure(BackendAddress backend) {
        healthOf(backend).recordFailure(nanoClock.getAsLong());
    }

    public boolean isEjected(BackendAddress backend) {
        return healthOf(backend).isEjected(nanoClock.getAsLong());
    }

    /** All backends in configured order, ejected or not. */
    public List<BackendAddress> backends() {
        return backends;
    }

    private long nextTicket() {
        return tickets.getAndIncrement();
    }

    private Optional<BackendAddress> firstHealthyFrom(long ticket, BackendAddress excluded) {
        long now = nanoClock.getAsLong();
        // floorMod keeps the index non-negative even if the counter ever wraps.
        int start = (int) Math.floorMod(ticket, (long) backends.size());
        for (int offset = 0; offset < backends.size(); offset++) {
            BackendAddress candidate = backends.get((start + offset) % backends.size());
            if (!candidate.equals(excluded) && !health.get(candidate).isEjected(now)) {
                return Optional.of(candidate);
            }
        }
        return Optional.empty();
    }

    private BackendHealth healthOf(BackendAddress backend) {
        BackendHealth found = health.get(backend);
        if (found == null) {
            throw new IllegalArgumentException("Unknown backend: " + backend);
        }
        return found;
    }

    private static void requireValid(List<BackendAddress> backends, HealthKnobs knobs) {
        if (backends.isEmpty()) {
            throw new IllegalArgumentException("A route needs at least one backend");
        }
        if (backends.stream().distinct().count() != backends.size()) {
            throw new IllegalArgumentException("Duplicate backend in " + backends);
        }
        if (knobs.failuresToEject() < 1) {
            throw new IllegalArgumentException("failuresToEject must be at least 1: " + knobs.failuresToEject());
        }
        if (knobs.ejectionTime().isNegative() || knobs.ejectionTime().isZero()) {
            throw new IllegalArgumentException("ejectionTime must be positive: " + knobs.ejectionTime());
        }
    }
}
