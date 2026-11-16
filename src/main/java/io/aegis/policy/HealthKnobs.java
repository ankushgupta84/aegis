package io.aegis.policy;

import java.time.Duration;

/**
 * Passive health checking: Aegis judges a backend by the real requests it serves.
 *
 * @param failuresToEject     consecutive failures that take a backend out of rotation
 * @param ejectionTime        how long an ejected backend sits out before it is tried again
 * @param countServerErrors   whether a 5xx response counts as a failure; connect errors and
 *                            timeouts always do
 */
public record HealthKnobs(int failuresToEject, Duration ejectionTime, boolean countServerErrors) {
}
