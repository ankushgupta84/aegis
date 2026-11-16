package io.aegis.loadtest;

/**
 * The intended send time of every request: request {@code n} is due {@code n / rate} seconds
 * after the origin. Each time is computed from the index in integer nanoseconds, never by adding
 * a rounded interval to the previous one, so rounding error cannot accumulate into drift.
 */
record SendSchedule(long originNanos, long ratePerSecond) {

    private static final long NANOS_PER_SECOND = 1_000_000_000L;

    long intendedAt(long index) {
        return originNanos + Math.multiplyExact(index, NANOS_PER_SECOND) / ratePerSecond;
    }
}
