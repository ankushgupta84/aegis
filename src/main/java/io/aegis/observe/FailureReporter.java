package io.aegis.observe;

import java.io.PrintStream;
import java.time.Clock;
import java.time.Duration;

/**
 * Reports a failure of the log itself to a stream, at most once per interval.
 *
 * <p>The log cannot record its own failure in itself, so standard error is the only place left;
 * the rate limit keeps a dead disk from turning into a flood there. Used by one thread only.
 */
final class FailureReporter {

    static final Duration INTERVAL = Duration.ofMinutes(1);

    private final Clock clock;
    private final PrintStream err;
    private long lastReportMillis;
    private boolean reportedBefore;

    FailureReporter(Clock clock, PrintStream err) {
        this.clock = clock;
        this.err = err;
    }

    void report(String what, Throwable cause) {
        long now = clock.millis();
        if (reportedBefore && now - lastReportMillis < INTERVAL.toMillis()) {
            return;
        }
        reportedBefore = true;
        lastReportMillis = now;
        err.println("aegis event log: " + what + ": " + cause);
    }
}
