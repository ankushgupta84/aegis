package io.aegis.observe;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneId;
import org.junit.jupiter.api.Test;

class FailureReporterTest {

    private final ByteArrayOutputStream captured = new ByteArrayOutputStream();
    private final SteppingClock clock = new SteppingClock();
    private final FailureReporter reporter =
            new FailureReporter(clock, new PrintStream(captured, true, StandardCharsets.UTF_8));

    @Test
    void first_failure_is_reported_with_its_cause() {
        reporter.report("cannot write", new IOException("disk full"));

        assertThat(output()).contains("cannot write").contains("disk full");
    }

    @Test
    void further_failures_within_a_minute_are_silent() {
        reporter.report("first", new IOException("a"));
        clock.advanceMillis(59_999);
        reporter.report("second", new IOException("b"));

        assertThat(output()).contains("first").doesNotContain("second");
    }

    @Test
    void a_failure_a_minute_later_is_reported_again() {
        reporter.report("first", new IOException("a"));
        clock.advanceMillis(60_000);
        reporter.report("second", new IOException("b"));

        assertThat(output()).contains("first").contains("second");
    }

    private String output() {
        return captured.toString(StandardCharsets.UTF_8);
    }

    /** A clock that moves only when the test says so. */
    static final class SteppingClock extends Clock {
        private long millis = Instant.parse("2026-01-01T00:00:00Z").toEpochMilli();

        void advanceMillis(long delta) {
            millis += delta;
        }

        @Override
        public ZoneId getZone() {
            return ZoneId.of("UTC");
        }

        @Override
        public Clock withZone(ZoneId zone) {
            return this;
        }

        @Override
        public Instant instant() {
            return Instant.ofEpochMilli(millis);
        }
    }
}
