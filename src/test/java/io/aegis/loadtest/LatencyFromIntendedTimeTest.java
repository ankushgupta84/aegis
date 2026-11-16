package io.aegis.loadtest;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

class LatencyFromIntendedTimeTest {

    private static final RequestSpec GET = new RequestSpec(false, 0, "/", false, false);

    @Test
    void countsFromTheIntendedTimeNotFromTheSendTime() {
        PendingRequest dueAt1000 = new PendingRequest(GET, 1_000, true);

        // Sent at 5_000 because every connection was busy; the 4_000 of waiting still counts.
        assertThat(dueAt1000.latencyNanos(6_000)).isEqualTo(5_000);
    }

    @Test
    void aSettledRequestIgnoresLaterEvents() {
        PendingRequest request = new PendingRequest(GET, 0, true);

        assertThat(request.settle()).isTrue();
        assertThat(request.settle()).isFalse();
    }

    @Test
    void anErrorEntersTheHistogramAtTheTimeoutValue() {
        Measurements measurements = new Measurements(5_000_000_000L);
        PendingRequest request = new PendingRequest(GET, 0, true);

        measurements.failure(request, ErrorCause.CONNECT_FAILURE, 1_000);

        Report report = measurements.report(
                LoadTestOptions.parse(new String[] {"--url", "http://h"}), 0);
        assertThat(report.latencyMs().p50()).isBetween(4990.0, 5010.0);
        assertThat(report.errorsByCause()).containsEntry(ErrorCause.CONNECT_FAILURE, 1L);
    }

    @Test
    void separatesExpectedAttackBlocksFromOtherNon2xx() {
        Measurements measurements = new Measurements(5_000_000_000L);
        RequestSpec attack = new RequestSpec(false, 0, "/x", true, false);
        measurements.response(new PendingRequest(attack, 0, true), 403, 1_000_000);
        measurements.response(new PendingRequest(attack, 0, true), 200, 1_000_000);
        measurements.response(new PendingRequest(GET, 0, true), 403, 1_000_000);
        measurements.response(new PendingRequest(GET, 0, true), 502, 1_000_000);
        measurements.response(new PendingRequest(GET, 0, true), 200, 1_000_000);

        Report report = measurements.report(LoadTestOptions.parse(new String[] {"--url", "http://h"}), 0);

        assertThat(report.attackRequests()).isEqualTo(2);
        assertThat(report.expectedAttackBlocks()).isEqualTo(1);
        assertThat(report.otherNon2xx()).isEqualTo(2);
        assertThat(report.responsesByStatus()).containsEntry(403, 2L).containsEntry(502, 1L);
    }
}
