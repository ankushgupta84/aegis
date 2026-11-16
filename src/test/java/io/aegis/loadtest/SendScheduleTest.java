package io.aegis.loadtest;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

class SendScheduleTest {

    @Test
    void spacesRequestsExactlyOneIntervalApart() {
        SendSchedule schedule = new SendSchedule(1_000, 5000);

        assertThat(schedule.intendedAt(0)).isEqualTo(1_000);
        assertThat(schedule.intendedAt(1) - schedule.intendedAt(0)).isEqualTo(200_000);
        assertThat(schedule.intendedAt(2) - schedule.intendedAt(1)).isEqualTo(200_000);
    }

    @Test
    void doesNotDriftOverAMillionTicks() {
        SendSchedule schedule = new SendSchedule(0, 5000);

        assertThat(schedule.intendedAt(1_000_000)).isEqualTo(200_000_000_000L);
    }

    @Test
    void doesNotAccumulateRoundingWhenTheIntervalIsNotWhole() {
        // 1e9 / 3 is 333_333_333.33... ns; adding a rounded interval a million times would lose 333_333 ns.
        SendSchedule schedule = new SendSchedule(0, 3);

        assertThat(schedule.intendedAt(3_000_000)).isEqualTo(1_000_000_000_000_000L);
        assertThat(schedule.intendedAt(1_000_000)).isEqualTo(333_333_333_333_333L);
    }

    @Test
    void neverEmitsBeforeThePreviousRequest() {
        SendSchedule schedule = new SendSchedule(0, 7_000_000);

        for (long i = 1; i <= 100_000; i++) {
            assertThat(schedule.intendedAt(i)).isGreaterThanOrEqualTo(schedule.intendedAt(i - 1));
        }
    }
}
