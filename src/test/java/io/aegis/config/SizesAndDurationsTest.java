package io.aegis.config;

import static org.assertj.core.api.Assertions.assertThat;

import io.aegis.policy.AegisConfig;
import java.time.Duration;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;

class SizesAndDurationsTest {

    private static AegisConfig withListener(String settings) {
        return ConfigLoader.parse(TestYaml.MINIMAL.replace("  tls: false\n", "  tls: false\n" + settings.indent(2)));
    }

    static Stream<Arguments> sizes() {
        return Stream.of(
                Arguments.of("512B", 512),
                Arguments.of("16KB", 16 * 1024),
                Arguments.of("10MB", 10 * 1024 * 1024),
                Arguments.of("1GB", 1 << 30),
                Arguments.of("4096", 4096));
    }

    @ParameterizedTest(name = "{0} is {1} bytes")
    @MethodSource("sizes")
    void sizesUseUnitsOfOneThousandAndTwentyFour(String written, int bytes) {
        assertThat(withListener("max_body_bytes: " + written).listener().maxBodyBytes()).isEqualTo(bytes);
    }

    @Test
    void aBareYamlIntegerIsAByteCount() {
        assertThat(withListener("max_body_bytes: 2048").listener().maxBodyBytes()).isEqualTo(2048);
    }

    @ParameterizedTest
    @ValueSource(strings = {"10 MB", "10mb", "ten", "1.5MB", "-1KB", "10TB"})
    void aMalformedSizeNamesTheKeyAndShowsValidSizes(String written) {
        assertThat(TestYaml.problemsOf(TestYaml.MINIMAL.replace("tls: false", "tls: false\n  max_body_bytes: \"" + written + "\"")))
                .containsExactly("listener.max_body_bytes: '" + written + "' is not a size. "
                        + "Write a whole number and a unit, e.g. 512B, 16KB, 10MB, 1GB. A bare number means bytes.");
    }

    @Test
    void aZeroSizeIsRefused() {
        assertThat(TestYaml.problemsOf(TestYaml.MINIMAL.replace("tls: false", "tls: false\n  max_body_bytes: 0")))
                .containsExactly("listener.max_body_bytes: A size must be greater than zero. "
                        + "Write a whole number and a unit, e.g. 512B, 16KB, 10MB, 1GB. A bare number means bytes.");
    }

    @Test
    void aSizeBeyondWhatTheKnobCanHoldIsRefused() {
        assertThat(TestYaml.problemsOf(TestYaml.MINIMAL.replace("tls: false", "tls: false\n  max_body_bytes: 4GB")))
                .containsExactly("listener.max_body_bytes: '4GB' is too large here. The most allowed is 2147483647 bytes.");
    }

    static Stream<Arguments> durations() {
        return Stream.of(
                Arguments.of("250ms", Duration.ofMillis(250)),
                Arguments.of("5s", Duration.ofSeconds(5)),
                Arguments.of("2m", Duration.ofMinutes(2)),
                Arguments.of("1h", Duration.ofHours(1)));
    }

    @ParameterizedTest(name = "{0} is {1}")
    @MethodSource("durations")
    void durationsTakeMillisecondsSecondsMinutesAndHours(String written, Duration expected) {
        assertThat(withListener("idle_timeout: " + written).listener().idleTimeout()).isEqualTo(expected);
    }

    @ParameterizedTest
    @ValueSource(strings = {"5 sec", "5", "five seconds", "1d", "-5s", "1.5s"})
    void aMalformedDurationNamesTheKeyAndShowsValidDurations(String written) {
        assertThat(TestYaml.problemsOf(TestYaml.route("health:\n  ejection_time: \"" + written + "\"")))
                .containsExactly("routes[0].health.ejection_time: '" + written + "' is not a duration. "
                        + "Write a number and a unit, e.g. 500ms, 5s, 2m.");
    }

    @Test
    void aZeroDurationIsRefused() {
        assertThat(TestYaml.problemsOf(TestYaml.route("connect_timeout: 0s")))
                .containsExactly("routes[0].connect_timeout: A duration must be longer than zero. "
                        + "Write a number and a unit, e.g. 500ms, 5s, 2m.");
    }
}
