package io.aegis.loadtest;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.nio.file.Path;
import java.time.Duration;
import org.junit.jupiter.api.Test;

class LoadTestOptionsTest {

    private static LoadTestOptions parse(String... args) {
        return LoadTestOptions.parse(args);
    }

    @Test
    void appliesTheKillTestDefaults() {
        LoadTestOptions o = parse("--url", "https://example.com:8443");

        assertThat(o.rate()).isEqualTo(5000);
        assertThat(o.duration()).isEqualTo(Duration.ofSeconds(600));
        assertThat(o.warmup()).isEqualTo(Duration.ofSeconds(120));
        assertThat(o.connections()).isEqualTo(64);
        assertThat(o.newConnectionShare()).isEqualTo(0.05);
        assertThat(o.postShare()).isEqualTo(0.30);
        assertThat(o.bodyMinBytes()).isEqualTo(1024);
        assertThat(o.bodyMaxBytes()).isEqualTo(64 * 1024);
        assertThat(o.attackShare()).isEqualTo(0.01);
        assertThat(o.timeout()).isEqualTo(Duration.ofSeconds(5));
        assertThat(o.hostHeader()).isEqualTo("example.com:8443");
        assertThat(o.port()).isEqualTo(8443);
        assertThat(o.https()).isTrue();
    }

    @Test
    void readsEveryFlag() {
        LoadTestOptions o = parse("--url", "http://10.0.0.1", "--rate", "100", "--duration", "2m",
                "--warmup", "500ms", "--connections", "8", "--new-connection-share", "0.5",
                "--post-share", "1", "--body-min", "2KB", "--body-max", "1MB", "--attack-share", "0",
                "--host-header", "shop.test", "--tls-trust", "ca.pem", "--label", "direct",
                "--seed", "42", "--timeout", "1s", "--json", "out.json");

        assertThat(o.port()).isEqualTo(80);
        assertThat(o.https()).isFalse();
        assertThat(o.duration()).isEqualTo(Duration.ofMinutes(2));
        assertThat(o.warmup()).isEqualTo(Duration.ofMillis(500));
        assertThat(o.bodyMinBytes()).isEqualTo(2048);
        assertThat(o.bodyMaxBytes()).isEqualTo(1024 * 1024);
        assertThat(o.hostHeader()).isEqualTo("shop.test");
        assertThat(o.tlsTrust()).contains(Path.of("ca.pem"));
        assertThat(o.label()).isEqualTo("direct");
        assertThat(o.seed()).isEqualTo(42);
        assertThat(o.jsonFile()).contains(Path.of("out.json"));
    }

    @Test
    void parsesUnitsCaseInsensitively() {
        assertThat(Units.parseDuration("--d", "1h")).isEqualTo(Duration.ofHours(1));
        assertThat(Units.parseSizeBytes("--s", "3kb")).isEqualTo(3072);
        assertThat(Units.parseSizeBytes("--s", "7B")).isEqualTo(7);
    }

    @Test
    void rejectsAUrlWithoutHttpOrHttpsScheme() {
        assertThatThrownBy(() -> parse("--url", "ftp://host")).isInstanceOf(UsageException.class)
                .hasMessageContaining("http");
    }

    @Test
    void rejectsAUrlWithAPath() {
        assertThatThrownBy(() -> parse("--url", "http://host/app")).isInstanceOf(UsageException.class);
    }

    @Test
    void rejectsAMissingUrl() {
        assertThatThrownBy(() -> parse("--rate", "10")).isInstanceOf(UsageException.class)
                .hasMessage("--url is required");
    }

    @Test
    void rejectsAnUnknownFlagInsteadOfIgnoringIt() {
        assertThatThrownBy(() -> parse("--url", "http://h", "--rat", "10"))
                .isInstanceOf(UsageException.class).hasMessage("unknown argument: --rat");
    }

    @Test
    void rejectsAFlagWithoutAValue() {
        assertThatThrownBy(() -> parse("--url", "http://h", "--rate"))
                .isInstanceOf(UsageException.class).hasMessage("--rate needs a value");
    }

    @Test
    void rejectsARepeatedFlag() {
        assertThatThrownBy(() -> parse("--url", "http://h", "--rate", "1", "--rate", "2"))
                .isInstanceOf(UsageException.class).hasMessage("--rate given twice");
    }

    @Test
    void rejectsADurationWithoutAUnit() {
        assertThatThrownBy(() -> parse("--url", "http://h", "--duration", "600"))
                .isInstanceOf(UsageException.class).hasMessageContaining("--duration");
    }

    @Test
    void rejectsAnUnknownUnit() {
        assertThatThrownBy(() -> parse("--url", "http://h", "--body-max", "5GB"))
                .isInstanceOf(UsageException.class).hasMessageContaining("--body-max");
    }

    @Test
    void rejectsASizeOfTwoGigabytesOrMore() {
        assertThatThrownBy(() -> Units.parseSizeBytes("--body-max", "2048MB"))
                .isInstanceOf(UsageException.class);
    }

    @Test
    void rejectsASharedOutsideZeroToOne() {
        assertThatThrownBy(() -> parse("--url", "http://h", "--post-share", "1.5"))
                .isInstanceOf(UsageException.class).hasMessageContaining("--post-share");
        assertThatThrownBy(() -> parse("--url", "http://h", "--attack-share", "lots"))
                .isInstanceOf(UsageException.class).hasMessageContaining("--attack-share");
    }

    @Test
    void rejectsAZeroRateAndZeroConnections() {
        assertThatThrownBy(() -> parse("--url", "http://h", "--rate", "0")).isInstanceOf(UsageException.class);
        assertThatThrownBy(() -> parse("--url", "http://h", "--connections", "0")).isInstanceOf(UsageException.class);
    }

    @Test
    void rejectsABodyRangeThatIsBackwards() {
        assertThatThrownBy(() -> parse("--url", "http://h", "--body-min", "10KB", "--body-max", "1KB"))
                .isInstanceOf(UsageException.class).hasMessageContaining("--body-min");
    }

    @Test
    void rejectsAZeroDuration() {
        assertThatThrownBy(() -> parse("--url", "http://h", "--duration", "0s")).isInstanceOf(UsageException.class);
    }

    @Test
    void backendOptionsRequireACertificateAndKeyTogether() {
        assertThatThrownBy(() -> BackendOptions.parse(new String[] {"--name", "a", "--tls-cert", "c.pem"}))
                .isInstanceOf(UsageException.class);
    }

    @Test
    void backendOptionsReadDelayAndPort() {
        BackendOptions o = BackendOptions.parse(new String[] {"--name", "backend-a", "--port", "9000", "--delay-ms", "25"});

        assertThat(o.port()).isEqualTo(9000);
        assertThat(o.delay()).isEqualTo(Duration.ofMillis(25));
        assertThat(o.tls()).isEmpty();
    }
}
