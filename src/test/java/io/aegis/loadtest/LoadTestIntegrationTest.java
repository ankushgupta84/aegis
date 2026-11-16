package io.aegis.loadtest;

import static org.assertj.core.api.Assertions.assertThat;

import io.netty.pkitesting.CertificateBuilder;
import io.netty.pkitesting.X509Bundle;
import java.io.IOException;
import java.net.ServerSocket;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class LoadTestIntegrationTest {

    /** Short, low-rate defaults; {@code overrides} are flag/value pairs that replace them. */
    private static LoadTestOptions options(String url, String... overrides) {
        Map<String, String> flags = new LinkedHashMap<>();
        flags.put("--url", url);
        flags.put("--rate", "50");
        flags.put("--duration", "1s");
        flags.put("--warmup", "0s");
        flags.put("--connections", "8");
        flags.put("--post-share", "0.3");
        flags.put("--body-min", "1KB");
        flags.put("--body-max", "8KB");
        flags.put("--attack-share", "0");
        flags.put("--new-connection-share", "0.2");
        flags.put("--seed", "7");
        for (int i = 0; i < overrides.length; i += 2) {
            flags.put(overrides[i], overrides[i + 1]);
        }
        return LoadTestOptions.parse(flags.entrySet().stream()
                .flatMap(e -> Stream.of(e.getKey(), e.getValue())).toArray(String[]::new));
    }

    @Test
    void measuresAFastBackendWithoutErrors() throws Exception {
        try (DummyBackend.Handle backend = DummyBackend.start(BackendOptions.plain("backend-a"))) {
            Report report = LoadTester.run(options("http://localhost:" + backend.port()));

            assertThat(report.requests()).isBetween(45L, 55L);
            assertThat(report.responsesByStatus()).containsOnlyKeys(200);
            assertThat(report.errors()).isZero();
            assertThat(report.otherNon2xx()).isZero();
            assertThat(report.achievedRate()).isBetween(35.0, 55.0);
            assertThat(report.latencyMs().p99()).isLessThan(500.0);
        }
    }

    @Test
    void latencyReflectsTheBackendDelay() throws Exception {
        BackendOptions slow = BackendOptions.plain("slow").withDelay(Duration.ofMillis(100));
        try (DummyBackend.Handle backend = DummyBackend.start(slow)) {
            Report report = LoadTester.run(options("http://localhost:" + backend.port()));

            assertThat(report.errors()).isZero();
            assertThat(report.latencyMs().p50()).isBetween(100.0, 400.0);
        }
    }

    @Test
    void aSlowBackendBuildsAQueueWhenConnectionsAreTooFew() throws Exception {
        BackendOptions slow = BackendOptions.plain("slow").withDelay(Duration.ofMillis(200));
        try (DummyBackend.Handle backend = DummyBackend.start(slow)) {
            // 50 requests/s at 200 ms each needs about 10 connections; give it 2 and no fresh connections.
            Report report = LoadTester.run(options("http://localhost:" + backend.port(),
                    "--connections", "2", "--new-connection-share", "0", "--timeout", "30s"));

            assertThat(report.maxQueueDepth()).isGreaterThan(5);
            assertThat(report.errors()).isZero();
            assertThat(report.latencyMs().max()).isGreaterThan(1000.0);
        }
    }

    @Test
    void aRequestThatOutlastsTheTimeoutIsAnErrorAtTheTimeoutValue() throws Exception {
        BackendOptions slow = BackendOptions.plain("slow").withDelay(Duration.ofMillis(800));
        try (DummyBackend.Handle backend = DummyBackend.start(slow)) {
            Report report = LoadTester.run(options("http://localhost:" + backend.port(), "--timeout", "300ms"));

            assertThat(report.errorsByCause().get(ErrorCause.TIMEOUT)).isEqualTo(report.requests());
            assertThat(report.latencyMs().p50()).isBetween(299.0, 301.0);
        }
    }

    @Test
    void aClosedPortReportsConnectFailuresInsteadOfHanging() throws Exception {
        int closedPort;
        try (ServerSocket probe = new ServerSocket(0)) {
            closedPort = probe.getLocalPort();
        }

        Report report = LoadTester.run(options("http://localhost:" + closedPort, "--timeout", "2s"));

        assertThat(report.requests()).isBetween(45L, 55L);
        assertThat(report.errorsByCause().get(ErrorCause.CONNECT_FAILURE)).isEqualTo(report.requests());
        assertThat(report.responsesByStatus()).isEmpty();
    }

    @Test
    void verifiesTheServerCertificateAgainstTheTrustFile(@TempDir Path dir) throws Exception {
        X509Bundle server = new CertificateBuilder().subject("CN=localhost").addSanDnsName("localhost")
                .setIsCertificateAuthority(true).buildSelfSigned();
        Path certificate = write(dir.resolve("cert.pem"), server.getCertificatePEM());
        Path key = write(dir.resolve("key.pem"), server.getPrivateKeyPEM());
        BackendOptions tls = BackendOptions.plain("secure").withTls(new BackendOptions.TlsFiles(certificate, key));
        try (DummyBackend.Handle backend = DummyBackend.start(tls)) {
            String url = "https://localhost:" + backend.port();

            Report trusted = LoadTester.run(options(url, "--tls-trust", certificate.toString()));
            Report untrusted = LoadTester.run(options(url));

            assertThat(trusted.errors()).isZero();
            assertThat(trusted.responsesByStatus()).containsOnlyKeys(200);
            assertThat(untrusted.errorsByCause().get(ErrorCause.TLS_FAILURE)).isEqualTo(untrusted.requests());
        }
    }

    @Test
    void refusesACertificateThatDoesNotNameTheHost(@TempDir Path dir) throws Exception {
        X509Bundle server = new CertificateBuilder().subject("CN=other.example").addSanDnsName("other.example")
                .setIsCertificateAuthority(true).buildSelfSigned();
        Path certificate = write(dir.resolve("cert.pem"), server.getCertificatePEM());
        Path key = write(dir.resolve("key.pem"), server.getPrivateKeyPEM());
        BackendOptions tls = BackendOptions.plain("secure").withTls(new BackendOptions.TlsFiles(certificate, key));
        try (DummyBackend.Handle backend = DummyBackend.start(tls)) {
            Report report = LoadTester.run(
                    options("https://localhost:" + backend.port(), "--tls-trust", certificate.toString()));

            assertThat(report.errorsByCause().get(ErrorCause.TLS_FAILURE)).isEqualTo(report.requests());
        }
    }

    @Test
    void writesTheReportAsJson(@TempDir Path dir) throws Exception {
        Path json = dir.resolve("run.json");
        try (DummyBackend.Handle backend = DummyBackend.start(BackendOptions.plain("backend-a"))) {
            Report report = LoadTester.run(options("http://localhost:" + backend.port(), "--label", "direct"));
            ReportJson.write(report, json);
        }

        String text = Files.readString(json);
        assertThat(text).contains("\"label\" : \"direct\"", "\"configuredRate\" : 50", "\"p99\"",
                "\"maxQueueDepth\"", "\"CONNECT_FAILURE\" : 0", "\"200\"");
    }

    private static Path write(Path file, String content) throws IOException {
        return Files.writeString(file, content);
    }
}
