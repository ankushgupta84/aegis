package io.aegis.proxy;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import io.aegis.config.ConfigLoader;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** The admin listener, startup failures, and shutdown. */
class AdminAndLifecycleTest {

    @TempDir
    Path dir;

    private static long eventLogThreads() {
        return Thread.getAllStackTraces().keySet().stream()
                .filter(t -> t.getName().equals("aegis-event-log") && t.isAlive()).count();
    }

    @Test
    void metricsShowRequestAndRuleHitCountersAndHealthzAnswers() throws Exception {
        try (ScriptedBackend backend = ScriptedBackend.answering("hello");
                TestProxy proxy = TestProxy.config(dir).backends(backend.port()).start();
                RawClient client = new RawClient(proxy.port())) {
            client.get("/");
            client.get("/?q=1%20union%20select%201");

            HttpResponse<String> metrics = proxy.adminResponse("/metrics");
            assertThat(metrics.statusCode()).isEqualTo(200);
            assertThat(metrics.headers().firstValue("Content-Type").orElse("")).startsWith("text/plain; version=0.0.4");
            assertThat(metrics.body())
                    .containsPattern("aegis_requests_total\\{[^}]*decision=\"allowed\"[^}]*\\} 1.0")
                    .containsPattern("aegis_requests_total\\{[^}]*decision=\"waf_blocked\"[^}]*\\} 1.0")
                    .containsPattern("aegis_waf_rule_hits_total\\{[^}]*sid=\"1000001\"[^}]*\\} 1.0")
                    .contains("aegis_request_duration_seconds_bucket")
                    .contains("aegis_waf_inspection_seconds_bucket")
                    .containsPattern("aegis_firewall_decisions_total\\{verdict=\"allow\"\\} 2.0")
                    .containsPattern("aegis_backend_requests_total\\{[^}]*result=\"success\"[^}]*\\} 1.0")
                    .containsPattern("aegis_rules_loaded_total\\{[^}]*rule_set=\"test\"[^}]*status=\"active\"[^}]*\\} 4.0")
                    .contains("aegis_rate_limit_tracked_clients")
                    .contains("aegis_log_events_dropped")
                    .contains("aegis_log_write_failures");
            HttpResponse<String> health = proxy.adminResponse("/healthz");
            assertThat(health.statusCode()).isEqualTo(200);
            assertThat(health.body()).isEqualTo("ok");
        }
    }

    @Test
    void theAdminListenerAnswers404ForOtherPathsAnd405ForOtherMethodsAndNeverProxies() throws Exception {
        try (ScriptedBackend backend = ScriptedBackend.answering("hello");
                TestProxy proxy = TestProxy.config(dir).backends(backend.port()).start()) {
            HttpClient http = HttpClient.newHttpClient();
            String base = "http://127.0.0.1:" + proxy.server().adminPort();

            assertThat(proxy.adminResponse("/").statusCode()).isEqualTo(404);
            assertThat(proxy.adminResponse("/anything/else").statusCode()).isEqualTo(404);
            HttpResponse<String> post = http.send(HttpRequest.newBuilder(URI.create(base + "/metrics"))
                    .POST(HttpRequest.BodyPublishers.ofString("x")).build(), HttpResponse.BodyHandlers.ofString());
            assertThat(post.statusCode()).isEqualTo(405);
            assertThat(backend.requests()).isEmpty();
        }
    }

    @Test
    void startupLogsRuleSetAndStartupEvents() throws Exception {
        try (ScriptedBackend backend = ScriptedBackend.answering("hello");
                TestProxy proxy = TestProxy.config(dir).backends(backend.port()).start()) {
            proxy.awaitEvent("rule_set_loaded", e -> e.get("rule_set").asText().equals("test")
                    && e.get("active").asInt() == 4 && e.get("unsupported").asInt() == 0);
            proxy.awaitEvent("rule_set_loaded", e -> e.get("rule_set").asText().equals("monitor"));
            proxy.awaitEvent("startup", e -> e.get("port").asInt() == proxy.port());
        }
    }

    @Test
    void aMissingRuleFileStopsStartupWithAClearMessageAndOpensNothing() throws Exception {
        String yaml = TestProxy.config(dir).backends(1).yaml().replace(
                TestProxy.TEST_RULES.toString(), dir.resolve("missing.rules").toString());

        assertThatThrownBy(() -> AegisServer.start(ConfigLoader.parse(yaml)))
                .isInstanceOf(StartupException.class)
                .hasMessageContaining("missing.rules")
                .hasMessageContaining("'test'");
        assertThat(Files.exists(dir.resolve("logs"))).isFalse();
    }

    @Test
    void aFailureAfterPartOfStartupClosesWhatWasAlreadyOpen() throws Exception {
        long before = eventLogThreads();
        try (ScriptedBackend backend = ScriptedBackend.answering("hello");
                TestProxy first = TestProxy.config(dir.resolve("first")).backends(backend.port()).start()) {
            long withOne = eventLogThreads();
            String yaml = TestProxy.config(dir.resolve("second")).backends(backend.port())
                    .listenerPort(first.port()).yaml();

            assertThatThrownBy(() -> AegisServer.start(ConfigLoader.parse(yaml))).isInstanceOf(StartupException.class).hasMessageContaining("Cannot listen");

            assertThat(eventLogThreads()).isEqualTo(withOne);
            assertThat(withOne).isEqualTo(before + 1);
        }
    }

    @Test
    void gracefulCloseLetsAnInFlightRequestFinish() throws Exception {
        CountDownLatch release = new CountDownLatch(1);
        ScriptedBackend.Behavior gated = (request, socket) -> {
            try {
                release.await(10, TimeUnit.SECONDS);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
            ScriptedBackend.answer(200, "finished").respond(request, socket);
        };
        try (ScriptedBackend backend = ScriptedBackend.start(gated);
                TestProxy proxy = TestProxy.config(dir).backends(backend.port()).start();
                RawClient client = new RawClient(proxy.port())) {
            CompletableFuture<RawClient.Response> inFlight = CompletableFuture.supplyAsync(() -> {
                try {
                    return client.get("/slow");
                } catch (Exception e) {
                    throw new IllegalStateException(e);
                }
            });
            Await.until("the backend to receive the request", () -> !backend.requests().isEmpty());

            CompletableFuture<Void> closing = CompletableFuture.runAsync(proxy::close);
            Await.until("the listener to stop accepting", () -> {
                try {
                    new RawClient(proxy.port(), 200).close();
                    return false;
                } catch (IOException e) {
                    return true;
                }
            });
            assertThat(closing).isNotDone();
            release.countDown();

            RawClient.Response response = inFlight.get(10, TimeUnit.SECONDS);
            assertThat(response.status()).isEqualTo(200);
            assertThat(response.text()).isEqualTo("finished");
            assertThat(response.header("Connection")).isEqualToIgnoringCase("close");
            closing.get(10, TimeUnit.SECONDS);
        }
    }
}
