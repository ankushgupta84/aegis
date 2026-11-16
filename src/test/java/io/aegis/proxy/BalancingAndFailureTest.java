package io.aegis.proxy;

import static org.assertj.core.api.Assertions.assertThat;

import com.fasterxml.jackson.databind.JsonNode;
import io.aegis.loadtest.BackendOptions;
import io.aegis.loadtest.DummyBackend;
import java.net.ServerSocket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** Which backend serves a request, and what happens when backends misbehave or are gone. */
class BalancingAndFailureTest {

    @TempDir
    Path dir;

    /** Two distinct ports nothing listens on: both sockets are open together so the ports differ, then closed. */
    private static int[] twoClosedPorts() throws Exception {
        try (ServerSocket first = new ServerSocket(0); ServerSocket second = new ServerSocket(0)) {
            return new int[] {first.getLocalPort(), second.getLocalPort()};
        }
    }

    @Test
    void roundRobinAlternatesStrictlyBetweenTwoBackends() throws Exception {
        try (DummyBackend.Handle a = DummyBackend.start(BackendOptions.plain("a"));
                DummyBackend.Handle b = DummyBackend.start(BackendOptions.plain("b"));
                TestProxy proxy = TestProxy.config(dir).backends(a.port(), b.port()).start();
                RawClient client = new RawClient(proxy.port())) {
            List<String> served = new ArrayList<>();
            for (int i = 0; i < 8; i++) {
                served.add(client.get("/").header("X-Backend"));
            }

            assertThat(served).containsExactly("a", "b", "a", "b", "a", "b", "a", "b");
        }
    }

    @Test
    void anUnknownHostOrPathGets404() throws Exception {
        try (ScriptedBackend backend = ScriptedBackend.answering("hello");
                TestProxy proxy = TestProxy.config(dir).backends(backend.port())
                        .host("app.example.com").pathPrefix("/api").start();
                RawClient client = new RawClient(proxy.port())) {
            assertThat(client.get("/api/items", "Host: app.example.com:8443").status()).isEqualTo(200);
            assertThat(client.get("/api/items", "Host: other.example.com").status()).isEqualTo(404);
            RawClient.Response wrongPath = client.get("/web", "Host: app.example.com");

            assertThat(wrongPath.status()).isEqualTo(404);
            assertThat(wrongPath.text()).contains("Incident ID: " + wrongPath.header("X-Request-Id"));
            assertThat(backend.requests()).hasSize(1);
        }
    }

    @Test
    void aGetToADeadFirstBackendIsRetriedOnTheSecondAndSucceeds() throws Exception {
        try (DummyBackend.Handle live = DummyBackend.start(BackendOptions.plain("live"));
                TestProxy proxy = TestProxy.config(dir).backends(twoClosedPorts()[0], live.port()).start();
                RawClient client = new RawClient(proxy.port())) {
            RawClient.Response response = client.get("/");

            assertThat(response.status()).isEqualTo(200);
            assertThat(response.header("X-Backend")).isEqualTo("live");
            JsonNode event = proxy.requestEvent(response.header("X-Request-Id"));
            assertThat(event.get("retried").asBoolean()).isTrue();
            assertThat(event.get("decision").asText()).isEqualTo("allowed");
            proxy.awaitEvent("backend_failure", e -> e.get("cause").asText().equals("connect_error"));
        }
    }

    @Test
    void aPostWhoseBackendDiesAfterReceivingItIsNotRetriedAndGets502() throws Exception {
        try (ScriptedBackend dying = ScriptedBackend.start(ScriptedBackend.dieAfterReadingRequest());
                ScriptedBackend healthy = ScriptedBackend.answering("never reached");
                TestProxy proxy = TestProxy.config(dir).backends(dying.port(), healthy.port()).start();
                RawClient client = new RawClient(proxy.port())) {
            RawClient.Response response = client.send("POST", "/pay", "amount=1".getBytes(StandardCharsets.UTF_8));

            assertThat(response.status()).isEqualTo(502);
            assertThat(dying.requests()).hasSize(1);
            assertThat(healthy.requests()).isEmpty();
            JsonNode event = proxy.requestEvent(response.header("X-Request-Id"));
            assertThat(event.get("decision").asText()).isEqualTo("upstream_failed");
            assertThat(event.get("retried").asBoolean()).isFalse();
        }
    }

    @Test
    void allBackendsDownGives502BeforeEjectionAnd503After() throws Exception {
        try (TestProxy proxy = TestProxy.config(dir).backends(twoClosedPorts()).start()) {
            List<Integer> statuses = new ArrayList<>();
            for (int i = 0; i < 3; i++) {
                try (RawClient client = new RawClient(proxy.port())) {
                    statuses.add(client.get("/").status());
                }
            }

            assertThat(statuses).containsExactly(502, 502, 503);
            proxy.awaitEvent("backend_ejected", e -> true);
            proxy.awaitEvent("request", e -> e.get("decision").asText().equals("no_backend"));
        }
    }

    @Test
    void aSlowBackendPastTheResponseTimeoutGets504() throws Exception {
        try (ScriptedBackend slow = ScriptedBackend.start(ScriptedBackend.hang());
                TestProxy proxy = TestProxy.config(dir).backends(slow.port()).responseTimeout("300ms").start();
                RawClient client = new RawClient(proxy.port())) {
            RawClient.Response response = client.get("/");

            assertThat(response.status()).isEqualTo(504);
            JsonNode event = proxy.requestEvent(response.header("X-Request-Id"));
            assertThat(event.get("decision").asText()).isEqualTo("upstream_timeout");
            proxy.awaitEvent("backend_failure", e -> e.get("cause").asText().equals("response_timeout"));
        }
    }

    @Test
    void manySequentialRequestsReuseOneClientAndOneBackendConnection() throws Exception {
        try (ScriptedBackend backend = ScriptedBackend.answering("ok");
                TestProxy proxy = TestProxy.config(dir).backends(backend.port()).start();
                RawClient client = new RawClient(proxy.port())) {
            for (int i = 0; i < 50; i++) {
                assertThat(client.get("/n/" + i).text()).isEqualTo("ok");
            }

            assertThat(backend.requests()).hasSize(50);
            assertThat(backend.connections()).isEqualTo(1);
        }
    }

    @Test
    void aClientThatHangsUpMidRequestIsLoggedAsAbortedAndTheBackendConnectionIsDropped() throws Exception {
        try (ScriptedBackend slow = ScriptedBackend.start(ScriptedBackend.hang());
                TestProxy proxy = TestProxy.config(dir).backends(slow.port()).start()) {
            RawClient client = new RawClient(proxy.port());
            client.writeText("GET /abandoned HTTP/1.1\r\nHost: localhost\r\n\r\n");
            Await.until("the backend to receive the request", () -> !slow.requests().isEmpty());
            client.close();

            proxy.awaitEvent("request", e -> e.get("decision").asText().equals("client_aborted"));
        }
    }

    @Test
    void aConnectionTheBackendClosedWhileIdleDoesNotFailTheNextPost() throws Exception {
        try (ScriptedBackend backend = ScriptedBackend.start(ScriptedBackend.answerThenCloseWhenIdle("ok"));
                TestProxy proxy = TestProxy.config(dir).backends(backend.port()).start();
                RawClient client = new RawClient(proxy.port())) {
            for (int round = 0; round < 5; round++) {
                assertThat(client.send("POST", "/order", "x=1".getBytes(StandardCharsets.UTF_8)).status()).isEqualTo(200);
                Thread.sleep(250); // let the backend's idle close happen; the assertion is that the proxy copes with it
            }

            assertThat(proxy.events("backend_failure")).isEmpty();
        }
    }

    @Test
    void aBackendFiveHundredIsRelayedAndDoesNotCountAsAFailureByDefault() throws Exception {
        try (ScriptedBackend backend = ScriptedBackend.start(ScriptedBackend.answer(500, "boom"));
                TestProxy proxy = TestProxy.config(dir).backends(backend.port()).start();
                RawClient client = new RawClient(proxy.port())) {
            for (int i = 0; i < 4; i++) {
                assertThat(client.get("/").status()).isEqualTo(500);
            }

            assertThat(proxy.events("backend_failure")).isEmpty();
            assertThat(proxy.events("backend_ejected")).isEmpty();
        }
    }
}
