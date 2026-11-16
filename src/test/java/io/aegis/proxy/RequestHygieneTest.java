package io.aegis.proxy;

import static org.assertj.core.api.Assertions.assertThat;

import com.fasterxml.jackson.databind.JsonNode;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** Malformed and hostile requests, and what the backend is allowed to see of a good one. */
class RequestHygieneTest {

    @TempDir
    Path dir;

    private TestProxy.Config config(ScriptedBackend backend) {
        return TestProxy.config(dir).backends(backend.port());
    }

    @Test
    void conflictingContentLengthAndTransferEncodingOverARawSocketGets400() throws Exception {
        try (ScriptedBackend backend = ScriptedBackend.answering("hello");
                TestProxy proxy = config(backend).start();
                RawClient client = new RawClient(proxy.port())) {
            client.writeText("POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 4\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n");
            RawClient.Response response = client.readResponse(false);

            assertThat(response.status()).isEqualTo(400);
            assertThat(response.text()).contains("Incident ID: " + response.header("X-Request-Id"));
            assertThat(backend.requests()).isEmpty();
        }
    }

    @Test
    void anOversizeBodyGets413WithAnIncidentIdAndTheConnectionCloses() throws Exception {
        try (ScriptedBackend backend = ScriptedBackend.answering("hello");
                TestProxy proxy = config(backend).listener("max_body_bytes: 1KB\n").start();
                RawClient client = new RawClient(proxy.port())) {
            RawClient.Response response = client.send("POST", "/", new byte[4096]);

            assertThat(response.status()).isEqualTo(413);
            assertThat(response.text()).contains("Incident ID: " + response.header("X-Request-Id"));
            assertThat(client.isClosedByServer()).isTrue();
            assertThat(backend.requests()).isEmpty();
            proxy.requestEvent(response.header("X-Request-Id"));
        }
    }

    @Test
    void connectIsRefusedWith405AndUpgradeWith501() throws Exception {
        try (ScriptedBackend backend = ScriptedBackend.answering("hello");
                TestProxy proxy = config(backend).start();
                RawClient client = new RawClient(proxy.port())) {
            client.writeText("CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n");
            assertThat(client.readResponse(false).status()).isEqualTo(405);

            RawClient.Response upgrade = client.get("/chat", "Connection: Upgrade", "Upgrade: websocket");
            assertThat(upgrade.status()).isEqualTo(501);
            assertThat(backend.requests()).isEmpty();
        }
    }

    @Test
    void anOverlongRequestLineGets414AndAnOversizeHeaderBlockGets431() throws Exception {
        try (ScriptedBackend backend = ScriptedBackend.answering("hello");
                TestProxy proxy = config(backend).start()) {
            try (RawClient client = new RawClient(proxy.port())) {
                assertThat(client.get("/" + "a".repeat(9000)).status()).isEqualTo(414);
            }
            try (RawClient client = new RawClient(proxy.port())) {
                assertThat(client.get("/", "X-Big: " + "b".repeat(20_000)).status()).isEqualTo(431);
            }
            assertThat(backend.requests()).isEmpty();
        }
    }

    @Test
    void aTargetWithBytesAboveAsciiIsRefusedInsteadOfReachingTheBackendAsDifferentBytes() throws Exception {
        try (ScriptedBackend backend = ScriptedBackend.answering("hello");
                TestProxy proxy = config(backend).start();
                RawClient client = new RawClient(proxy.port())) {
            RawClient.Response response = client.get("/café");

            assertThat(response.status()).isEqualTo(400);
            assertThat(backend.requests()).isEmpty();
        }
    }

    @Test
    void aHeaderValueWithBytesAboveAsciiReachesTheBackendByteForByte() throws Exception {
        try (ScriptedBackend backend = ScriptedBackend.answering("hello");
                TestProxy proxy = config(backend).start();
                RawClient client = new RawClient(proxy.port())) {
            RawClient.Response response = client.get("/", "X-Name: café");

            assertThat(response.status()).isEqualTo(200);
            byte[] sent = backend.requests().get(0).headBytes();
            String head = new String(sent, StandardCharsets.ISO_8859_1);
            assertThat(head).contains("X-Name: café\r\n");
        }
    }

    @Test
    void aSlowRequestHeadGets408() throws Exception {
        try (ScriptedBackend backend = ScriptedBackend.answering("hello");
                TestProxy proxy = config(backend).listener("header_timeout: 300ms\n").start();
                RawClient client = new RawClient(proxy.port())) {
            client.writeText("GET / HT");
            RawClient.Response response = client.readResponse(false);

            assertThat(response.status()).isEqualTo(408);
            assertThat(client.isClosedByServer()).isTrue();
        }
    }

    @Test
    void anIdleKeepAliveConnectionClosesAfterTheIdleTimeout() throws Exception {
        try (ScriptedBackend backend = ScriptedBackend.answering("hello");
                TestProxy proxy = config(backend).listener("idle_timeout: 300ms\n").start();
                RawClient client = new RawClient(proxy.port())) {
            assertThat(client.get("/").status()).isEqualTo(200);

            assertThat(client.isClosedByServer()).isTrue();
        }
    }

    @Test
    void hopByHopHeadersAreStrippedAndForwardingHeadersReachTheBackend() throws Exception {
        List<String> backendHeaders = List.of("Connection: X-Hop", "X-Hop: private", "Keep-Alive: timeout=1",
                "Proxy-Authenticate: Basic", "X-Custom: kept");
        try (ScriptedBackend backend = ScriptedBackend.start(ScriptedBackend.answerWith(200, backendHeaders, "hello"));
                TestProxy proxy = config(backend).start();
                RawClient client = new RawClient(proxy.port())) {
            RawClient.Response response = client.get("/path?x=1",
                    "Host: app.example.com", "X-Forwarded-For: 198.51.100.7",
                    "Connection: keep-alive, X-Secret", "X-Secret: s", "Keep-Alive: timeout=5", "TE: trailers",
                    "Proxy-Authorization: Basic Zm9v", "X-Keep: yes");

            ScriptedBackend.Request seen = backend.requests().get(0);
            assertThat(seen.header("Host")).isEqualTo("app.example.com");
            assertThat(seen.header("X-Forwarded-For")).isEqualTo("198.51.100.7, 127.0.0.1");
            assertThat(seen.header("X-Forwarded-Proto")).isEqualTo("http");
            assertThat(seen.header("X-Request-Id")).isEqualTo(response.header("X-Request-Id")).isNotBlank();
            assertThat(seen.header("X-Keep")).isEqualTo("yes");
            for (String stripped : List.of("X-Secret", "Keep-Alive", "TE", "Proxy-Authorization", "Connection")) {
                assertThat(seen.header(stripped)).as(stripped).isNull();
            }
            assertThat(response.header("X-Custom")).isEqualTo("kept");
            for (String stripped : List.of("X-Hop", "Keep-Alive", "Proxy-Authenticate", "Connection")) {
                assertThat(response.header(stripped)).as(stripped).isNull();
            }
        }
    }

    @Test
    void aChunkedRequestBodyReachesTheBackendWithAnExactContentLength() throws Exception {
        try (ScriptedBackend backend = ScriptedBackend.answering("hello");
                TestProxy proxy = config(backend).start();
                RawClient client = new RawClient(proxy.port())) {
            client.writeText("POST /up HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n"
                    + "5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n");
            RawClient.Response response = client.readResponse(false);

            assertThat(response.status()).isEqualTo(200);
            ScriptedBackend.Request seen = backend.requests().get(0);
            assertThat(seen.header("Content-Length")).isEqualTo("11");
            assertThat(seen.header("Transfer-Encoding")).isNull();
            assertThat(new String(seen.body(), StandardCharsets.US_ASCII)).isEqualTo("hello world");
        }
    }

    @Test
    void pipelinedRequestsAreAnsweredInOrder() throws Exception {
        try (ScriptedBackend backend = ScriptedBackend.start((request, socket) -> ScriptedBackend
                .answer(200, request.head().split(" ")[1]).respond(request, socket));
                TestProxy proxy = config(backend).start();
                RawClient client = new RawClient(proxy.port())) {
            client.writeText("GET /one HTTP/1.1\r\nHost: x\r\n\r\nGET /two HTTP/1.1\r\nHost: x\r\n\r\n"
                    + "GET /three HTTP/1.1\r\nHost: x\r\n\r\n");

            assertThat(client.readResponse(false).text()).isEqualTo("/one");
            assertThat(client.readResponse(false).text()).isEqualTo("/two");
            assertThat(client.readResponse(false).text()).isEqualTo("/three");
        }
    }

    @Test
    void aHeadRequestGetsHeadersWithoutABody() throws Exception {
        ScriptedBackend.Behavior headAware = (request, socket) -> {
            boolean head = request.head().startsWith("HEAD");
            socket.getOutputStream().write(("HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n" + (head ? "" : "hello"))
                    .getBytes(StandardCharsets.US_ASCII));
        };
        try (ScriptedBackend backend = ScriptedBackend.start(headAware);
                TestProxy proxy = config(backend).start();
                RawClient client = new RawClient(proxy.port())) {
            RawClient.Response head = client.send("HEAD", "/", null);
            RawClient.Response next = client.get("/");

            assertThat(head.status()).isEqualTo(200);
            assertThat(head.header("Content-Length")).isEqualTo("5");
            assertThat(head.body()).isEmpty();
            assertThat(next.text()).isEqualTo("hello");
        }
    }

    @Test
    void aLargeResponseStreamsThroughIntact() throws Exception {
        int size = 12 * 1024 * 1024;
        try (ScriptedBackend backend = ScriptedBackend.start(ScriptedBackend.streamBody(size));
                TestProxy proxy = config(backend).start();
                RawClient client = new RawClient(proxy.port(), 30_000)) {
            RawClient.Response response = client.get("/big");

            byte[] expected = MessageDigest.getInstance("SHA-256").digest(ScriptedBackend.pattern(size));
            byte[] actual = MessageDigest.getInstance("SHA-256").digest(response.body());
            assertThat(actual).isEqualTo(expected);
            JsonNode event = proxy.requestEvent(response.header("X-Request-Id"));
            assertThat(event.get("response_bytes").asLong()).isEqualTo(size);
        }
    }
}
