package io.aegis.proxy;

import static org.assertj.core.api.Assertions.assertThat;

import com.fasterxml.jackson.databind.JsonNode;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.stream.StreamSupport;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** What the WAF stage blocks, passes, and records, seen through real requests. */
class WafEndToEndTest {

    @TempDir
    Path dir;

    @Test
    void anAttackGets403WhoseBodyAndHeadersCarryTheIncidentIdAndNoRuleDetail() throws Exception {
        try (ScriptedBackend backend = ScriptedBackend.answering("hello");
                TestProxy proxy = TestProxy.config(dir).backends(backend.port()).start();
                RawClient client = new RawClient(proxy.port())) {
            RawClient.Response response = client.get("/search?q=1%20union%20select%20password");

            String id = response.header("X-Request-Id");
            assertThat(response.status()).isEqualTo(403);
            assertThat(id).hasSizeGreaterThanOrEqualTo(16);
            assertThat(response.text()).contains("Incident ID: " + id);
            String everythingSent = response.text() + response.headers().stream().map(Arrays::toString).toList();
            assertThat(everythingSent).doesNotContain("1000001", "SQL", "union", "test", "score", "127.0.0.1");
            assertThat(backend.requests()).isEmpty();
            JsonNode event = proxy.requestEvent(id);
            assertThat(event.get("decision").asText()).isEqualTo("waf_blocked");
            assertThat(event.get("waf_score").asInt()).isEqualTo(5);
            assertThat(event.get("waf_hits").get(0).get("sid").asInt()).isEqualTo(1000001);
            assertThat(event.get("waf_hits").get(0).get("rule_set").asText()).isEqualTo("test");
        }
    }

    @Test
    void aScannerUserAgentAlonePassesButScannerPlusQuoteCommentBlocks() throws Exception {
        try (ScriptedBackend backend = ScriptedBackend.answering("hello");
                TestProxy proxy = TestProxy.config(dir).backends(backend.port()).start();
                RawClient client = new RawClient(proxy.port())) {
            RawClient.Response scannerOnly = client.get("/", "User-Agent: Nikto/2.1");
            RawClient.Response quoteOnly = client.get("/?a=1'--");
            RawClient.Response both = client.get("/?a=1'--", "User-Agent: Nikto/2.1");

            assertThat(scannerOnly.status()).isEqualTo(200);
            assertThat(quoteOnly.status()).isEqualTo(200);
            assertThat(both.status()).isEqualTo(403);
            JsonNode event = proxy.requestEvent(both.header("X-Request-Id"));
            assertThat(event.get("waf_score").asInt()).isEqualTo(6);
        }
    }

    @Test
    void aMonitorModeHitPassesAndIsLoggedAndCounted() throws Exception {
        try (ScriptedBackend backend = ScriptedBackend.answering("hello");
                TestProxy proxy = TestProxy.config(dir).backends(backend.port()).start();
                RawClient client = new RawClient(proxy.port())) {
            RawClient.Response response = client.get("/?monitored=1");

            assertThat(response.status()).isEqualTo(200);
            JsonNode event = proxy.requestEvent(response.header("X-Request-Id"));
            assertThat(event.get("decision").asText()).isEqualTo("allowed");
            JsonNode hit = event.get("waf_hits").get(0);
            assertThat(hit.get("sid").asInt()).isEqualTo(2000001);
            assertThat(hit.get("mode").asText()).isEqualTo("monitor");
            assertThat(hit.get("score").asInt()).isZero();
            assertThat(proxy.admin("/metrics")).containsPattern("aegis_waf_rule_hits_total\\{[^}]*sid=\"2000001\"[^}]*\\} 1.0");
        }
    }

    @Test
    void aBodyOverTheScanLimitBlocksUnderStrictAndPassesWithTheGapLoggedUnderBalanced() throws Exception {
        byte[] body = ("a".repeat(2000) + "attackmarker").getBytes(StandardCharsets.US_ASCII);
        String route = "waf:\n  body_scan_limit: 1KB\n";
        try (ScriptedBackend backend = ScriptedBackend.answering("hello");
                TestProxy strict = TestProxy.config(dir.resolve("strict")).profile("strict").backends(backend.port())
                        .route(route).start();
                TestProxy balanced = TestProxy.config(dir.resolve("balanced")).backends(backend.port())
                        .route(route).start()) {
            RawClient.Response blocked;
            try (RawClient client = new RawClient(strict.port())) {
                blocked = client.send("POST", "/upload", body);
            }
            RawClient.Response passed;
            try (RawClient client = new RawClient(balanced.port())) {
                passed = client.send("POST", "/upload", body);
            }

            assertThat(blocked.status()).isEqualTo(403);
            JsonNode blockedEvent = strict.requestEvent(blocked.header("X-Request-Id"));
            assertThat(blockedEvent.get("body").get("length").asInt()).isEqualTo(body.length);
            assertThat(blockedEvent.get("body").get("sha256").asText()).hasSize(64);
            assertThat(passed.status()).isEqualTo(200);
            JsonNode passedEvent = balanced.requestEvent(passed.header("X-Request-Id"));
            assertThat(StreamSupport.stream(passedEvent.get("inspection_gaps").spliterator(), false).map(JsonNode::asText))
                    .containsExactly("body_over_scan_limit");
            assertThat(balanced.admin("/metrics")).containsPattern("aegis_inspection_gaps_total\\{[^}]*gap=\"body_over_scan_limit\"");
        }
    }

    @Test
    void anAttackInsideTheScannedBodyBlocks() throws Exception {
        try (ScriptedBackend backend = ScriptedBackend.answering("hello");
                TestProxy proxy = TestProxy.config(dir).backends(backend.port()).start();
                RawClient client = new RawClient(proxy.port())) {
            RawClient.Response response = client.send("POST", "/", "x=attackmarker".getBytes(StandardCharsets.US_ASCII));

            assertThat(response.status()).isEqualTo(403);
        }
    }

    @Test
    void theLogHoldsOneRequestEventWithARedactedQueryValueAndTheDecision() throws Exception {
        try (ScriptedBackend backend = ScriptedBackend.answering("hello");
                TestProxy proxy = TestProxy.config(dir).backends(backend.port()).start();
                RawClient client = new RawClient(proxy.port())) {
            RawClient.Response response = client.get("/search?page=2&q=hunter2", "User-Agent: test-agent");

            JsonNode event = proxy.requestEvent(response.header("X-Request-Id"));
            assertThat(event.get("target").asText()).isEqualTo("/search?page=2&q=[redacted]");
            assertThat(event.get("decision").asText()).isEqualTo("allowed");
            assertThat(event.get("status").asInt()).isEqualTo(200);
            assertThat(event.get("method").asText()).isEqualTo("GET");
            assertThat(event.get("route").asText()).isEqualTo("web");
            assertThat(event.get("client_ip").asText()).isEqualTo("127.0.0.1");
            assertThat(event.get("backend").asText()).isEqualTo("127.0.0.1:" + backend.port());
            assertThat(event.get("response_bytes").asInt()).isEqualTo(5);
            assertThat(event.has("total_ms")).isTrue();
            assertThat(event.toString()).doesNotContain("hunter2");
        }
    }
}
