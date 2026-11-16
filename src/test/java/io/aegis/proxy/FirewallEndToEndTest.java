package io.aegis.proxy;

import static org.assertj.core.api.Assertions.assertThat;

import java.nio.file.Path;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** The IP access list and rate limit, with client addresses chosen through a trusted X-Forwarded-For. */
class FirewallEndToEndTest {

    @TempDir
    Path dir;

    private static String from(String address) {
        return "X-Forwarded-For: " + address;
    }

    @Test
    void aDenyListedClientGets403AndAnAllowListedOneIsServed() throws Exception {
        try (ScriptedBackend backend = ScriptedBackend.answering("hello");
                TestProxy proxy = TestProxy.config(dir).backends(backend.port())
                        .firewall("allow: [198.51.100.0/24]\ndeny: [198.51.100.66/32]\nrate_limit:\n  enabled: false\n")
                        .start();
                RawClient client = new RawClient(proxy.port())) {
            assertThat(client.get("/", from("198.51.100.7")).status()).isEqualTo(200);
            RawClient.Response denied = client.get("/", from("198.51.100.66"));
            RawClient.Response outsider = client.get("/", from("192.0.2.9"));

            assertThat(denied.status()).isEqualTo(403);
            assertThat(outsider.status()).isEqualTo(403);
            assertThat(denied.text()).contains(denied.header("X-Request-Id")).doesNotContain("198.51.100");
            assertThat(backend.requests()).hasSize(1);
            assertThat(proxy.requestEvent(denied.header("X-Request-Id")).get("decision").asText())
                    .isEqualTo("firewall_denied");
        }
    }

    @Test
    void exactlyBurstRequestsPassThenTheNextGets429AndAnExemptClientIsNotLimited() throws Exception {
        String limit = "rate_limit:\n  enabled: true\n  requests_per_second: 0.001\n  burst: 5\n";
        String exemption = "exemptions:\n  - name: scanner\n    sources: [10.20.0.5]\n    skip: [rate_limit]\n"
                + "    reason: weekly scan\n    owner: security@example.com\n";
        try (ScriptedBackend backend = ScriptedBackend.answering("hello");
                TestProxy proxy = TestProxy.config(dir).backends(backend.port()).firewall(limit).topLevel(exemption).start();
                RawClient client = new RawClient(proxy.port())) {
            int passed = 0;
            for (int i = 0; i < 5; i++) {
                passed += client.get("/", from("198.51.100.1")).status() == 200 ? 1 : 0;
            }
            RawClient.Response limited = client.get("/", from("198.51.100.1"));
            int exemptPassed = 0;
            for (int i = 0; i < 12; i++) {
                exemptPassed += client.get("/", from("10.20.0.5")).status() == 200 ? 1 : 0;
            }

            assertThat(passed).isEqualTo(5);
            assertThat(limited.status()).isEqualTo(429);
            assertThat(exemptPassed).isEqualTo(12);
            assertThat(proxy.requestEvent(limited.header("X-Request-Id")).get("decision").asText())
                    .isEqualTo("rate_limited");
        }
    }
}
