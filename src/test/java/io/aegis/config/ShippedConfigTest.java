package io.aegis.config;

import static org.assertj.core.api.Assertions.assertThat;

import io.aegis.net.Cidr;
import io.aegis.policy.AegisConfig;
import io.aegis.policy.BackendAddress;
import io.aegis.policy.FailAction;
import io.aegis.policy.RoutePolicy;
import io.aegis.policy.RuleMode;
import io.aegis.policy.Skip;
import io.aegis.policy.TlsMode;
import java.nio.file.Path;
import java.time.Duration;
import java.util.Map;
import java.util.Optional;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

class ShippedConfigTest {
    private static AegisConfig config;

    @BeforeAll
    static void loadTheExampleFromTheRepositoryRoot() {
        config = ConfigLoader.load(Path.of("config/aegis.yaml"));
    }

    @Test
    void theExampleStartsFromTheBalancedProfile() {
        assertThat(config.profile()).isEqualTo("balanced");
    }

    @Test
    void theListenerMatchesTheExample() {
        var listener = config.listener();
        assertThat(listener.bindAddress()).isEqualTo("0.0.0.0");
        assertThat(listener.port()).isEqualTo(8443);
        assertThat(listener.tls()).isTrue();
        assertThat(listener.maxHeaderBytes()).isEqualTo(16 * 1024);
        assertThat(listener.maxBodyBytes()).isEqualTo(10 * 1024 * 1024);
        assertThat(listener.headerTimeout()).isEqualTo(Duration.ofSeconds(10));
        assertThat(listener.idleTimeout()).isEqualTo(Duration.ofSeconds(60));
        assertThat(listener.drainTimeout()).isEqualTo(Duration.ofSeconds(30));
    }

    @Test
    void theAdminEndpointStaysOnLocalhost() {
        assertThat(config.admin()).isEqualTo(new io.aegis.policy.Admin(true, "127.0.0.1", 9090));
    }

    @Test
    void theLogSettingsMatchTheExample() {
        var log = config.log();
        assertThat(log.directory()).isEqualTo(Path.of("logs"));
        assertThat(log.rotateAtBytes()).isEqualTo(100L * 1024 * 1024);
        assertThat(log.keepFiles()).isEqualTo(10);
        assertThat(log.loggedQueryParams()).containsExactly("page", "limit", "sort");
    }

    @Test
    void noProxyIsTrustedByDefault() {
        assertThat(config.clientIp().trustedProxies()).isEmpty();
    }

    @Test
    void theFirewallDeniesTheDocumentationBlockAndRateLimits() {
        var firewall = config.firewall();
        assertThat(firewall.allow()).isEmpty();
        assertThat(firewall.deny()).containsExactly(Cidr.parse("203.0.113.0/24"));
        assertThat(firewall.rateLimit().enabled()).isTrue();
        assertThat(firewall.rateLimit().requestsPerSecond()).isEqualTo(100.0);
        assertThat(firewall.rateLimit().burst()).isEqualTo(50);
        assertThat(firewall.rateLimit().ipv4PrefixBits()).isEqualTo(32);
        assertThat(firewall.rateLimit().ipv6PrefixBits()).isEqualTo(64);
        assertThat(firewall.rateLimit().maxTrackedClients()).isEqualTo(100_000);
    }

    @Test
    void theCoreRuleSetIsDeclaredInBlockMode() {
        assertThat(config.ruleSets()).singleElement().satisfies(source -> {
            assertThat(source.name()).isEqualTo("aegis-core");
            assertThat(source.file()).isEqualTo(Path.of("config/rules/aegis-core.rules"));
            assertThat(source.defaultMode()).isEqualTo(RuleMode.BLOCK);
        });
    }

    @Test
    void theLocalhostCertificateIsWatchedOnDisk() {
        assertThat(config.tlsHosts()).singleElement().satisfies(host -> {
            assertThat(host.hostname()).isEqualTo("localhost");
            assertThat(host.mode()).isEqualTo(TlsMode.REVERSE_PROXY);
            assertThat(host.providerType()).isEqualTo("file_watch");
            assertThat(host.providerSettings()).containsExactlyInAnyOrderEntriesOf(Map.of(
                    "cert_file", "config/certs/localhost.crt",
                    "key_file", "config/certs/localhost.key"));
        });
    }

    @Test
    void theDefaultRouteBalancesTwoBackends() {
        RoutePolicy route = config.routes().get(0);
        assertThat(config.routes()).hasSize(1);
        assertThat(route.name()).isEqualTo("default");
        assertThat(route.host()).isEqualTo("*");
        assertThat(route.pathPrefix()).isEqualTo("/");
        assertThat(route.upstream().backends())
                .containsExactly(new BackendAddress("127.0.0.1", 9001), new BackendAddress("127.0.0.1", 9002));
        assertThat(route.upstream().health().failuresToEject()).isEqualTo(3);
        assertThat(route.upstream().health().ejectionTime()).isEqualTo(Duration.ofSeconds(5));
        assertThat(route.upstream().health().countServerErrors()).isFalse();
        assertThat(route.upstream().connectTimeout()).isEqualTo(Duration.ofSeconds(2));
        assertThat(route.upstream().responseTimeout()).isEqualTo(Duration.ofSeconds(30));
        assertThat(route.upstream().tls().enabled()).isFalse();
        assertThat(route.upstream().tls().trustedCa()).isEqualTo(Optional.empty());
    }

    @Test
    void theDefaultRouteUsesTheBalancedWafKnobs() {
        var knobs = config.routes().get(0).waf().knobs();
        assertThat(knobs.blockThreshold()).isEqualTo(5);
        assertThat(knobs.bodyScanLimitBytes()).isEqualTo(128 * 1024);
        assertThat(knobs.onBodyOverLimit()).isEqualTo(FailAction.PASS);
        assertThat(knobs.inspectionBudget()).isEqualTo(Duration.ofMillis(5));
        assertThat(knobs.onBudgetExceeded()).isEqualTo(FailAction.BLOCK);
        assertThat(knobs.onEngineError()).isEqualTo(FailAction.BLOCK);
    }

    @Test
    void theScannerExemptionReachesTheFirewallAndTheRouteWhole() {
        var exemption = config.firewall().exemptions().get(0);
        assertThat(exemption.name()).isEqualTo("internal-scanner");
        assertThat(exemption.sources()).containsExactly(Cidr.parse("10.20.0.5"));
        assertThat(exemption.skips()).containsExactly(Skip.rateLimit(), Skip.ruleSet("aegis-core"));
        assertThat(exemption.reason()).isEqualTo("Weekly authenticated vulnerability scan");
        assertThat(exemption.owner()).isEqualTo("security-team@example.com");
        assertThat(config.routes().get(0).waf().exemptions()).containsExactly(exemption);
    }

    @Test
    void theExplanationOfTheExampleLoadsToo() {
        assertThat(ConfigExplainer.explain(Path.of("config/aegis.yaml")))
                .contains("routes.default.waf.on_body_over_limit = pass   (profile balanced)")
                .contains("routes.default.waf.block_threshold = 5   (global waf)");
    }
}
