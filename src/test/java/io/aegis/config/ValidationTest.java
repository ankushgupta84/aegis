package io.aegis.config;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import io.aegis.policy.AegisConfig;
import io.aegis.policy.BackendAddress;
import io.aegis.policy.TlsMode;
import java.util.Optional;
import org.junit.jupiter.api.Test;

class ValidationTest {

    @Test
    void theMinimalConfigurationTakesEveryDocumentedDefault() {
        AegisConfig config = ConfigLoader.parse(TestYaml.MINIMAL);
        var route = config.routes().get(0);
        assertThat(config.listener().port()).isEqualTo(8443);
        assertThat(config.admin().bindAddress()).isEqualTo("127.0.0.1");
        assertThat(route.host()).isEqualTo("*");
        assertThat(route.pathPrefix()).isEqualTo("/");
        assertThat(route.upstream().health().failuresToEject()).isEqualTo(3);
        assertThat(config.firewall().rateLimit().enabled()).isTrue();
        assertThat(config.ruleSets()).isEmpty();
    }

    @Test
    void theExceptionMessageListsEveryProblemNumbered() {
        assertThatThrownBy(() -> ConfigLoader.parse(TestYaml.route("host: \"a b\"\nconnect_timeout: soon")))
                .isInstanceOf(ConfigException.class)
                .hasMessageStartingWith("The configuration has 2 problems:\n  1. routes[0].host: ")
                .hasMessageContaining("\n  2. routes[0].connect_timeout: 'soon' is not a duration.");
    }

    @Test
    void severalProblemsInDifferentPlacesAreReportedTogether() {
        String yaml = """
                profile: relaxed
                listener:
                  port: 70000
                  bakends: []
                routes:
                  - name: web
                    backends: [localhost]
                """;
        assertThat(TestYaml.problemsOf(yaml)).containsExactly(
                "profile: 'relaxed' is not one of: strict, balanced, easy.",
                "listener.port: '70000' is not a whole number from 0 to 65535.",
                "listener.tls is true but there is no 'tls' entry to say which certificate to present. "
                        + "Add a tls entry with a hostname and a certificate, or set listener.tls to false.",
                "routes[0].backends[0]: 'localhost' is not a backend address. "
                        + "Write host:port, e.g. 10.0.0.5:8080 or [::1]:8080.",
                "Unknown key 'bakends' under listener. Valid keys here: bind, drain_timeout, header_timeout, "
                        + "idle_timeout, max_body_bytes, max_header_bytes, port, tls.");
    }

    @Test
    void anUnknownKeySuggestsTheClosestValidKey() {
        assertThat(TestYaml.problemsOf(TestYaml.route("bakends: [127.0.0.1:9002]")))
                .containsExactly("Unknown key 'bakends' under routes[0]. Did you mean 'backends'?");
    }

    @Test
    void anUnknownKeyAtTheTopLevelIsReported() {
        assertThat(TestYaml.problemsOf(TestYaml.plus("lisener: {}")))
                .containsExactly("Unknown key 'lisener' at the top level. Did you mean 'listener'?");
    }

    @Test
    void anUnknownKeyWithNothingCloseListsTheValidOnes() {
        assertThat(TestYaml.problemsOf(TestYaml.plus("admin:\n  colour: red")))
                .containsExactly("Unknown key 'colour' under admin. Valid keys here: bind, enabled, port.");
    }

    @Test
    void aWrongTypeNamesTheKeyAndWhatWasFound() {
        assertThat(TestYaml.problemsOf(TestYaml.plus("admin:\n  enabled: \"yes\"")))
                .containsExactly("admin.enabled: 'yes' is not true or false. Write true or false.");
    }

    @Test
    void aSectionThatIsNotAMappingIsAProblem() {
        assertThat(TestYaml.problemsOf(TestYaml.plus("admin: enabled")))
                .containsExactly("admin must be a mapping of settings, but found 'enabled'.");
    }

    @Test
    void aListThatIsNotAListIsAProblem() {
        assertThat(TestYaml.problemsOf(TestYaml.plus("firewall:\n  deny: 10.0.0.0/8")))
                .containsExactly("firewall.deny must be a list, e.g. [a, b], but found '10.0.0.0/8'.");
    }

    @Test
    void theProfileIsRequired() {
        assertThat(TestYaml.problemsOf(TestYaml.MINIMAL.replace("profile: balanced\n", "")))
                .containsExactly("profile is required but missing.");
    }

    @Test
    void atLeastOneRouteIsRequired() {
        assertThat(TestYaml.problemsOf(TestYaml.withoutRoutes("")))
                .containsExactly("routes is required: add at least one route with a name and backends.");
    }

    @Test
    void aRouteNeedsAtLeastOneBackend() {
        assertThat(TestYaml.problemsOf(TestYaml.MINIMAL.replace("[127.0.0.1:9001]", "[]")))
                .containsExactly("routes[0].backends needs at least one entry.");
    }

    @Test
    void routeNamesMustBeUnique() {
        assertThat(TestYaml.problemsOf(TestYaml.MINIMAL + "  - name: web\n    backends: [127.0.0.1:9002]\n"))
                .containsExactly("routes[1].name 'web' is already used by routes[0]. Each entry needs its own name.");
    }

    @Test
    void aPathPrefixMustStartWithASlash() {
        assertThat(TestYaml.problemsOf(TestYaml.route("path_prefix: api")))
                .containsExactly("routes[0].path_prefix: 'api' is not a path prefix. It must start with /, e.g. /api.");
    }

    @Test
    void backendPortsRunFromOneToSixtyFiveThousandFiveHundredThirtyFive() {
        assertThat(TestYaml.problemsOf(TestYaml.MINIMAL.replace("127.0.0.1:9001", "127.0.0.1:0")))
                .containsExactly("routes[0].backends[0]: '127.0.0.1:0' has no valid port. Use a number from 1 to 65535.");
        assertThat(TestYaml.problemsOf(TestYaml.MINIMAL.replace("127.0.0.1:9001", "127.0.0.1:65536")))
                .hasSize(1);
    }

    @Test
    void aBackendMayBeAnIpv6AddressInBrackets() {
        AegisConfig config = ConfigLoader.parse(TestYaml.MINIMAL.replace("127.0.0.1:9001", "\"[::1]:9001\""));
        assertThat(config.routes().get(0).upstream().backends()).containsExactly(new BackendAddress("::1", 9001));
    }

    @Test
    void theListenerAndAdminMayBindAnEphemeralPort() {
        AegisConfig config = ConfigLoader.parse(TestYaml.plus("admin:\n  port: 0").replace("tls: false", "tls: false\n  port: 0"));
        assertThat(config.listener().port()).isZero();
        assertThat(config.admin().port()).isZero();
    }

    @Test
    void aTlsListenerNeedsATlsEntry() {
        assertThat(TestYaml.problemsOf(TestYaml.MINIMAL.replace("tls: false", "tls: true")))
                .containsExactly("listener.tls is true but there is no 'tls' entry to say which certificate to present. "
                        + "Add a tls entry with a hostname and a certificate, or set listener.tls to false.");
    }

    @Test
    void aTlsEntryKeepsItsProviderSettingsAsStrings() {
        AegisConfig config = ConfigLoader.parse(TestYaml.MINIMAL.replace("tls: false", "tls: true") + """
                tls:
                  - hostname: WWW.Example.com
                    mode: transparent
                    certificate:
                      type: aws_acm
                      arn: arn:aws:acm:eu-west-1:1:certificate/x
                      refresh_hours: 12
                """);
        var host = config.tlsHosts().get(0);
        assertThat(host.hostname()).isEqualTo("www.example.com");
        assertThat(host.mode()).isEqualTo(TlsMode.TRANSPARENT);
        assertThat(host.providerType()).isEqualTo("aws_acm");
        assertThat(host.providerSettings())
                .containsEntry("arn", "arn:aws:acm:eu-west-1:1:certificate/x")
                .containsEntry("refresh_hours", "12")
                .doesNotContainKey("type");
    }

    @Test
    void aTlsEntryNeedsACertificateType() {
        assertThat(TestYaml.problemsOf(TestYaml.plus("tls:\n  - hostname: a.example.com\n")))
                .containsExactly("tls[0].certificate.type is required but missing.");
    }

    @Test
    void aPinnedFingerprintMustBeSixtyFourHexDigitsAndColonsAreStripped() {
        String fingerprint = "AB:".repeat(31) + "AB";
        AegisConfig config = ConfigLoader.parse(TestYaml.route(
                "upstream_tls:\n  enabled: true\n  pinned_sha256: \"" + fingerprint + "\""));
        assertThat(config.routes().get(0).upstream().tls().pinnedSha256()).contains("ab".repeat(32));
        assertThat(TestYaml.problemsOf(TestYaml.route("upstream_tls:\n  enabled: true\n  pinned_sha256: abc")))
                .containsExactly("routes[0].upstream_tls.pinned_sha256: 'abc' is not a SHA-256 fingerprint. "
                        + "Write 64 hex digits; colons between bytes are allowed.");
    }

    @Test
    void upstreamTlsSettingsWithoutEnablingTlsWouldBeIgnoredSoTheyAreAProblem() {
        assertThat(TestYaml.problemsOf(TestYaml.route("upstream_tls:\n  trusted_ca: ca.pem")))
                .containsExactly("routes[0].upstream_tls.enabled is false, so trusted_ca and pinned_sha256 "
                        + "would be ignored. Set enabled: true or remove them.");
    }

    @Test
    void aTrustedCaPathStaysRelative() {
        var tls = ConfigLoader.parse(TestYaml.route("upstream_tls:\n  enabled: true\n  trusted_ca: certs/ca.pem"))
                .routes().get(0).upstream().tls();
        assertThat(tls.trustedCa()).map(Object::toString).isEqualTo(Optional.of("certs/ca.pem"));
    }

    @Test
    void rateLimitNumbersMustBePositiveAndPrefixesInRange() {
        assertThat(TestYaml.problemsOf(TestYaml.plus("""
                firewall:
                  rate_limit:
                    requests_per_second: 0
                    burst: -1
                    ipv4_prefix: 33
                    ipv6_prefix: 129
                    max_tracked_clients: 0
                """))).containsExactly(
                "firewall.rate_limit.requests_per_second: '0' is not a positive number, e.g. 100 or 2.5.",
                "firewall.rate_limit.burst: '-1' is not a whole number from 1 to 2147483647.",
                "firewall.rate_limit.ipv4_prefix: '33' is not a whole number from 0 to 32.",
                "firewall.rate_limit.ipv6_prefix: '129' is not a whole number from 0 to 128.",
                "firewall.rate_limit.max_tracked_clients: '0' is not a whole number from 1 to 2147483647.");
    }

    @Test
    void aBadCidrInTheFirewallNamesTheEntry() {
        assertThat(TestYaml.problemsOf(TestYaml.plus("firewall:\n  deny: [10.0.0.0/8, 10.0.0.0/40]")))
                .containsExactly("firewall.deny[1]: '10.0.0.0/40' is not an IP address or CIDR block. "
                        + "Valid examples: 192.0.2.7, 10.0.0.0/8, 2001:db8::/32.");
    }

    @Test
    void duplicateKeysAreRefusedBecauseOneWouldSilentlyWin() {
        assertThat(TestYaml.problemsOf(TestYaml.plus("admin:\n  port: 1\n  port: 2")))
                .singleElement().asString().startsWith("The file is not valid YAML (line ");
    }

    @Test
    void brokenYamlAndEmptyFilesAreProblemsNotCrashes() {
        assertThat(TestYaml.problemsOf("profile: [")).singleElement().asString().startsWith("The file is not valid YAML");
        assertThat(TestYaml.problemsOf("# nothing here\n")).singleElement().asString().startsWith("The file is empty.");
        assertThat(TestYaml.problemsOf("- a\n- b\n"))
                .contains("The top level of the file must be a mapping of settings, but found '[\"a\",\"b\"]'.");
    }

    @Test
    void aMissingFileIsAProblem() {
        assertThatThrownBy(() -> ConfigLoader.load(java.nio.file.Path.of("no/such/aegis.yaml")))
                .isInstanceOf(ConfigException.class)
                .hasMessageContaining("Cannot read the configuration file no/such/aegis.yaml");
    }
}
