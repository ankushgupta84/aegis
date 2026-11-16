package io.aegis.config;

import static org.assertj.core.api.Assertions.assertThat;

import io.aegis.net.Cidr;
import io.aegis.policy.AegisConfig;
import io.aegis.policy.Exemption;
import io.aegis.policy.Skip;
import org.junit.jupiter.api.Test;

class ExemptionTest {
    private static final String RULE_SETS = """
            rule_sets:
              - name: aegis-core
                file: rules/core.rules
                mode: block
            """;

    private static final String SCANNER = """
            exemptions:
              - name: scanner
                sources: [10.20.0.5, 10.30.0.0/16]
                skip: [rate_limit, waf, "rule_set:aegis-core", "sid:942100"]
                reason: Weekly scan
                owner: sec@example.com
            """;

    @Test
    void anExemptionIsReadWithEverythingItNames() {
        AegisConfig config = ConfigLoader.parse(TestYaml.plus(RULE_SETS + SCANNER));
        Exemption exemption = config.firewall().exemptions().get(0);
        assertThat(exemption.sources()).containsExactly(Cidr.parse("10.20.0.5"), Cidr.parse("10.30.0.0/16"));
        assertThat(exemption.skips()).containsExactly(
                Skip.rateLimit(), Skip.waf(), Skip.ruleSet("aegis-core"), Skip.sid(942100));
    }

    @Test
    void theWholeExemptionGoesToTheFirewallAndToEveryRoute() {
        String twoRoutes = TestYaml.MINIMAL + "  - name: api\n    backends: [127.0.0.1:9002]\n";
        AegisConfig config = ConfigLoader.parse(twoRoutes + RULE_SETS + SCANNER);
        Exemption exemption = config.firewall().exemptions().get(0);
        assertThat(config.routes()).hasSize(2).allSatisfy(route ->
                assertThat(route.waf().exemptions()).containsExactly(exemption));
    }

    @Test
    void anExemptionWithoutAReasonMustBeExplained() {
        assertThat(TestYaml.problemsOf(TestYaml.plus(SCANNER.replace("    reason: Weekly scan\n", ""))))
                .contains("exemptions[0].reason is required but missing. "
                        + "Loosening protection must be explained: say why this exemption exists.");
    }

    @Test
    void anExemptionWithoutAnOwnerMustBeOwned() {
        assertThat(TestYaml.problemsOf(TestYaml.plus(RULE_SETS + SCANNER.replace("    owner: sec@example.com\n", ""))))
                .containsExactly("exemptions[0].owner is required but missing. "
                        + "Loosening protection must be owned: name the team or person who answers for it.");
    }

    @Test
    void anExemptionWithoutSourcesOrSkipsIsAProblem() {
        assertThat(TestYaml.problemsOf(TestYaml.plus("""
                exemptions:
                  - name: empty
                    sources: []
                    reason: r
                    owner: o
                """)))
                .containsExactly(
                        "exemptions[0].sources needs at least one entry.",
                        "exemptions[0].skip is required but missing.");
    }

    @Test
    void skippingAnUndeclaredRuleSetIsAProblem() {
        assertThat(TestYaml.problemsOf(TestYaml.plus(RULE_SETS + SCANNER.replace("aegis-core\"", "aegis-cor\""))))
                .containsExactly("exemptions[0].skip: 'aegis-cor' is not a declared rule set. "
                        + "Declared rule sets: aegis-core.");
    }

    @Test
    void anUnknownKindOfSkipIsAProblem() {
        assertThat(TestYaml.problemsOf(TestYaml.plus(SCANNER.replace("[rate_limit, waf,", "[everything,"))))
                .anyMatch(problem -> problem.startsWith("exemptions[0].skip[0]: 'everything' is not something an "
                        + "exemption can skip. Write rate_limit, waf, rule_set:<name>, or sid:<number>."));
    }

    @Test
    void aSourceThatIsAHostNameIsAProblem() {
        assertThat(TestYaml.problemsOf(TestYaml.plus(RULE_SETS + SCANNER.replace("10.20.0.5", "scanner.example.com"))))
                .containsExactly("exemptions[0].sources[0]: 'scanner.example.com' is not an IP address or CIDR block. "
                        + "Valid examples: 192.0.2.7, 10.0.0.0/8, 2001:db8::/32.");
    }
}
