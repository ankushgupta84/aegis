package io.aegis.config;

import static org.assertj.core.api.Assertions.assertThat;

import io.aegis.policy.RuleMode;
import io.aegis.policy.WafPolicy;
import java.util.Map;
import org.junit.jupiter.api.Test;

class RuleModesTest {
    private static final String RULE_SETS = """
            rule_sets:
              - name: aegis-core
                file: rules/core.rules
                mode: block
              - name: et-open
                file: rules/et.rules
                mode: monitor
            """;

    private static WafPolicy wafOf(String routeBody) {
        return ConfigLoader.parse(TestYaml.route(routeBody) + RULE_SETS).routes().get(0).waf();
    }

    @Test
    void everyDeclaredRuleSetRunsInItsDeclaredModeOnEveryRoute() {
        WafPolicy waf = ConfigLoader.parse(TestYaml.MINIMAL + RULE_SETS).routes().get(0).waf();
        assertThat(waf.ruleSetModes()).isEqualTo(Map.of("aegis-core", RuleMode.BLOCK, "et-open", RuleMode.MONITOR));
    }

    @Test
    void aRouteCanOverrideTheModeOfADeclaredRuleSet() {
        WafPolicy waf = wafOf("rule_sets:\n  et-open: block\n  aegis-core: disabled");
        assertThat(waf.ruleSetModes()).isEqualTo(Map.of("aegis-core", RuleMode.DISABLED, "et-open", RuleMode.BLOCK));
    }

    @Test
    void aRouteCanSetTheModeAndScoreOfASingleRule() {
        WafPolicy waf = wafOf("""
                rules:
                  - sid: 9000001
                    mode: disabled
                    score: 2
                  - sid: 9000002
                    score: 4
                """);
        assertThat(waf.sidModes()).isEqualTo(Map.of(9000001, RuleMode.DISABLED));
        assertThat(waf.sidScores()).isEqualTo(Map.of(9000001, 2, 9000002, 4));
    }

    @Test
    void aRouteNamingAnUndeclaredRuleSetIsAProblem() {
        assertThat(TestYaml.problemsOf(TestYaml.route("rule_sets:\n  et-pro: block") + RULE_SETS))
                .containsExactly("routes[0].rule_sets.et-pro: 'et-pro' is not a declared rule set. "
                        + "Declared rule sets: aegis-core, et-open.");
    }

    @Test
    void anUndeclaredRuleSetIsReportedEvenWhenNoneAreDeclared() {
        assertThat(TestYaml.problemsOf(TestYaml.route("rule_sets:\n  et-pro: block")))
                .containsExactly("routes[0].rule_sets.et-pro: 'et-pro' is not a declared rule set. "
                        + "No rule sets are declared under rule_sets.");
    }

    @Test
    void aDeclaredRuleSetMustSayItsMode() {
        assertThat(TestYaml.problemsOf(TestYaml.plus("rule_sets:\n  - name: et\n    file: et.rules\n")))
                .containsExactly("rule_sets[0].mode is required but missing. "
                        + "Write block, monitor, or disabled; imported rule sets should start in monitor.");
    }

    @Test
    void aRuleOverrideNeedsASid() {
        assertThat(TestYaml.problemsOf(TestYaml.route("rules:\n  - mode: disabled")))
                .containsExactly("routes[0].rules[0].sid is required but missing.");
    }

    @Test
    void aSidMayBeOverriddenOnlyOncePerRoute() {
        assertThat(TestYaml.problemsOf(TestYaml.route("rules:\n  - sid: 7\n  - sid: 7")))
                .containsExactly("routes[0].rules[1].sid '7' is already used by routes[0].rules[0]. "
                        + "Each entry needs its own sid.");
    }
}
