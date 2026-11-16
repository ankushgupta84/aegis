package io.aegis.corerules;

import static org.assertj.core.api.Assertions.assertThat;

import io.aegis.rules.ClassifiedRule;
import io.aegis.rules.RuleStatus;
import io.aegis.rules.SuricataRule;
import java.util.List;
import org.junit.jupiter.api.Test;

class RulesFileTest {

    /** The class names in sid-block order, which is the order of the sections in the rules file. */
    private static final List<String> CLASSES_BY_SID_BLOCK = List.of("SQLI", "XSS", "TRAVERSAL", "INCLUSION",
            "CMDI", "EXPLOIT", "EVASION", "SCANNER", "PROBE");

    private final CoreRules core = CoreRules.shared();

    @Test
    void everyRuleInTheFileIsActive() {
        List<ClassifiedRule> notActive = core.ruleSet().rules().stream()
                .filter(rule -> rule.status() != RuleStatus.ACTIVE)
                .toList();

        assertThat(notActive)
                .as("rules that are not ACTIVE, with the reason the parser gave")
                .extracting(rule -> rule.sid() + " " + rule.status() + ": " + rule.reason())
                .isEmpty();
        assertThat(core.ruleSet().rules()).isNotEmpty();
    }

    @Test
    void noRuleIsNotApplicableOrUnsupported() {
        assertThat(core.ruleSet().count(RuleStatus.NOT_APPLICABLE)).isZero();
        assertThat(core.ruleSet().count(RuleStatus.UNSUPPORTED)).isZero();
    }

    @Test
    void sidsAreUniqueAndAscendingFromNineMillion() {
        List<Integer> sids = activeRules().stream().map(SuricataRule::sid).toList();

        assertThat(sids).isSorted().doesNotHaveDuplicates();
        assertThat(sids.get(0)).isEqualTo(9_000_001);
    }

    @Test
    void everyRuleHasAPrefilterPattern() {
        assertThat(core.engine().rulesWithoutPrefilter()).isZero();
        assertThat(core.engine().ruleCount()).isEqualTo(activeRules().size());
    }

    @Test
    void everyRuleCarriesAnExplicitScoreOfThreeOrFive() {
        assertThat(activeRules())
                .allSatisfy(rule -> assertThat(rule.metadata().get("score"))
                        .as("score of sid " + rule.sid()).isNotNull().hasSize(1));
        assertThat(activeRules()).extracting(SuricataRule::defaultScore).containsOnly(3, 5);
    }

    @Test
    void everyMessageNamesAClassUnderTheAegisCorePrefix() {
        assertThat(activeRules()).extracting(SuricataRule::msg).allSatisfy(msg -> assertThat(msg)
                .matches("AEGIS CORE (SQLI|XSS|TRAVERSAL|INCLUSION|CMDI|EXPLOIT|EVASION|SCANNER|PROBE) .+"));
    }

    @Test
    void everyRuleSitsInTheSidBlockOfItsClass() {
        assertThat(activeRules()).allSatisfy(rule -> {
            String attackClass = rule.msg().split(" ")[2];
            int block = (rule.sid() - 9_000_001) / 100;
            assertThat(CLASSES_BY_SID_BLOCK.get(block)).as("class of sid " + rule.sid()).isEqualTo(attackClass);
        });
    }

    @Test
    void everyRuleSaysToServerEstablishedAndTargetsTheWebServer() {
        assertThat(activeRules()).allSatisfy(rule -> {
            assertThat(rule.raw()).contains("flow:to_server,established;");
            assertThat(rule.metadata().get("attack_target")).containsExactly("Web_Server");
        });
    }

    @Test
    void everyRuleThatTargetsASpecificCveCitesIt() {
        assertThat(activeRules())
                .filteredOn(rule -> rule.metadata().containsKey("cve"))
                .allSatisfy(rule -> assertThat(rule.references()).anyMatch(reference -> reference.startsWith("cve,")));
    }

    private List<SuricataRule> activeRules() {
        return core.ruleSet().activeRules();
    }
}
