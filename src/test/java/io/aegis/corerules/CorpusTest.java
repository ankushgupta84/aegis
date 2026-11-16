package io.aegis.corerules;

import static org.assertj.core.api.Assertions.assertThat;

import io.aegis.rules.SuricataRule;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;
import java.util.stream.Collectors;
import org.junit.jupiter.api.Test;

class CorpusTest {

    private static final List<CorpusRequest> ATTACKS = Corpus.read("attacks.tsv");
    private static final List<CorpusRequest> BENIGN = Corpus.read("benign.tsv");
    private static final List<CorpusRequest> KNOWN_GAPS = Corpus.read("known-gaps.tsv");

    private final CoreRules core = CoreRules.shared();

    @Test
    void corporaAreLargeEnoughToMeanSomething() {
        assertThat(ATTACKS).hasSizeGreaterThanOrEqualTo(150);
        assertThat(BENIGN).hasSizeGreaterThanOrEqualTo(150);
    }

    @Test
    void idsAreUniqueAcrossAllCorpusFiles() {
        List<String> ids = List.of(ATTACKS, BENIGN, KNOWN_GAPS).stream().flatMap(List::stream)
                .map(CorpusRequest::id).toList();

        assertThat(ids).doesNotHaveDuplicates();
    }

    @Test
    void everyAttackLineIsBlocked() {
        List<CoreRules.Outcome> passed = ATTACKS.stream().map(core::evaluate).filter(o -> !o.blocked()).toList();

        assertThat(passed).as("attack ids that passed, with their scores and sids").isEmpty();
    }

    @Test
    void noBenignLineIsBlocked() {
        List<CoreRules.Outcome> blocked = BENIGN.stream().map(core::evaluate).filter(CoreRules.Outcome::blocked).toList();

        assertThat(blocked).as("benign ids that were blocked, with the sids that fired").isEmpty();
    }

    @Test
    void everyRuleFiresOnAtLeastOneAttackLine() {
        Set<Integer> fired = ATTACKS.stream().map(core::evaluate).flatMap(o -> o.sids().stream())
                .collect(Collectors.toSet());
        Set<Integer> silent = new TreeSet<>(core.ruleSet().activeRules().stream().map(SuricataRule::sid).toList());
        silent.removeAll(fired);

        assertThat(silent).as("rules that never fire on the attack corpus").isEmpty();
    }

    @Test
    void knownGapsStillBehaveAsDocumented() {
        List<String> changed = KNOWN_GAPS.stream().map(core::evaluate)
                .filter(o -> o.blocked() != o.request().kind().equals("benign"))
                .map(o -> o + " (documented as " + o.request().kind() + ")")
                .toList();

        assertThat(changed).as("known gaps whose behavior changed: move them into the main corpus").isEmpty();
    }

    @Test
    void everyKnownGapStatesAKindAndAReason() {
        assertThat(KNOWN_GAPS).allSatisfy(gap -> {
            assertThat(gap.kind()).isIn("attack", "benign");
            assertThat(gap.reason()).isNotBlank();
        });
    }
}
