package io.aegis.corerules;

import static org.assertj.core.api.Assertions.assertThat;

import io.aegis.rules.SuricataRule;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.stream.Collectors;
import org.junit.jupiter.api.Test;

/** Prints the numbers a reviewer wants: false negatives and positives, and blocks per attack class. */
class CorpusReportTest {

    private final CoreRules core = CoreRules.shared();

    @Test
    void reportsFalseNegativesFalsePositivesAndPerClassBlocks() {
        List<CorpusRequest> attacks = Corpus.read("attacks.tsv");
        List<CorpusRequest> benign = Corpus.read("benign.tsv");
        List<CoreRules.Outcome> attackOutcomes = attacks.stream().map(core::evaluate).toList();
        long falseNegatives = attackOutcomes.stream().filter(o -> !o.blocked()).count();
        long falsePositives = benign.stream().map(core::evaluate).filter(CoreRules.Outcome::blocked).count();
        Map<String, long[]> perClass = new TreeMap<>();
        attackOutcomes.forEach(o -> {
            long[] counts = perClass.computeIfAbsent(o.request().attackClass(), c -> new long[2]);
            counts[0] += o.blocked() ? 1 : 0;
            counts[1]++;
        });

        System.out.println("aegis-core: " + core.ruleSet().activeRules().size() + " rules; "
                + attacks.size() + " attack lines, " + benign.size() + " benign lines");
        System.out.println("false negatives: " + falseNegatives + ", false positives: " + falsePositives);
        perClass.forEach((name, c) -> System.out.println("  " + name + ": " + c[0] + "/" + c[1] + " blocked"));
        System.out.println("rules by class: " + core.ruleSet().activeRules().stream()
                .collect(Collectors.groupingBy(CorpusReportTest::classOf, TreeMap::new, Collectors.counting())));

        assertThat(falseNegatives).isZero();
        assertThat(falsePositives).isZero();
    }

    private static String classOf(SuricataRule rule) {
        return rule.msg().split(" ")[2];
    }
}
