package io.aegis.waf;

import static io.aegis.waf.TestRules.content;
import static io.aegis.waf.TestRules.requestOf;
import static io.aegis.waf.TestRules.rule;
import static org.assertj.core.api.Assertions.assertThat;

import io.aegis.http.RequestBuffers;
import io.aegis.http.RuleBuffer;
import io.aegis.rules.SuricataRule;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.Set;
import org.junit.jupiter.api.Test;

/** A rule set the size of a full ET Open import, to show that cost follows the request, not the rules. */
class RuleEngineScaleTest {

    private static final int RULES = 30_000;
    private static final int REQUESTS = 10_000;
    private static final String ALPHABET = "abcdefghijklmnopqrstuvwxyz0123456789";

    private final Random random = new Random(42);

    private String randomText(int length) {
        StringBuilder text = new StringBuilder(length);
        for (int i = 0; i < length; i++) {
            text.append(ALPHABET.charAt(random.nextInt(ALPHABET.length())));
        }
        return text.toString();
    }

    private List<String> distinctPatterns() {
        Set<String> patterns = new HashSet<>();
        List<String> ordered = new ArrayList<>();
        while (ordered.size() < RULES) {
            String pattern = randomText(12);
            if (patterns.add(pattern)) {
                ordered.add(pattern);
            }
        }
        return ordered;
    }

    @Test
    void thirtyThousandRulesCompileInTensOfMegabytesAndMatchInMicroseconds() {
        List<String> patterns = distinctPatterns();
        List<SuricataRule> rules = new ArrayList<>();
        for (int i = 0; i < RULES; i++) {
            RuleBuffer buffer = i % 2 == 0 ? RuleBuffer.HTTP_URI : RuleBuffer.HTTP_HEADER;
            rules.add(rule(10_000 + i, content(buffer, patterns.get(i)).nocase().build()));
        }

        long compileStart = System.nanoTime();
        RuleEngine engine = RuleEngine.compile(List.of(TestRules.ruleSet("scale", rules.toArray(SuricataRule[]::new))));
        long compileMillis = (System.nanoTime() - compileStart) / 1_000_000;

        String uri = "/search?q=" + randomText(60) + "&a=" + patterns.get(100).toUpperCase() + "&b=" + patterns.get(29_998);
        String header = "Host: example.com\r\nX-Token: " + patterns.get(7) + "\r\n" + randomText(100);
        RequestBuffers request = requestOf(Map.of(RuleBuffer.HTTP_URI, uri, RuleBuffer.HTTP_HEADER, header));

        assertThat(engine.match(request, index -> true, Long.MAX_VALUE, () -> 0L).matchedRuleIndexes())
                .containsExactly(7, 100, 29_998);

        long matchStart = System.nanoTime();
        int matches = 0;
        for (int i = 0; i < REQUESTS; i++) {
            matches += engine.match(request, index -> true, Long.MAX_VALUE, () -> 0L).matchedRuleIndexes().length;
        }
        long meanMicros = (System.nanoTime() - matchStart) / REQUESTS / 1_000;
        long tableMegabytes = engine.prefilterBytes() / (1024 * 1024);

        System.out.printf("scale: %d rules, compile %d ms, prefilter tables ~%d MB, mean match %d us over %d requests%n",
                engine.ruleCount(), compileMillis, tableMegabytes, meanMicros, REQUESTS);
        assertThat(matches).isEqualTo(3 * REQUESTS);
        assertThat(compileMillis).isLessThan(30_000);
        assertThat(tableMegabytes).isLessThan(150);
        assertThat(meanMicros).isLessThan(2_000);
    }
}
