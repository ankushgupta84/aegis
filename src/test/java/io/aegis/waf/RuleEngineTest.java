package io.aegis.waf;

import static io.aegis.waf.TestRules.content;
import static io.aegis.waf.TestRules.engine;
import static io.aegis.waf.TestRules.pcre;
import static io.aegis.waf.TestRules.request;
import static io.aegis.waf.TestRules.requestOf;
import static io.aegis.waf.TestRules.rule;
import static io.aegis.waf.TestRules.uri;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import io.aegis.http.RequestBuffers;
import io.aegis.http.RuleBuffer;
import io.aegis.rules.ClassifiedRule;
import io.aegis.rules.Condition;
import io.aegis.rules.PcreMatch;
import io.aegis.rules.RuleStatus;
import io.aegis.rules.RuleSet;
import io.aegis.rules.Transform;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.function.IntPredicate;
import java.util.function.LongSupplier;
import org.junit.jupiter.api.Test;

class RuleEngineTest {

    private static final RuleBuffer URI = RuleBuffer.HTTP_URI;
    private static final RuleBuffer BODY = RuleBuffer.HTTP_REQUEST_BODY;
    private static final RuleBuffer HEADER = RuleBuffer.HTTP_HEADER;

    private static int[] matchUri(RuleEngine engine, String uri) {
        return matched(engine, request(URI, uri));
    }

    private static int[] matched(RuleEngine engine, RequestBuffers buffers) {
        return engine.match(buffers, index -> true, Long.MAX_VALUE, () -> 0L).matchedRuleIndexes();
    }

    private static Condition[] all(Condition... conditions) {
        return conditions;
    }

    @Test
    void aRuleMatchesWhenItsContentOccurs() {
        RuleEngine engine = engine(rule(1, uri("/admin").build()));

        assertThat(matchUri(engine, "/x/admin/y")).containsExactly(0);
        assertThat(matchUri(engine, "/x/user/y")).isEmpty();
    }

    @Test
    void matchedIndexesAreAscendingWhateverOrderThePrefilterFindsThem() {
        RuleEngine engine = engine(
                rule(1, uri("zzz").build()),
                rule(2, uri("yyy").build()),
                rule(3, uri("xxx").build()));

        assertThat(matchUri(engine, "xxx yyy zzz")).containsExactly(0, 1, 2);
    }

    @Test
    void ruleIndexesRunAcrossRuleSetsInOrder() {
        RuleEngine engine = RuleEngine.compile(List.of(
                TestRules.ruleSet("first", rule(1, uri("aaa").build())),
                TestRules.ruleSet("second", rule(2, uri("bbb").build()))));

        assertThat(engine.ruleCount()).isEqualTo(2);
        assertThat(engine.rule(1).sid()).isEqualTo(2);
        assertThat(engine.rule(1).ruleSet()).isEqualTo("second");
        assertThat(matchUri(engine, "bbb")).containsExactly(1);
    }

    @Test
    void onlyActiveRulesAreCompiled() {
        RuleSet mixed = new RuleSet("mixed", List.of(
                ClassifiedRule.active(rule(1, uri("aaa").build())),
                ClassifiedRule.skipped(2, 1, RuleStatus.UNSUPPORTED, "uses flowbits", "raw")));

        assertThat(RuleEngine.compile(List.of(mixed)).ruleCount()).isEqualTo(1);
    }

    // ---- content positions ----

    @Test
    void offsetAndDepthBoundTheMatchFromTheBufferStart() {
        RuleEngine engine = engine(rule(1, uri("abc").offset(2).depth(4).build()));

        assertThat(matchUri(engine, "xxabcx")).containsExactly(0);
        assertThat(matchUri(engine, "xabcxx")).isEmpty();
        assertThat(matchUri(engine, "xxxxabc")).isEmpty();
    }

    @Test
    void depthWithoutOffsetCountsFromZero() {
        RuleEngine engine = engine(rule(1, uri("abc").depth(4).build()));

        assertThat(matchUri(engine, "xabc")).containsExactly(0);
        assertThat(matchUri(engine, "xxabc")).isEmpty();
    }

    @Test
    void distanceSkipsBytesAfterThePreviousMatch() {
        RuleEngine engine = engine(rule(1, uri("ab").build(), uri("cd").distance(2).build()));

        assertThat(matchUri(engine, "abxxcd")).containsExactly(0);
        assertThat(matchUri(engine, "abxcd")).isEmpty();
    }

    @Test
    void withinLimitsTheEndOfTheMatchRelativeToThePreviousMatch() {
        RuleEngine engine = engine(rule(1, uri("ab").build(), uri("cd").within(4).build()));

        assertThat(matchUri(engine, "abxxcd")).containsExactly(0);
        assertThat(matchUri(engine, "abxxxcd")).isEmpty();
    }

    @Test
    void withinIsCountedFromTheEndOfTheDistanceGap() {
        RuleEngine engine = engine(rule(1, uri("ab").build(), uri("cd").distance(3).within(2).build()));

        assertThat(matchUri(engine, "abxxxcd")).containsExactly(0);
        assertThat(matchUri(engine, "abxxxxcd")).isEmpty();
        assertThat(matchUri(engine, "abxxcd")).isEmpty();
    }

    @Test
    void hugeModifierValuesSaturateInsteadOfWrappingIntoAnEmptyWindow() {
        RuleEngine relative = engine(rule(1, uri("ab").build(),
                uri("cd").distance(1).within(Integer.MAX_VALUE).build()));
        RuleEngine absolute = engine(rule(2, uri("cd").offset(1).depth(Integer.MAX_VALUE).build()));

        assertThat(matchUri(relative, "abxcd")).containsExactly(0);
        assertThat(matchUri(absolute, "xcd")).containsExactly(0);
    }

    @Test
    void aRelativeConditionTriesLaterOccurrencesOfThePreviousContent() {
        // The first "ab" is followed by "cd" too far away; the second "ab" is close enough.
        RuleEngine engine = engine(rule(1, uri("ab").build(), uri("cd").within(3).build()));

        assertThat(matchUri(engine, "abxxxxxxab_cd")).containsExactly(0);
        assertThat(matchUri(engine, "abxxxxxxab__cd")).isEmpty();
    }

    @Test
    void backtrackingSpansThreeConditions() {
        RuleEngine engine = engine(rule(1,
                uri("a").build(), uri("b").distance(1).within(1).build(), uri("c").distance(0).within(1).build()));

        assertThat(matchUri(engine, "a_b__a_bc")).containsExactly(0);
    }

    @Test
    void backtrackingWorksWhenAnEarlierContentAlsoOccursAsTheSameBytes() {
        RuleEngine engine = engine(rule(1, uri("aa").build(), uri("b").within(2).distance(0).build()));

        assertThat(matchUri(engine, "aaab")).containsExactly(0);
    }

    @Test
    void aNegatedContentHoldsWhenAbsentFromItsWindow() {
        RuleEngine engine = engine(rule(1, uri("ab").build(), uri("zz").negated().within(3).build()));

        assertThat(matchUri(engine, "abxxxxzz")).containsExactly(0);
        assertThat(matchUri(engine, "abxzzx")).isEmpty();
    }

    @Test
    void aNegatedContentWithOffsetAndDepthChecksOnlyThatWindow() {
        RuleEngine engine = engine(rule(1, uri("ab").build(), uri("zz").negated().offset(0).depth(4).build()));

        assertThat(matchUri(engine, "ab__zz")).containsExactly(0);
        assertThat(matchUri(engine, "abzz__")).isEmpty();
    }

    @Test
    void aNegatedContentDoesNotMoveThePreviousMatch() {
        RuleEngine engine = engine(rule(1,
                uri("ab").build(), uri("zz").negated().build(), uri("cd").distance(0).within(2).build()));

        assertThat(matchUri(engine, "abcd")).containsExactly(0);
    }

    @Test
    void startsWithAnchorsAtTheBufferStart() {
        RuleEngine engine = engine(rule(1, uri("/api").startsWith().build()));

        assertThat(matchUri(engine, "/api/x")).containsExactly(0);
        assertThat(matchUri(engine, "/x/api")).isEmpty();
    }

    @Test
    void startsWithAnchorsAtThePreviousMatchEndWhenRelative() {
        RuleEngine engine = engine(rule(1, uri("ab").build(), uri("cd").startsWith().distance(0).build()));

        assertThat(matchUri(engine, "abcd")).containsExactly(0);
        assertThat(matchUri(engine, "abxcd")).isEmpty();
    }

    @Test
    void endsWithAnchorsAtTheBufferEnd() {
        RuleEngine engine = engine(rule(1, uri(".php").endsWith().build()));

        assertThat(matchUri(engine, "/a.php")).containsExactly(0);
        assertThat(matchUri(engine, "/a.php?x=1")).isEmpty();
    }

    @Test
    void endsWithSeesTheLastOccurrenceWhenTheContentAlsoOccursEarlier() {
        RuleEngine engine = engine(rule(1, uri("aa").endsWith().build()));

        assertThat(matchUri(engine, "aaxaa")).containsExactly(0);
        assertThat(matchUri(engine, "aaxa")).isEmpty();
    }

    @Test
    void nocaseIgnoresAsciiCase() {
        RuleEngine engine = engine(rule(1, uri("SeLeCt").nocase().build()));

        assertThat(matchUri(engine, "x select y")).containsExactly(0);
        assertThat(matchUri(engine, "x SELECT y")).containsExactly(0);
    }

    @Test
    void withoutNocaseCaseMattersEvenThoughThePrefilterFoldsIt() {
        RuleEngine engine = engine(rule(1, uri("SELECT").build()));

        assertThat(matchUri(engine, "x select y")).isEmpty();
        assertThat(matchUri(engine, "x SELECT y")).containsExactly(0);
    }

    @Test
    void nocaseDoesNotFoldLatin1Letters() {
        RuleEngine engine = engine(rule(1, uri("é").nocase().build()));

        assertThat(matchUri(engine, "É")).isEmpty();
        assertThat(matchUri(engine, "é")).containsExactly(0);
    }

    @Test
    void nocaseWorksWithPositionLimits() {
        RuleEngine engine = engine(rule(1, uri("ab").nocase().build(), uri("CD").nocase().distance(1).within(2).build()));

        assertThat(matchUri(engine, "AB_cd")).containsExactly(0);
        assertThat(matchUri(engine, "AB__cd")).isEmpty();
    }

    @Test
    void aContentLongerThanTheBufferNeverMatchesAndNeverThrows() {
        RuleEngine engine = engine(rule(1, uri("abcdef").endsWith().build()));

        assertThat(matchUri(engine, "abc")).isEmpty();
        assertThat(matchUri(engine, "")).isEmpty();
    }

    // ---- views ----

    @Test
    void aUrlEncodedPatternIsCaughtOnlyThroughUrlDecode() {
        RuleEngine plain = engine(rule(1, content(BODY, "<script>").build()));
        RuleEngine decoding = engine(rule(1, content(BODY, "<script>").transforms(Transform.URL_DECODE).build()));
        RequestBuffers encoded = request(BODY, "q=%3Cscript%3E");

        assertThat(matched(plain, encoded)).isEmpty();
        assertThat(matched(decoding, encoded)).containsExactly(0);
    }

    @Test
    void positionsAreMeasuredInTheTransformedView() {
        RuleEngine engine = engine(rule(1,
                content(BODY, "ab").transforms(Transform.URL_DECODE).build(),
                content(BODY, "cd").transforms(Transform.URL_DECODE).distance(1).within(2).build()));

        assertThat(matched(engine, request(BODY, "a%62%20cd"))).containsExactly(0);
    }

    @Test
    void conditionsOnDifferentViewsDoNotShareTheirPreviousMatch() {
        // "cd" is within 2 bytes of its own view's start (no earlier match there), not of "ab" in the URI.
        RuleEngine engine = engine(rule(1,
                uri("ab").build(),
                content(HEADER, "cd").distance(0).within(2).build()));
        RequestBuffers request = requestOf(Map.of(URI, "abxxxxxxxx", HEADER, "cd"));

        assertThat(matched(engine, request)).containsExactly(0);
    }

    @Test
    void aRuleNeedsEveryViewToHold() {
        RuleEngine engine = engine(rule(1, uri("ab").build(), content(HEADER, "cd").build()));

        assertThat(matched(engine, requestOf(Map.of(URI, "ab")))).isEmpty();
        assertThat(matched(engine, requestOf(Map.of(URI, "ab", HEADER, "cd")))).containsExactly(0);
    }

    @Test
    void theBodyIsNeverRequestedWhenNoRuleInspectsIt() {
        RuleEngine engine = engine(rule(1, uri("ab").build()));
        List<RuleBuffer> requested = new ArrayList<>();

        matched(engine, buffer -> {
            requested.add(buffer);
            return "ab";
        });

        assertThat(requested).containsExactly(URI);
    }

    @Test
    void theBodyIsNotRequestedWhenTheCheaperPrefilterPatternDoesNotOccur() {
        RuleEngine engine = engine(rule(1,
                uri("longer-uri-pattern").build(), content(BODY, "b").build()));
        List<RuleBuffer> requested = new ArrayList<>();

        matched(engine, buffer -> {
            requested.add(buffer);
            return "nothing here";
        });

        assertThat(requested).containsExactly(URI);
    }

    @Test
    void aBufferIsFetchedOnceEvenWhenSeveralViewsDeriveFromIt() {
        RuleEngine engine = engine(
                rule(1, content(BODY, "ab").build()),
                rule(2, content(BODY, "ab").transforms(Transform.URL_DECODE).build()),
                rule(3, content(BODY, "ab").transforms(Transform.TO_LOWERCASE).build()));
        List<RuleBuffer> requested = new ArrayList<>();

        matched(engine, buffer -> {
            requested.add(buffer);
            return "ab";
        });

        assertThat(requested).containsExactly(BODY);
    }

    // ---- fast pattern and prefilter ----

    @Test
    void aFlaggedFastPatternIsUsedEvenWhenAnotherContentIsLonger() {
        RuleEngine engine = engine(rule(1, uri("short").fastPattern().build(), uri("muchlongercontent").build()));

        assertThat(engine.rule(0).fastPattern().orElseThrow().match().pattern()).isEqualTo("short");
        assertThat(matchUri(engine, "short and muchlongercontent")).containsExactly(0);
    }

    @Test
    void theLongestNonNegatedContentIsTheDefaultFastPattern() {
        RuleEngine engine = engine(rule(1,
                uri("ab").build(), uri("a-negated-very-long-pattern").negated().build(), uri("abcd").build()));

        assertThat(engine.rule(0).fastPattern().orElseThrow().match().pattern()).isEqualTo("abcd");
    }

    @Test
    void rulesSharingAFastPatternAreEachConfirmedOnTheirOwn() {
        RuleEngine engine = engine(
                rule(1, uri("login").build(), uri("admin").build()),
                rule(2, uri("login").build(), uri("guest").build()),
                rule(3, uri("login").build()));

        assertThat(matchUri(engine, "/login?u=admin")).containsExactly(0, 2);
        assertThat(matchUri(engine, "/login?u=guest")).containsExactly(1, 2);
    }

    @Test
    void aPcreOnlyRuleIsEvaluatedOnEveryRequest() {
        RuleEngine engine = engine(rule(1, pcre(URI, "^/a+$", false, false)), rule(2, uri("zzz").build()));

        assertThat(engine.rulesWithoutPrefilter()).isEqualTo(1);
        assertThat(matchUri(engine, "/aaa")).containsExactly(0);
        assertThat(matchUri(engine, "/b")).isEmpty();
    }

    @Test
    void aNegationOnlyRuleIsEvaluatedOnEveryRequest() {
        RuleEngine engine = engine(rule(1, uri("evil").negated().build()));

        assertThat(engine.rulesWithoutPrefilter()).isEqualTo(1);
        assertThat(matchUri(engine, "/good")).containsExactly(0);
        assertThat(matchUri(engine, "/evil")).isEmpty();
    }

    @Test
    void anEngineWithNoRulesMatchesNothing() {
        RuleEngine engine = RuleEngine.compile(List.of());

        assertThat(matchUri(engine, "/anything")).isEmpty();
    }

    // ---- pcre ----

    @Test
    void pcreFindsAMatchAnywhereInTheView() {
        RuleEngine engine = engine(rule(1, uri("id").build(), pcre(URI, "id=\\d+", false, false)));

        assertThat(matchUri(engine, "/p?id=42")).containsExactly(0);
        assertThat(matchUri(engine, "/p?id=x")).isEmpty();
    }

    @Test
    void aRelativePcreSearchesOnlyAfterThePreviousMatch() {
        RuleEngine engine = engine(rule(1, uri("start").build(), pcre(URI, "\\d+", false, true)));

        assertThat(matchUri(engine, "12 start 34")).containsExactly(0);
        assertThat(matchUri(engine, "12 start x")).isEmpty();
    }

    @Test
    void aPcreMatchBecomesThePreviousMatchForALaterContent() {
        RuleEngine engine = engine(rule(1,
                uri("start").build(), pcre(URI, "\\d+", false, true), uri("end").distance(0).within(4).build()));

        assertThat(matchUri(engine, "start 12 end")).containsExactly(0);
        assertThat(matchUri(engine, "start 12    end")).isEmpty();
    }

    @Test
    void aNegatedPcreHoldsWhenItDoesNotMatch() {
        RuleEngine engine = engine(rule(1, uri("ab").build(), pcre(URI, "\\d", true, false)));

        assertThat(matchUri(engine, "ab")).containsExactly(0);
        assertThat(matchUri(engine, "ab1")).isEmpty();
    }

    @Test
    void pcreHonoursItsFlags() {
        Condition insensitive = new PcreMatch(URI, List.of(), "select", false, true, false, false, false);
        Condition dotAll = new PcreMatch(URI, List.of(), "a.b", false, false, true, false, false);
        Condition multiline = new PcreMatch(URI, List.of(), "^b$", false, false, false, true, false);

        assertThat(matchUri(engine(rule(1, insensitive)), "SELECT")).containsExactly(0);
        assertThat(matchUri(engine(rule(1, dotAll)), "a\nb")).containsExactly(0);
        assertThat(matchUri(engine(rule(1, multiline)), "a\nb\nc")).containsExactly(0);
        assertThat(matchUri(engine(rule(1, pcre(URI, "a.b", false, false))), "a\nb")).isEmpty();
    }

    @Test
    void pcreSeesTheTransformedView() {
        Condition decoded = new PcreMatch(
                BODY, List.of(Transform.URL_DECODE), "<script", false, false, false, false, false);

        assertThat(matched(engine(rule(1, decoded)), request(BODY, "%3Cscript"))).containsExactly(0);
    }

    @Test
    void aRegexThatCannotCompileFailsAtEngineCompileWithTheSid() {
        assertThatThrownBy(() -> engine(rule(77, pcre(URI, "(?=lookahead)", false, false))))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("sid 77");
    }

    // ---- enablement and budget ----

    @Test
    void aDisabledRuleIsNotEvaluated() {
        RuleEngine engine = engine(rule(1, uri("ab").build()), rule(2, uri("ab").build()));
        IntPredicate onlySecond = index -> index == 1;

        MatchResult result = engine.match(request(URI, "ab"), onlySecond, Long.MAX_VALUE, () -> 0L);

        assertThat(result.matchedRuleIndexes()).containsExactly(1);
    }

    @Test
    void aClockThatJumpsPastTheDeadlineStopsEvaluationAndKeepsMatchesFoundBefore() {
        RuleEngine engine = engine(
                rule(1, uri("aaa").build()), rule(2, uri("bbb").build()), rule(3, uri("ccc").build()));
        long[] now = {0};
        LongSupplier clock = () -> now[0];
        IntPredicate jumpAfterFirstRule = index -> {
            if (index == 1) {
                now[0] = 1_000;
            }
            return true;
        };

        MatchResult result = engine.match(request(URI, "aaa bbb ccc"), jumpAfterFirstRule, 500, clock);

        assertThat(result.budgetExceeded()).isTrue();
        assertThat(result.matchedRuleIndexes()).containsExactly(0, 1);
    }

    @Test
    void aDeadlineAlreadyPastEvaluatesNothing() {
        RuleEngine engine = engine(rule(1, uri("ab").build()));

        MatchResult result = engine.match(request(URI, "ab"), index -> true, 10, () -> 11L);

        assertThat(result.budgetExceeded()).isTrue();
        assertThat(result.matchedRuleIndexes()).isEmpty();
    }

    @Test
    void theBudgetIsCheckedBetweenOccurrencesOfOneContent() {
        RuleEngine engine = engine(rule(1, uri("a").build(), uri("never").distance(0).within(1).build()));
        long[] reads = {0};
        LongSupplier clock = () -> reads[0]++ < 2 ? 0 : 1_000;

        MatchResult result = engine.match(request(URI, "a".repeat(100) + "never"), index -> true, 500, clock);

        assertThat(result.budgetExceeded()).isTrue();
        assertThat(reads[0]).isLessThan(10);
    }

    @Test
    void aRuleCutShortByTheBudgetIsNotReportedAsMatched() {
        RuleEngine engine = engine(rule(1, uri("a").build(), uri("b").distance(0).within(1).build()));
        long[] reads = {0};
        LongSupplier clock = () -> reads[0]++ < 1 ? 0 : 1_000;

        MatchResult result = engine.match(request(URI, "aaaaab"), index -> true, 500, clock);

        assertThat(result.budgetExceeded()).isTrue();
        assertThat(result.matchedRuleIndexes()).isEmpty();
    }

    @Test
    void anEngineIsSafeToShareAcrossThreads() throws Exception {
        RuleEngine engine = engine(rule(1, uri("ab").build(), uri("cd").distance(1).within(2).build()));
        try (var pool = Executors.newFixedThreadPool(8)) {
            List<Future<Boolean>> results = new ArrayList<>();
            for (int i = 0; i < 64; i++) {
                String uri = i % 2 == 0 ? "ab_cd" : "ab__cd";
                boolean expected = i % 2 == 0;
                results.add(pool.submit(() -> {
                    for (int n = 0; n < 500; n++) {
                        if ((matchUri(engine, uri).length == 1) != expected) {
                            return false;
                        }
                    }
                    return true;
                }));
            }
            for (var result : results) {
                assertThat(result.get()).isTrue();
            }
        }
    }
}
