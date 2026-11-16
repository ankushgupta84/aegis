package io.aegis.waf;

import static io.aegis.waf.TestRules.request;
import static io.aegis.waf.TestRules.ruleSet;
import static io.aegis.waf.TestRules.scoredRule;
import static io.aegis.waf.TestRules.uri;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.tuple;

import io.aegis.http.RequestBuffers;
import io.aegis.http.RuleBuffer;
import io.aegis.net.Cidr;
import io.aegis.policy.Exemption;
import io.aegis.policy.FailAction;
import io.aegis.policy.RuleMode;
import io.aegis.policy.Skip;
import io.aegis.policy.WafKnobs;
import io.aegis.policy.WafPolicy;
import io.aegis.rules.RuleSet;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.function.LongSupplier;
import org.junit.jupiter.api.Test;

class WafTest {

    private static final InetAddress INSIDE = address("10.0.0.5");
    private static final InetAddress OUTSIDE = address("203.0.113.9");
    private static final RequestBuffers ATTACK = request(RuleBuffer.HTTP_URI, "aaa bbb");

    private final long[] now = {0};
    private final LongSupplier clock = () -> now[0];
    private final List<RuntimeException> engineErrors = new ArrayList<>();

    private static InetAddress address(String literal) {
        try {
            return InetAddress.getByName(literal);
        } catch (UnknownHostException e) {
            throw new IllegalStateException(e);
        }
    }

    private static WafKnobs knobs(FailAction onBody, FailAction onBudget, FailAction onError) {
        return new WafKnobs(5, 1024, onBody, Duration.ofMillis(5), onBudget, onError);
    }

    private static WafKnobs passingKnobs() {
        return knobs(FailAction.PASS, FailAction.PASS, FailAction.PASS);
    }

    private static WafPolicy policy(WafKnobs knobs, Map<String, RuleMode> ruleSetModes, List<Exemption> exemptions) {
        return new WafPolicy(knobs, ruleSetModes, Map.of(), Map.of(), exemptions);
    }

    private static Exemption exemption(String name, Skip... skips) {
        return new Exemption(name, List.of(Cidr.parse("10.0.0.0/8")), List.of(skips), "scanner", "secops");
    }

    private Waf waf(RuleEngine engine, WafPolicy policy) {
        return new Waf(engine, policy, clock, engineErrors::add);
    }

    /** One rule set "web" holding sid 1 ("aaa", score 3) and sid 2 ("bbb", score 2). */
    private static RuleEngine twoRuleEngine() {
        return RuleEngine.compile(List.of(ruleSet("web",
                scoredRule(1, 3, uri("aaa").build()),
                scoredRule(2, 2, uri("bbb").build()))));
    }

    private static WafPolicy blockingPolicy(Exemption... exemptions) {
        return policy(passingKnobs(), Map.of("web", RuleMode.BLOCK), List.of(exemptions));
    }

    // ---- scoring ----

    @Test
    void blockModeHitsAddTheirScoresAndAFourDoesNotBlock() {
        RuleEngine engine = RuleEngine.compile(List.of(ruleSet("web", scoredRule(1, 4, uri("aaa").build()))));

        WafVerdict verdict = waf(engine, blockingPolicy()).evaluate(ATTACK, OUTSIDE, false);

        assertThat(verdict.score()).isEqualTo(4);
        assertThat(verdict.blocked()).isFalse();
    }

    @Test
    void aTotalOfExactlyTheThresholdBlocks() {
        RuleEngine engine = RuleEngine.compile(List.of(ruleSet("web", scoredRule(1, 5, uri("aaa").build()))));

        assertThat(waf(engine, blockingPolicy()).evaluate(ATTACK, OUTSIDE, false).blocked()).isTrue();
    }

    @Test
    void scoresFromSeveralHitsAdd() {
        WafVerdict verdict = waf(twoRuleEngine(), blockingPolicy()).evaluate(ATTACK, OUTSIDE, false);

        assertThat(verdict.score()).isEqualTo(5);
        assertThat(verdict.blocked()).isTrue();
        assertThat(verdict.hits()).extracting(RuleHit::sid).containsExactly(1, 2);
    }

    @Test
    void aHitCarriesTheRuleIdentityAndItsMode() {
        WafVerdict verdict = waf(twoRuleEngine(), blockingPolicy()).evaluate(ATTACK, OUTSIDE, false);

        assertThat(verdict.hits().getFirst())
                .isEqualTo(new RuleHit(1, 1, "rule 1", "web", RuleMode.BLOCK, 3));
    }

    @Test
    void monitorModeHitsAreRecordedWithScoreZero() {
        WafPolicy monitor = policy(passingKnobs(), Map.of("web", RuleMode.MONITOR), List.of());

        WafVerdict verdict = waf(twoRuleEngine(), monitor).evaluate(ATTACK, OUTSIDE, false);

        assertThat(verdict.hits()).hasSize(2).allSatisfy(hit -> {
            assertThat(hit.mode()).isEqualTo(RuleMode.MONITOR);
            assertThat(hit.score()).isZero();
        });
        assertThat(verdict.score()).isZero();
        assertThat(verdict.blocked()).isFalse();
    }

    @Test
    void aRuleSetMissingFromThePolicyIsDisabled() {
        WafPolicy none = policy(passingKnobs(), Map.of(), List.of());

        WafVerdict verdict = waf(twoRuleEngine(), none).evaluate(ATTACK, OUTSIDE, false);

        assertThat(verdict.hits()).isEmpty();
    }

    @Test
    void aSidModeOverridesItsRuleSetMode() {
        WafPolicy policy = new WafPolicy(passingKnobs(), Map.of("web", RuleMode.BLOCK),
                Map.of(1, RuleMode.MONITOR, 2, RuleMode.DISABLED), Map.of(), List.of());

        WafVerdict verdict = waf(twoRuleEngine(), policy).evaluate(ATTACK, OUTSIDE, false);

        assertThat(verdict.hits()).extracting(RuleHit::sid, RuleHit::mode).containsExactly(
                tuple(1, RuleMode.MONITOR));
    }

    @Test
    void aSidModeEnablesARuleInADisabledRuleSet() {
        WafPolicy policy = new WafPolicy(passingKnobs(), Map.of(),
                Map.of(2, RuleMode.BLOCK), Map.of(), List.of());

        WafVerdict verdict = waf(twoRuleEngine(), policy).evaluate(ATTACK, OUTSIDE, false);

        assertThat(verdict.hits()).extracting(RuleHit::sid).containsExactly(2);
    }

    @Test
    void aSidScoreOverridesTheRulesDefault() {
        WafPolicy policy = new WafPolicy(passingKnobs(), Map.of("web", RuleMode.BLOCK),
                Map.of(), Map.of(1, 10), List.of());

        WafVerdict verdict = waf(twoRuleEngine(), policy).evaluate(ATTACK, OUTSIDE, false);

        assertThat(verdict.score()).isEqualTo(12);
        assertThat(verdict.hits().getFirst().score()).isEqualTo(10);
    }

    @Test
    void aBenignRequestPassesWithNoHitsGapsOrExemptions() {
        WafVerdict verdict = waf(twoRuleEngine(), blockingPolicy()).evaluate(request(RuleBuffer.HTTP_URI, "/ok"), OUTSIDE, false);

        assertThat(verdict).isEqualTo(new WafVerdict(false, 0, List.of(), List.of(), List.of()));
    }

    // ---- exemptions ----

    @Test
    void aWafExemptionSkipsTheWholeStageAndIsNamed() {
        Waf waf = waf(twoRuleEngine(), blockingPolicy(exemption("scanner", Skip.waf())));

        WafVerdict verdict = waf.evaluate(ATTACK, INSIDE, true);

        assertThat(verdict).isEqualTo(new WafVerdict(false, 0, List.of(), List.of(), List.of("scanner")));
    }

    @Test
    void anExemptionDoesNotApplyToOtherClients() {
        Waf waf = waf(twoRuleEngine(), blockingPolicy(exemption("scanner", Skip.waf())));

        WafVerdict verdict = waf.evaluate(ATTACK, OUTSIDE, false);

        assertThat(verdict.blocked()).isTrue();
        assertThat(verdict.appliedExemptions()).isEmpty();
    }

    @Test
    void aRuleSetExemptionDisablesJustThatRuleSet() {
        RuleEngine engine = RuleEngine.compile(List.of(
                ruleSet("web", scoredRule(1, 3, uri("aaa").build())),
                ruleSet("scanner-noise", scoredRule(2, 3, uri("bbb").build()))));
        WafPolicy policy = policy(passingKnobs(),
                Map.of("web", RuleMode.BLOCK, "scanner-noise", RuleMode.BLOCK),
                List.of(exemption("qa", Skip.ruleSet("scanner-noise"))));

        WafVerdict verdict = waf(engine, policy).evaluate(ATTACK, INSIDE, false);

        assertThat(verdict.hits()).extracting(RuleHit::sid).containsExactly(1);
        assertThat(verdict.appliedExemptions()).containsExactly("qa");
    }

    @Test
    void aSidExemptionDisablesJustThatRule() {
        Waf waf = waf(twoRuleEngine(), blockingPolicy(exemption("fp", Skip.sid(1))));

        WafVerdict verdict = waf.evaluate(ATTACK, INSIDE, false);

        assertThat(verdict.hits()).extracting(RuleHit::sid).containsExactly(2);
        assertThat(verdict.score()).isEqualTo(2);
        assertThat(verdict.appliedExemptions()).containsExactly("fp");
    }

    @Test
    void aRateLimitExemptionIsNotTheWafsConcernAndIsNotListed() {
        Waf waf = waf(twoRuleEngine(), blockingPolicy(exemption("burst", Skip.rateLimit())));

        WafVerdict verdict = waf.evaluate(ATTACK, INSIDE, false);

        assertThat(verdict.blocked()).isTrue();
        assertThat(verdict.appliedExemptions()).isEmpty();
    }

    @Test
    void anExemptionWithBothRateLimitAndSidSkipsIsListedForTheSid() {
        Waf waf = waf(twoRuleEngine(), blockingPolicy(exemption("both", Skip.rateLimit(), Skip.sid(1))));

        assertThat(waf.evaluate(ATTACK, INSIDE, false).appliedExemptions()).containsExactly("both");
    }

    @Test
    void anExemptionNamingARuleTheRouteHasDisabledSkippedNothingAndIsNotListed() {
        Waf waf = waf(twoRuleEngine(), blockingPolicy(exemption("ghost", Skip.sid(999), Skip.ruleSet("elsewhere"))));

        assertThat(waf.evaluate(ATTACK, INSIDE, false).appliedExemptions()).isEmpty();
    }

    // ---- gaps ----

    @Test
    void aTruncatedBodyIsRecordedAndStillInspected() {
        WafVerdict verdict = waf(twoRuleEngine(), blockingPolicy()).evaluate(ATTACK, OUTSIDE, true);

        assertThat(verdict.gaps()).containsExactly(InspectionGap.BODY_OVER_SCAN_LIMIT);
        assertThat(verdict.hits()).hasSize(2);
    }

    @Test
    void aTruncatedBodyBlocksOnlyWhenItsKnobSaysBlock() {
        RequestBuffers benign = request(RuleBuffer.HTTP_URI, "/ok");
        WafPolicy passing = policy(knobs(FailAction.PASS, FailAction.BLOCK, FailAction.BLOCK), Map.of("web", RuleMode.BLOCK), List.of());
        WafPolicy blocking = policy(knobs(FailAction.BLOCK, FailAction.PASS, FailAction.PASS), Map.of("web", RuleMode.BLOCK), List.of());

        assertThat(waf(twoRuleEngine(), passing).evaluate(benign, OUTSIDE, true).blocked()).isFalse();
        assertThat(waf(twoRuleEngine(), blocking).evaluate(benign, OUTSIDE, true).blocked()).isTrue();
    }

    @Test
    void aBlownBudgetIsRecordedAndBlocksOnlyWhenItsKnobSaysBlock() {
        RuleEngine engine = twoRuleEngine();
        RequestBuffers slow = buffer -> {
            now[0] += Duration.ofMillis(6).toNanos();
            return "aaa bbb";
        };
        WafPolicy passing = policy(passingKnobs(), Map.of("web", RuleMode.MONITOR), List.of());
        WafPolicy blocking = policy(knobs(FailAction.PASS, FailAction.BLOCK, FailAction.PASS), Map.of("web", RuleMode.MONITOR), List.of());

        WafVerdict passed = waf(engine, passing).evaluate(slow, OUTSIDE, false);
        WafVerdict blocked = waf(engine, blocking).evaluate(slow, OUTSIDE, false);

        assertThat(passed.gaps()).containsExactly(InspectionGap.TIME_BUDGET_EXCEEDED);
        assertThat(passed.blocked()).isFalse();
        assertThat(blocked.gaps()).containsExactly(InspectionGap.TIME_BUDGET_EXCEEDED);
        assertThat(blocked.blocked()).isTrue();
    }

    @Test
    void theDeadlineIsNowPlusTheInspectionBudget() {
        RuleEngine engine = twoRuleEngine();
        now[0] = 1_000_000_000L;
        RequestBuffers fiveMillisecondsIn = buffer -> {
            now[0] += Duration.ofMillis(5).toNanos();
            return "aaa bbb";
        };

        WafVerdict verdict = waf(engine, blockingPolicy()).evaluate(fiveMillisecondsIn, OUTSIDE, false);

        assertThat(verdict.gaps()).isEmpty();
        assertThat(verdict.hits()).hasSize(2);
    }

    @Test
    void anEngineErrorIsReportedAndTrustsNoHits() {
        RuntimeException failure = new IllegalStateException("boom");
        RequestBuffers broken = buffer -> {
            throw failure;
        };
        WafPolicy blocking = policy(knobs(FailAction.PASS, FailAction.PASS, FailAction.BLOCK), Map.of("web", RuleMode.BLOCK), List.of());

        WafVerdict verdict = waf(twoRuleEngine(), blocking).evaluate(broken, OUTSIDE, false);

        assertThat(engineErrors).containsExactly(failure);
        assertThat(verdict.gaps()).containsExactly(InspectionGap.ENGINE_ERROR);
        assertThat(verdict.hits()).isEmpty();
        assertThat(verdict.blocked()).isTrue();
    }

    @Test
    void anEngineErrorPassesWhenItsKnobSaysPass() {
        RequestBuffers broken = buffer -> {
            throw new IllegalStateException("boom");
        };

        WafVerdict verdict = waf(twoRuleEngine(), blockingPolicy()).evaluate(broken, OUTSIDE, false);

        assertThat(verdict.blocked()).isFalse();
        assertThat(verdict.gaps()).containsExactly(InspectionGap.ENGINE_ERROR);
    }

    @Test
    void gapsAccumulateInTheOrderTruncatedThenBudgetThenError() {
        RequestBuffers broken = buffer -> {
            throw new IllegalStateException("boom");
        };

        WafVerdict verdict = waf(twoRuleEngine(), blockingPolicy()).evaluate(broken, OUTSIDE, true);

        assertThat(verdict.gaps()).containsExactly(InspectionGap.BODY_OVER_SCAN_LIMIT, InspectionGap.ENGINE_ERROR);
    }

    @Test
    void eachRuleSetGetsItsOwnMode() {
        RuleSet monitored = ruleSet("imported", scoredRule(2, 9, uri("bbb").build()));
        RuleEngine engine = RuleEngine.compile(List.of(ruleSet("own", scoredRule(1, 1, uri("aaa").build())), monitored));
        WafPolicy policy = policy(passingKnobs(), Map.of("own", RuleMode.BLOCK, "imported", RuleMode.MONITOR), List.of());

        WafVerdict verdict = waf(engine, policy).evaluate(ATTACK, OUTSIDE, false);

        assertThat(verdict.score()).isEqualTo(1);
        assertThat(verdict.hits()).extracting(RuleHit::mode).containsExactly(RuleMode.BLOCK, RuleMode.MONITOR);
    }
}
