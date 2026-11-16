package io.aegis.waf;

import io.aegis.http.RequestBuffers;
import io.aegis.policy.Exemption;
import io.aegis.policy.FailAction;
import io.aegis.policy.RuleMode;
import io.aegis.policy.Skip;
import io.aegis.policy.WafPolicy;
import java.net.InetAddress;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.function.Consumer;
import java.util.function.LongSupplier;

/**
 * The WAF stage of one route: runs the shared {@link RuleEngine} and turns its matches into a
 * verdict under the route's policy.
 *
 * <p>Policy is resolved once, at construction, into flat per-rule arrays, so the request path does
 * no map lookups per rule. Cheap to create; the engine, which is expensive, is shared.
 */
public final class Waf {

    private final RuleEngine engine;
    private final WafPolicy policy;
    private final LongSupplier nanoClock;
    private final Consumer<RuntimeException> onEngineError;
    private final RuleMode[] modes;
    private final int[] scores;
    private final Set<Integer> enabledSids = new HashSet<>();
    private final Set<String> enabledRuleSets = new HashSet<>();

    public Waf(RuleEngine engine, WafPolicy policy, LongSupplier nanoClock, Consumer<RuntimeException> onEngineError) {
        this.engine = engine;
        this.policy = policy;
        this.nanoClock = nanoClock;
        this.onEngineError = onEngineError;
        this.modes = new RuleMode[engine.ruleCount()];
        this.scores = new int[engine.ruleCount()];
        for (int i = 0; i < modes.length; i++) {
            CompiledRule rule = engine.rule(i);
            modes[i] = policy.sidModes().getOrDefault(rule.sid(),
                    policy.ruleSetModes().getOrDefault(rule.ruleSet(), RuleMode.DISABLED));
            scores[i] = policy.sidScores().getOrDefault(rule.sid(), rule.defaultScore());
            if (modes[i] != RuleMode.DISABLED) {
                enabledSids.add(rule.sid());
                enabledRuleSets.add(rule.ruleSet());
            }
        }
    }

    /**
     * Inspects one request.
     *
     * @param client        the client address, to find the exemptions that apply
     * @param bodyTruncated true when the body was longer than the scan limit, so the buffers hold
     *                      only its prefix
     */
    public WafVerdict evaluate(RequestBuffers buffers, InetAddress client, boolean bodyTruncated) {
        Skips skips = skipsFor(client);
        if (!skips.wafExemptions.isEmpty()) {
            return new WafVerdict(false, 0, List.of(), List.of(), skips.wafExemptions);
        }
        List<InspectionGap> gaps = new ArrayList<>();
        if (bodyTruncated) {
            gaps.add(InspectionGap.BODY_OVER_SCAN_LIMIT);
        }
        List<RuleHit> hits = new ArrayList<>();
        int score = 0;
        MatchResult result = inspect(buffers, skips, gaps);
        for (int index : result.matchedRuleIndexes()) {
            CompiledRule rule = engine.rule(index);
            int points = modes[index] == RuleMode.BLOCK ? scores[index] : 0;
            score += points;
            hits.add(new RuleHit(rule.sid(), rule.rev(), rule.msg(), rule.ruleSet(), modes[index], points));
        }
        boolean blocked = score >= policy.knobs().blockThreshold() || gaps.stream().anyMatch(this::blocks);
        return new WafVerdict(blocked, score, hits, gaps, skips.applied);
    }

    /** Runs the engine; an engine failure is reported and yields no matches, since none can be trusted. */
    private MatchResult inspect(RequestBuffers buffers, Skips skips, List<InspectionGap> gaps) {
        long now = nanoClock.getAsLong();
        long deadline = now + policy.knobs().inspectionBudget().toNanos();
        try {
            MatchResult result = engine.match(buffers, index -> isEnabled(index, skips), deadline, nanoClock);
            if (result.budgetExceeded()) {
                gaps.add(InspectionGap.TIME_BUDGET_EXCEEDED);
            }
            return result;
        } catch (RuntimeException e) {
            onEngineError.accept(e);
            gaps.add(InspectionGap.ENGINE_ERROR);
            return new MatchResult(new int[0], false);
        }
    }

    private boolean isEnabled(int index, Skips skips) {
        CompiledRule rule = engine.rule(index);
        return modes[index] != RuleMode.DISABLED
                && !skips.sids.contains(rule.sid())
                && !skips.ruleSets.contains(rule.ruleSet());
    }

    private boolean blocks(InspectionGap gap) {
        return switch (gap) {
            case BODY_OVER_SCAN_LIMIT -> policy.knobs().onBodyOverLimit() == FailAction.BLOCK;
            case TIME_BUDGET_EXCEEDED -> policy.knobs().onBudgetExceeded() == FailAction.BLOCK;
            case ENGINE_ERROR -> policy.knobs().onEngineError() == FailAction.BLOCK;
        };
    }

    private Skips skipsFor(InetAddress client) {
        Skips skips = new Skips();
        for (Exemption exemption : policy.exemptions()) {
            if (exemption.appliesTo(client)) {
                skips.add(exemption);
            }
        }
        return skips;
    }

    /**
     * What the exemptions for one client skip. An exemption is listed as applied only when it
     * skips something this route would have run: a rate-limit skip is not the WAF's business, and
     * a skip naming a rule the route has disabled changes nothing.
     */
    private final class Skips {
        final Set<Integer> sids = new HashSet<>();
        final Set<String> ruleSets = new HashSet<>();
        final List<String> wafExemptions = new ArrayList<>();
        final List<String> applied = new ArrayList<>();

        void add(Exemption exemption) {
            boolean skippedAnything = false;
            for (Skip skip : exemption.skips()) {
                switch (skip.kind()) {
                    case WAF -> {
                        wafExemptions.add(exemption.name());
                        skippedAnything = true;
                    }
                    case RULE_SET -> {
                        ruleSets.add(skip.target());
                        skippedAnything |= enabledRuleSets.contains(skip.target());
                    }
                    case SID -> {
                        sids.add(skip.sid());
                        skippedAnything |= enabledSids.contains(skip.sid());
                    }
                    case RATE_LIMIT -> {
                        // The rate limiter enforces this skip; it says nothing about rules.
                    }
                }
            }
            if (skippedAnything) {
                applied.add(exemption.name());
            }
        }
    }
}
