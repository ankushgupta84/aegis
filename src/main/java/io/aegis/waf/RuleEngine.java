package io.aegis.waf;

import io.aegis.http.RequestBuffers;
import io.aegis.rules.RuleSet;
import io.aegis.rules.SuricataRule;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.BitSet;
import java.util.List;
import java.util.Objects;
import java.util.function.IntPredicate;
import java.util.function.LongSupplier;

/**
 * Runs Suricata rules against a request: one multi-pattern pass per view picks the candidate
 * rules, and only candidates are confirmed in full.
 *
 * <p>Immutable once compiled, so one engine is shared by every thread and every route; all
 * per-request state lives in objects created inside {@link #match}. Rule policy (mode, score,
 * exemptions) is not here: the caller passes in which rules are enabled.
 */
public final class RuleEngine {

    private final List<CompiledRule> rules;
    private final List<ViewKey> views;
    /** Indexed by view id; null for a view no rule's fast pattern lives in. */
    private final List<ViewPrefilter> prefilters;
    /** Rules with no non-negated content: nothing to prefilter on, so every request is a candidate. */
    private final BitSet alwaysCandidates;

    private RuleEngine(List<CompiledRule> rules, List<ViewKey> views,
            List<ViewPrefilter> prefilters, BitSet alwaysCandidates) {
        this.rules = rules;
        this.views = views;
        this.prefilters = prefilters;
        this.alwaysCandidates = alwaysCandidates;
    }

    /** Compiles the active rules of every set. A rule's index is its position across the sets, in order. */
    public static RuleEngine compile(List<RuleSet> ruleSets) {
        RuleCompiler compiler = new RuleCompiler();
        List<CompiledRule> rules = new ArrayList<>();
        for (RuleSet ruleSet : ruleSets) {
            for (SuricataRule rule : ruleSet.activeRules()) {
                rules.add(compiler.compile(rule, ruleSet.name()));
            }
        }
        List<ViewKey> views = compiler.views();
        return new RuleEngine(rules, views, buildPrefilters(rules, views.size()), alwaysCandidates(rules));
    }

    /**
     * Returns the enabled rules that match the request.
     *
     * @param ruleEnabled  false for a rule index to skip it without evaluating it
     * @param deadlineNanos when {@code nanoClock} passes this, evaluation stops and the result says so
     */
    public MatchResult match(RequestBuffers buffers, IntPredicate ruleEnabled, long deadlineNanos, LongSupplier nanoClock) {
        RequestViews requestViews = new RequestViews(buffers, views);
        BitSet candidates = findCandidates(requestViews);
        RuleConfirmer confirmer = new RuleConfirmer(requestViews, views.size(), deadlineNanos, nanoClock);
        int[] matched = new int[candidates.cardinality()];
        int matchedCount = 0;
        for (int rule = candidates.nextSetBit(0); rule >= 0; rule = candidates.nextSetBit(rule + 1)) {
            if (confirmer.outOfTime()) {
                break;
            }
            if (ruleEnabled.test(rule) && confirmer.matches(rules.get(rule))) {
                matched[matchedCount++] = rule;
            }
        }
        return new MatchResult(Arrays.copyOf(matched, matchedCount), confirmer.outOfTime());
    }

    public int ruleCount() {
        return rules.size();
    }

    public CompiledRule rule(int index) {
        return rules.get(index);
    }

    /** How many rules are evaluated on every request because they have no content to prefilter on. */
    public int rulesWithoutPrefilter() {
        return alwaysCandidates.cardinality();
    }

    /** Approximate bytes held by the prefilter tables, for capacity planning and tests. */
    long prefilterBytes() {
        return prefilters.stream().filter(Objects::nonNull).mapToLong(ViewPrefilter::approximateBytes).sum();
    }

    private BitSet findCandidates(RequestViews requestViews) {
        BitSet candidates = (BitSet) alwaysCandidates.clone();
        for (int view = 0; view < prefilters.size(); view++) {
            ViewPrefilter prefilter = prefilters.get(view);
            if (prefilter != null) {
                prefilter.markCandidates(requestViews.get(view), candidates);
            }
        }
        return candidates;
    }

    private static List<ViewPrefilter> buildPrefilters(List<CompiledRule> rules, int viewCount) {
        List<List<String>> patterns = new ArrayList<>();
        List<List<Integer>> owners = new ArrayList<>();
        for (int view = 0; view < viewCount; view++) {
            patterns.add(new ArrayList<>());
            owners.add(new ArrayList<>());
        }
        for (int rule = 0; rule < rules.size(); rule++) {
            ContentStep fast = rules.get(rule).fastPattern().orElse(null);
            if (fast != null) {
                patterns.get(fast.viewId()).add(fast.match().pattern());
                owners.get(fast.viewId()).add(rule);
            }
        }
        List<ViewPrefilter> prefilters = new ArrayList<>();
        for (int view = 0; view < viewCount; view++) {
            prefilters.add(patterns.get(view).isEmpty() ? null : new ViewPrefilter(patterns.get(view), owners.get(view)));
        }
        return prefilters;
    }

    private static BitSet alwaysCandidates(List<CompiledRule> rules) {
        BitSet always = new BitSet(rules.size());
        for (int rule = 0; rule < rules.size(); rule++) {
            if (rules.get(rule).fastPattern().isEmpty()) {
                always.set(rule);
            }
        }
        return always;
    }
}
