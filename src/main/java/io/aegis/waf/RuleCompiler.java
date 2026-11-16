package io.aegis.waf;

import com.google.re2j.PatternSyntaxException;
import io.aegis.rules.Condition;
import io.aegis.rules.ContentMatch;
import io.aegis.rules.PcreMatch;
import io.aegis.rules.SuricataRule;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * Turns parsed rules into {@link CompiledRule}s. It numbers the distinct views as it meets them,
 * so conditions that inspect the same buffer with the same transforms share a view id.
 */
final class RuleCompiler {

    private final Map<ViewKey, Integer> viewIds = new LinkedHashMap<>();

    CompiledRule compile(SuricataRule rule, String ruleSetName) {
        List<Step> steps = new ArrayList<>();
        for (Condition condition : rule.conditions()) {
            steps.add(compile(rule.sid(), condition));
        }
        return new CompiledRule(rule.sid(), rule.rev(), rule.msg(), ruleSetName, rule.defaultScore(),
                steps, chooseFastPattern(steps));
    }

    /** The distinct views seen so far, indexed by view id. */
    List<ViewKey> views() {
        return List.copyOf(viewIds.keySet());
    }

    private Step compile(int sid, Condition condition) {
        int viewId = viewIds.computeIfAbsent(
                new ViewKey(condition.buffer(), condition.transforms()), key -> viewIds.size());
        return switch (condition) {
            case ContentMatch content -> new ContentStep(viewId, content);
            case PcreMatch pcre -> compilePcre(sid, viewId, pcre);
        };
    }

    private static PcreStep compilePcre(int sid, int viewId, PcreMatch pcre) {
        try {
            return PcreStep.compile(viewId, pcre);
        } catch (PatternSyntaxException e) {
            throw new IllegalArgumentException("Rule sid " + sid + " has a pcre RE2/J cannot compile: " + e.getMessage(), e);
        }
    }

    /**
     * The flagged {@code fast_pattern}, else the longest non-negated content: longer patterns are
     * rarer in traffic, so they wake fewer rules. A negated content cannot be used because its
     * absence proves nothing about a candidate.
     */
    private static Optional<ContentStep> chooseFastPattern(List<Step> steps) {
        List<ContentStep> candidates = steps.stream()
                .filter(ContentStep.class::isInstance)
                .map(ContentStep.class::cast)
                .filter(step -> !step.negated())
                .toList();
        return candidates.stream().filter(step -> step.match().fastPattern()).findFirst()
                .or(() -> candidates.stream().max(Comparator.comparingInt(ContentStep::length)));
    }
}
