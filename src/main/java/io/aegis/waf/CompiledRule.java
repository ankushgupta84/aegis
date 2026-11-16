package io.aegis.waf;

import java.util.List;
import java.util.Optional;

/**
 * A rule as the engine holds it: identity for logs and policy, plus its conditions resolved to
 * views and its chosen prefilter pattern.
 */
public final class CompiledRule {

    private final int sid;
    private final int rev;
    private final String msg;
    private final String ruleSet;
    private final int defaultScore;
    private final List<Step> steps;
    private final Optional<ContentStep> fastPattern;

    CompiledRule(int sid, int rev, String msg, String ruleSet, int defaultScore,
            List<Step> steps, Optional<ContentStep> fastPattern) {
        this.sid = sid;
        this.rev = rev;
        this.msg = msg;
        this.ruleSet = ruleSet;
        this.defaultScore = defaultScore;
        this.steps = List.copyOf(steps);
        this.fastPattern = fastPattern;
    }

    public int sid() {
        return sid;
    }

    public int rev() {
        return rev;
    }

    public String msg() {
        return msg;
    }

    /** The name of the rule set this rule was imported in. */
    public String ruleSet() {
        return ruleSet;
    }

    public int defaultScore() {
        return defaultScore;
    }

    List<Step> steps() {
        return steps;
    }

    /** The content the prefilter looks for; empty when the rule has no non-negated content. */
    Optional<ContentStep> fastPattern() {
        return fastPattern;
    }
}
