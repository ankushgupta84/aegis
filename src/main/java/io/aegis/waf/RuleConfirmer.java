package io.aegis.waf;

import com.google.re2j.Matcher;
import java.util.Arrays;
import java.util.List;
import java.util.function.LongSupplier;

/**
 * Decides whether a candidate rule really matches, with Suricata's positional semantics.
 *
 * <p>Holds the per-request scratch state: the end of the previous match in each view, which
 * relative conditions measure from, and the time budget. One instance serves one request on one
 * thread.
 *
 * <p>A content may occur several times, and a later relative condition can fail for the first
 * occurrence yet hold for the second. So each step tries its occurrences in turn and recurses into
 * the rest of the rule, undoing its position when the rest fails. Regular expressions take their
 * first match only: they are linear-time, and chasing every match would not be.
 */
final class RuleConfirmer {

    private final RequestViews views;
    private final long deadlineNanos;
    private final LongSupplier nanoClock;
    private final int[] previousEnd;
    private boolean outOfTime;

    RuleConfirmer(RequestViews views, int viewCount, long deadlineNanos, LongSupplier nanoClock) {
        this.views = views;
        this.deadlineNanos = deadlineNanos;
        this.nanoClock = nanoClock;
        this.previousEnd = new int[viewCount];
    }

    /**
     * True once the budget is spent. The clock is read only here, and callers ask between rules and
     * between occurrences, never per byte. The answer is latched: time does not run backwards.
     */
    boolean outOfTime() {
        if (!outOfTime) {
            outOfTime = nanoClock.getAsLong() - deadlineNanos > 0;
        }
        return outOfTime;
    }

    /** False also when time ran out mid-rule: an undecided rule is not reported as matched. */
    boolean matches(CompiledRule rule) {
        Arrays.fill(previousEnd, 0);
        return holdsFrom(rule.steps(), 0);
    }

    private boolean holdsFrom(List<Step> steps, int index) {
        if (index == steps.size()) {
            return true;
        }
        return switch (steps.get(index)) {
            case ContentStep content -> contentHolds(steps, index, content);
            case PcreStep pcre -> pcreHolds(steps, index, pcre);
        };
    }

    private boolean contentHolds(List<Step> steps, int index, ContentStep step) {
        int view = step.viewId();
        String text = views.get(view);
        int latest = step.latestStart(previousEnd[view], text.length());
        int start = step.indexIn(text, step.earliestStart(previousEnd[view], text.length()), latest);
        if (step.negated()) {
            return start < 0 && holdsFrom(steps, index + 1);
        }
        int endBefore = previousEnd[view];
        while (start >= 0) {
            previousEnd[view] = start + step.length();
            if (holdsFrom(steps, index + 1)) {
                return true;
            }
            previousEnd[view] = endBefore;
            if (outOfTime()) {
                return false;
            }
            start = step.indexIn(text, start + 1, latest);
        }
        return false;
    }

    private boolean pcreHolds(List<Step> steps, int index, PcreStep step) {
        int view = step.viewId();
        String text = views.get(view);
        int from = step.match().relative() ? previousEnd[view] : 0;
        Matcher matcher = step.pattern().matcher(text);
        boolean found = from <= text.length() && matcher.find(from);
        if (step.negated()) {
            return !found && holdsFrom(steps, index + 1);
        }
        if (!found) {
            return false;
        }
        int endBefore = previousEnd[view];
        previousEnd[view] = matcher.end();
        if (holdsFrom(steps, index + 1)) {
            return true;
        }
        previousEnd[view] = endBefore;
        return false;
    }
}
