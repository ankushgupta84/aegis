package io.aegis.waf;

import java.util.BitSet;
import java.util.List;

/**
 * The prefilter for one view: one pass over the view marks every rule whose fast pattern occurs in
 * it. Cost depends on the view's length, not on how many rules there are.
 */
final class ViewPrefilter {

    private final AhoCorasick automaton;
    private final int[] ruleOfPattern;

    /** @param ruleIndexes the rule that owns each pattern, parallel to {@code patterns} */
    ViewPrefilter(List<String> patterns, List<Integer> ruleIndexes) {
        this.automaton = new AhoCorasick(patterns);
        this.ruleOfPattern = ruleIndexes.stream().mapToInt(Integer::intValue).toArray();
    }

    void markCandidates(String view, BitSet candidates) {
        automaton.scan(view, pattern -> candidates.set(ruleOfPattern[pattern]));
    }

    long approximateBytes() {
        return automaton.approximateBytes() + 4L * ruleOfPattern.length;
    }
}
