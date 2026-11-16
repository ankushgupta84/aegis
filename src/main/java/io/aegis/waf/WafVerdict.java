package io.aegis.waf;

import java.util.List;

/**
 * The WAF's decision on one request, with everything needed to explain it.
 *
 * @param blocked           true when the score reached the threshold, or a gap occurred whose
 *                          policy is to block
 * @param score             the sum of scores from block-mode hits
 * @param hits              every rule that matched, in rule order, including monitor-mode hits
 * @param gaps              the ways inspection was incomplete; empty for a fully inspected request
 * @param appliedExemptions names of the exemptions that skipped something for this client
 */
public record WafVerdict(
        boolean blocked,
        int score,
        List<RuleHit> hits,
        List<InspectionGap> gaps,
        List<String> appliedExemptions) {

    public WafVerdict {
        hits = List.copyOf(hits);
        gaps = List.copyOf(gaps);
        appliedExemptions = List.copyOf(appliedExemptions);
    }
}
