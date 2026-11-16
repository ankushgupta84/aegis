package io.aegis.policy;

import java.util.List;
import java.util.Map;

/**
 * Everything the WAF needs to decide for one route.
 *
 * <p>A rule's mode is {@code sidModes[sid]} if set, otherwise {@code ruleSetModes[its rule set]}.
 * A rule set missing from {@code ruleSetModes} is {@link RuleMode#DISABLED} for the route. A rule's
 * score is {@code sidScores[sid]} if set, otherwise the rule's own default.
 */
public record WafPolicy(
        WafKnobs knobs,
        Map<String, RuleMode> ruleSetModes,
        Map<Integer, RuleMode> sidModes,
        Map<Integer, Integer> sidScores,
        List<Exemption> exemptions) {

    public WafPolicy {
        ruleSetModes = Map.copyOf(ruleSetModes);
        sidModes = Map.copyOf(sidModes);
        sidScores = Map.copyOf(sidScores);
        exemptions = List.copyOf(exemptions);
    }
}
