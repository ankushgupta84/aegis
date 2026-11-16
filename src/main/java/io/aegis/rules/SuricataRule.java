package io.aegis.rules;

import java.util.List;
import java.util.Map;

/**
 * A parsed Suricata rule that Aegis can evaluate in full.
 *
 * <p>The source text stays the source of truth: {@code raw} is the rule exactly as imported, and
 * everything else is derived from it. Overrides (mode, score, exemptions) live in policy, keyed by
 * {@code sid}, and never edit the rule.
 *
 * @param action       the rule's own action ({@code alert}, {@code drop}, ...); Aegis decides by
 *                     mode and score, so this is informational
 * @param classtype    the {@code classtype} value, or the empty string
 * @param defaultScore points this rule adds when it matches: {@code metadata: score N} if present,
 *                     otherwise the score table's value for its classtype and severity
 * @param metadata     {@code metadata} keys to their values, in rule order
 * @param references   {@code reference} values such as {@code cve,2021-44228}
 * @param conditions   every condition must hold for the rule to match; never empty
 */
public record SuricataRule(
        int sid,
        int rev,
        String action,
        String msg,
        String classtype,
        int defaultScore,
        Map<String, List<String>> metadata,
        List<String> references,
        List<Condition> conditions,
        String raw) {

    public SuricataRule {
        metadata = Map.copyOf(metadata);
        references = List.copyOf(references);
        conditions = List.copyOf(conditions);
        if (conditions.isEmpty()) {
            throw new IllegalArgumentException("Rule sid " + sid + " has no conditions to evaluate");
        }
    }
}
