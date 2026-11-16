package io.aegis.waf;

import io.aegis.policy.RuleMode;

/**
 * A rule that matched a request.
 *
 * @param mode  the mode the rule ran in; a {@link RuleMode#MONITOR} hit is logged but adds no score
 * @param score points this hit added to the request's total; 0 in monitor mode
 */
public record RuleHit(int sid, int rev, String msg, String ruleSet, RuleMode mode, int score) {
}
