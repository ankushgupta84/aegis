package io.aegis.waf;

/**
 * What the engine found in one request.
 *
 * @param matchedRuleIndexes indexes of the rules that matched, ascending
 * @param budgetExceeded     true when the time budget ran out; the indexes are then only the rules
 *                           confirmed before that point
 */
public record MatchResult(int[] matchedRuleIndexes, boolean budgetExceeded) {
}
