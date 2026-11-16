package io.aegis.rules;

import io.aegis.http.RuleBuffer;
import java.util.List;

/**
 * A Suricata {@code pcre} keyword, already translated for a linear-time regex engine.
 *
 * <p>{@code regex} is the expression between the slashes. The parser has verified that RE2/J
 * compiles it; a rule whose expression needs backtracking is classified unsupported instead.
 *
 * @param relative true for the {@code R} flag: the match starts at the end of the previous match
 */
public record PcreMatch(
        RuleBuffer buffer,
        List<Transform> transforms,
        String regex,
        boolean negated,
        boolean caseInsensitive,
        boolean dotAll,
        boolean multiline,
        boolean relative) implements Condition {

    public PcreMatch {
        transforms = List.copyOf(transforms);
    }
}
