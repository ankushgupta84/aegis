package io.aegis.rules;

import io.aegis.http.RuleBuffer;
import java.util.List;

/**
 * A {@code pcre} keyword read and checked, but not yet placed on a buffer. A buffer flag such as
 * {@code U} fixes {@code bufferFlag}; otherwise the sticky buffer in force decides.
 *
 * @param bufferFlag the buffer named by a flag, or null
 */
record ParsedPcre(
        String regex,
        boolean negated,
        boolean caseInsensitive,
        boolean dotAll,
        boolean multiline,
        boolean relative,
        RuleBuffer bufferFlag) {

    PcreMatch on(RuleBuffer buffer, List<Transform> transforms) {
        return new PcreMatch(buffer, transforms, regex, negated, caseInsensitive, dotAll, multiline, relative);
    }
}
