package io.aegis.rules;

import io.aegis.http.RuleBuffer;
import java.util.List;
import java.util.OptionalInt;

/**
 * A Suricata {@code content} keyword with its modifiers.
 *
 * <p>{@code pattern} holds the decoded bytes, one char per byte: {@code |0d 0a|} in the rule is
 * {@code "\r\n"} here. Positions follow Suricata: {@code offset} and {@code depth} count from the
 * start of the buffer, {@code distance} and {@code within} from the end of the previous match in
 * the same buffer.
 */
public record ContentMatch(
        RuleBuffer buffer,
        List<Transform> transforms,
        String pattern,
        boolean negated,
        boolean nocase,
        OptionalInt offset,
        OptionalInt depth,
        OptionalInt distance,
        OptionalInt within,
        boolean startsWith,
        boolean endsWith,
        boolean fastPattern) implements Condition {

    public ContentMatch {
        transforms = List.copyOf(transforms);
        if (pattern.isEmpty()) {
            throw new IllegalArgumentException("A content pattern cannot be empty");
        }
    }

    /** An untransformed match anywhere in the buffer. */
    public static ContentMatch anywhere(RuleBuffer buffer, String pattern, boolean nocase) {
        return new ContentMatch(buffer, List.of(), pattern, false, nocase,
                OptionalInt.empty(), OptionalInt.empty(), OptionalInt.empty(), OptionalInt.empty(),
                false, false, false);
    }

    /** True when the match position depends on the previous match in the same buffer. */
    public boolean isRelative() {
        return distance.isPresent() || within.isPresent();
    }
}
