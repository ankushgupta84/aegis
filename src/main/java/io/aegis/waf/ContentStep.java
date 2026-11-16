package io.aegis.waf;

import io.aegis.rules.ContentMatch;

/**
 * A compiled {@code content} condition and the position rules for it.
 *
 * <p>Positions are start indexes into the view. For a pattern of length L in a view of length N
 * the match may start at any index from {@link #earliestStart} to {@link #latestStart}, inclusive.
 *
 * <p>Reading of Suricata's modifiers, which this class implements:
 * <ul>
 *   <li>Absolute (no {@code distance}/{@code within}): the match starts at or after {@code offset}
 *       (default 0) and ends at or before {@code offset + depth} (default: the view end).</li>
 *   <li>Relative ({@code distance} and/or {@code within}): with P the end of the previous match in
 *       this view (0 if none), the match starts at or after {@code P + distance} (default 0) and
 *       ends at or before {@code P + distance + within}. Counting {@code within} from the end of
 *       the {@code distance} gap follows Suricata's inspection code; counting it from P alone
 *       would make {@code distance:5; within:3} unsatisfiable.</li>
 *   <li>{@code startswith}: the match starts exactly at the view start, or at P when relative.</li>
 *   <li>{@code endswith}: the match ends exactly at the view end.</li>
 * </ul>
 */
record ContentStep(int viewId, ContentMatch match) implements Step {

    @Override
    public boolean negated() {
        return match.negated();
    }

    int earliestStart(int previousEnd, int viewLength) {
        int start = match.isRelative()
                ? clamped((long) previousEnd + match.distance().orElse(0))
                : match.offset().orElse(0);
        start = Math.max(0, start);
        if (match.startsWith()) {
            start = Math.max(start, anchor(previousEnd));
        }
        if (match.endsWith()) {
            start = Math.max(start, viewLength - length());
        }
        return start;
    }

    int latestStart(int previousEnd, int viewLength) {
        int start = Math.min(viewLength, windowEnd(previousEnd)) - length();
        if (match.startsWith()) {
            start = Math.min(start, anchor(previousEnd));
        }
        if (match.endsWith()) {
            start = Math.min(start, viewLength - length());
        }
        return start;
    }

    /**
     * The first index in {@code [from, to]} where the pattern starts, or -1. Case-sensitive search
     * uses {@link String#indexOf(String, int, int)}, which the JVM vectorizes and which stops at
     * the window end rather than scanning the rest of a large body.
     */
    int indexIn(String view, int from, int to) {
        if (from > to) {
            return -1;
        }
        if (!match.nocase()) {
            return view.indexOf(match.pattern(), from, to + length());
        }
        for (int start = from; start <= to; start++) {
            if (matchesIgnoringCaseAt(view, start)) {
                return start;
            }
        }
        return -1;
    }

    int length() {
        return match.pattern().length();
    }

    private int anchor(int previousEnd) {
        return match.isRelative() ? previousEnd : 0;
    }

    private int windowEnd(int previousEnd) {
        if (match.isRelative()) {
            return match.within().isPresent()
                    ? clamped((long) previousEnd + match.distance().orElse(0) + match.within().getAsInt())
                    : Integer.MAX_VALUE;
        }
        return match.depth().isPresent()
                ? clamped((long) match.offset().orElse(0) + match.depth().getAsInt())
                : Integer.MAX_VALUE;
    }

    /** A rule may carry huge modifier values; their sum must saturate, not wrap into a negative window. */
    private static int clamped(long position) {
        return (int) Math.max(Integer.MIN_VALUE, Math.min(Integer.MAX_VALUE, position));
    }

    private boolean matchesIgnoringCaseAt(String view, int start) {
        String pattern = match.pattern();
        for (int i = 0; i < pattern.length(); i++) {
            if (Ascii.toLower(view.charAt(start + i)) != Ascii.toLower(pattern.charAt(i))) {
                return false;
            }
        }
        return true;
    }
}
