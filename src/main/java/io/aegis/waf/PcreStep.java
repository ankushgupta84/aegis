package io.aegis.waf;

import com.google.re2j.Pattern;
import io.aegis.rules.PcreMatch;

/** A compiled {@code pcre} condition. RE2/J guarantees linear-time matching, so hostile input cannot stall it. */
record PcreStep(int viewId, PcreMatch match, Pattern pattern) implements Step {

    static PcreStep compile(int viewId, PcreMatch match) {
        int flags = (match.caseInsensitive() ? Pattern.CASE_INSENSITIVE : 0)
                | (match.dotAll() ? Pattern.DOTALL : 0)
                | (match.multiline() ? Pattern.MULTILINE : 0);
        return new PcreStep(viewId, match, Pattern.compile(match.regex(), flags));
    }

    @Override
    public boolean negated() {
        return match.negated();
    }
}
