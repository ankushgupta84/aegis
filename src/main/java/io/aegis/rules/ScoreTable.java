package io.aegis.rules;

import java.util.List;
import java.util.Map;
import java.util.OptionalInt;

/**
 * Gives a rule its default score. Suricata rules alert; they do not score, so Aegis derives points
 * from what the rule says about itself, in this order:
 *
 * <ol>
 *   <li>{@code metadata: score N}, a number from 0 to 100, always wins;</li>
 *   <li>otherwise the points of the classtype's {@link Category} at the rule's {@link Severity}
 *       (see {@link Category} for the table);</li>
 *   <li>severity comes from {@code metadata: signature_severity} (unless it says {@code Unknown}),
 *       else from the rule's {@code priority}, else from the classtype's default priority.</li>
 * </ol>
 *
 * Unreadable score or severity values are errors, never ignored.
 */
final class ScoreTable {

    private static final int MAX_SCORE = 100;
    private static final String UNRATED = "Unknown";

    private ScoreTable() {
    }

    static int defaultScore(String classtype, OptionalInt priority, Map<String, List<String>> metadata) {
        if (metadata.containsKey("score")) {
            return explicitScore(metadata.get("score"));
        }
        Classtypes.Entry entry = Classtypes.find(classtype).orElse(new Classtypes.Entry(Category.MISC, Classtypes.UNKNOWN_PRIORITY));
        return entry.category().points(severity(entry, priority, metadata));
    }

    private static int explicitScore(List<String> values) {
        String text = values.get(values.size() - 1);
        try {
            int score = Integer.parseInt(text);
            if (score >= 0 && score <= MAX_SCORE) {
                return score;
            }
        } catch (NumberFormatException notANumber) {
            // reported below with the offending text
        }
        throw Rejection.because("metadata score '" + text + "' is not a whole number from 0 to " + MAX_SCORE);
    }

    private static Severity severity(Classtypes.Entry entry, OptionalInt priority, Map<String, List<String>> metadata) {
        List<String> named = metadata.get("signature_severity");
        // ET itself writes "Unknown" when it has not rated a rule: that is a stated absence, not a bad value.
        if (named != null && !named.get(named.size() - 1).equalsIgnoreCase(UNRATED)) {
            String text = named.get(named.size() - 1);
            return Severity.fromName(text).orElseThrow(
                    () -> Rejection.because("metadata signature_severity '" + text + "' is not Critical, Major, Minor, Informational or Unknown"));
        }
        return Severity.fromPriority(priority.orElse(entry.priority()));
    }
}
