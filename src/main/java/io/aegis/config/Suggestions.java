package io.aegis.config;

import java.util.Collection;
import java.util.Optional;

/** Finds the valid key closest to a misspelled one, so an error can say "did you mean". */
final class Suggestions {
    private static final int MAX_DISTANCE = 2;

    private Suggestions() {
    }

    static Optional<String> closest(String typo, Collection<String> validKeys) {
        String best = null;
        int bestDistance = MAX_DISTANCE + 1;
        for (String key : validKeys) {
            int distance = editDistance(typo, key);
            if (distance < bestDistance) {
                best = key;
                bestDistance = distance;
            }
        }
        return Optional.ofNullable(best);
    }

    private static int editDistance(String a, String b) {
        int[] previous = new int[b.length() + 1];
        for (int j = 0; j <= b.length(); j++) {
            previous[j] = j;
        }
        for (int i = 1; i <= a.length(); i++) {
            int[] current = new int[b.length() + 1];
            current[0] = i;
            for (int j = 1; j <= b.length(); j++) {
                int substitution = previous[j - 1] + (a.charAt(i - 1) == b.charAt(j - 1) ? 0 : 1);
                current[j] = Math.min(substitution, Math.min(previous[j], current[j - 1]) + 1);
            }
            previous = current;
        }
        return previous[b.length()];
    }
}
