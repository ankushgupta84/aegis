package io.aegis.config;

import java.util.ArrayList;
import java.util.List;

/** Collects every problem found while reading, so they can be reported together. */
final class Problems {
    private final List<String> found = new ArrayList<>();

    void add(String problem) {
        found.add(problem);
    }

    /** A bookmark: compare with {@link #count()} later to learn whether a step added problems. */
    int count() {
        return found.size();
    }

    void throwIfAny() {
        if (!found.isEmpty()) {
            throw new ConfigException(found);
        }
    }
}
