package io.aegis.config;

import java.util.ArrayList;
import java.util.List;

/**
 * The value of every knob and where it came from, recorded once while the configuration is
 * resolved. Both loading and explaining read the same ledger, so they cannot disagree.
 */
final class Ledger {
    static final String SET_IN_FILE = "set in file";
    static final String BUILT_IN_DEFAULT = "built-in default";

    record Entry(String path, String value, String source) {
        String line() {
            return path + " = " + value + "   (" + source + ")";
        }
    }

    private final List<Entry> entries = new ArrayList<>();

    void record(String path, String value, String source) {
        entries.add(new Entry(path, value, source));
    }

    List<Entry> entries() {
        return List.copyOf(entries);
    }
}
