package io.aegis.rules;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.Reader;
import java.util.ArrayList;
import java.util.List;

/**
 * Groups the lines of a rule file into rules. Blank lines and {@code #} comments (including
 * commented-out rules) are dropped; a line ending in a backslash continues on the next line.
 */
final class RuleLines {

    /**
     * One rule as found in the file.
     *
     * @param raw  the file's own lines, joined by newlines, backslashes included
     * @param text the same rule on a single line, ready to parse
     */
    record Entry(String raw, String text) {
    }

    private RuleLines() {
    }

    static List<Entry> read(Reader source) throws IOException {
        List<Entry> rules = new ArrayList<>();
        BufferedReader lines = new BufferedReader(source);
        for (String line = lines.readLine(); line != null; line = lines.readLine()) {
            if (isSkippable(line)) {
                continue;
            }
            StringBuilder raw = new StringBuilder(line);
            StringBuilder text = new StringBuilder();
            while (line != null && line.endsWith("\\")) {
                text.append(line, 0, line.length() - 1);
                line = lines.readLine();
                if (line != null) {
                    raw.append('\n').append(line);
                }
            }
            text.append(line == null ? "" : line.stripLeading());
            rules.add(new Entry(raw.toString(), text.toString()));
        }
        return rules;
    }

    private static boolean isSkippable(String line) {
        String trimmed = line.strip();
        return trimmed.isEmpty() || trimmed.startsWith("#");
    }
}
