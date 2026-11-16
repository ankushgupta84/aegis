package io.aegis.rules;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;

/**
 * The part of a rule before its options: {@code action proto src sport direction dst dport}.
 *
 * <p>Addresses and ports are checked for shape only. Aegis is a reverse proxy, so every request
 * is client to server on an HTTP port, and the header's network constraints add nothing.
 *
 * @param optionText the text between the outer parentheses
 */
record RuleHeader(String action, String protocol, String optionText) {

    private static final Set<String> ACTIONS =
            Set.of("alert", "drop", "reject", "rejectsrc", "rejectdst", "rejectboth", "pass", "config");
    private static final Set<String> DIRECTIONS = Set.of("->", "<>");
    private static final int FIELDS = 7;

    static RuleHeader parse(String rule) {
        List<String> fields = new ArrayList<>();
        int pos = 0;
        while (fields.size() < FIELDS) {
            pos = skipBlanks(rule, pos);
            if (pos == rule.length() || rule.charAt(pos) == '(') {
                throw Rejection.syntax("header has " + fields.size() + " of " + FIELDS + " fields");
            }
            int end = endOfField(rule, pos);
            fields.add(rule.substring(pos, end));
            pos = end;
        }
        pos = skipBlanks(rule, pos);
        String rest = rule.substring(pos).stripTrailing();
        if (!rest.startsWith("(") || !rest.endsWith(")")) {
            throw Rejection.syntax("options are not wrapped in parentheses");
        }
        if (!ACTIONS.contains(fields.get(0))) {
            throw Rejection.syntax("unknown action '" + fields.get(0) + "'");
        }
        if (!DIRECTIONS.contains(fields.get(4))) {
            throw Rejection.syntax("unknown direction '" + fields.get(4) + "'");
        }
        return new RuleHeader(fields.get(0), fields.get(1), rest.substring(1, rest.length() - 1));
    }

    /** A field ends at a blank outside square brackets, so {@code [10.0.0.0/8, 192.168.0.0/16]} is one field. */
    private static int endOfField(String rule, int start) {
        int depth = 0;
        int i = start;
        while (i < rule.length() && (depth > 0 || !Character.isWhitespace(rule.charAt(i)))) {
            char c = rule.charAt(i++);
            depth += c == '[' ? 1 : c == ']' ? -1 : 0;
        }
        if (depth != 0) {
            throw Rejection.syntax("unbalanced '[' in header");
        }
        return i;
    }

    private static int skipBlanks(String rule, int pos) {
        while (pos < rule.length() && Character.isWhitespace(rule.charAt(pos))) {
            pos++;
        }
        return pos;
    }
}
