package io.aegis.rules;

import java.util.ArrayList;
import java.util.List;

/**
 * Cuts the text inside a rule's parentheses into options at each {@code ;}.
 *
 * <p>A {@code ;} does not end an option inside double quotes or after a backslash, so values such
 * as {@code content:"a;b"} and {@code pcre:"/x{1;2}/"} survive intact.
 */
final class OptionSplitter {

    private OptionSplitter() {
    }

    static List<RuleOption> split(String body) {
        List<RuleOption> options = new ArrayList<>();
        StringBuilder current = new StringBuilder();
        boolean quoted = false;
        for (int i = 0; i < body.length(); i++) {
            char c = body.charAt(i);
            if (c == '\\' && i + 1 < body.length()) {
                current.append(c).append(body.charAt(++i));
            } else if (c == ';' && !quoted) {
                addOption(options, current.toString());
                current.setLength(0);
            } else {
                quoted ^= c == '"';
                current.append(c);
            }
        }
        if (quoted) {
            throw Rejection.syntax("unterminated quote in the option list");
        }
        if (!current.toString().isBlank()) {
            throw Rejection.syntax("last option is not terminated by ';'");
        }
        return options;
    }

    private static void addOption(List<RuleOption> options, String text) {
        String option = text.strip();
        if (option.isEmpty()) {
            return;
        }
        int colon = option.indexOf(':');
        if (colon < 0) {
            options.add(new RuleOption(option, ""));
        } else {
            options.add(new RuleOption(option.substring(0, colon).strip(), option.substring(colon + 1).strip()));
        }
    }
}
