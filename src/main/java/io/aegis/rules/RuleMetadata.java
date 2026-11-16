package io.aegis.rules;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.OptionalInt;

/**
 * Collects the descriptive options of one rule: {@code msg}, {@code sid}, {@code rev},
 * {@code classtype}, {@code priority}, {@code reference}, {@code metadata}, {@code gid} and
 * {@code target}. None of them changes what the rule matches.
 */
final class RuleMetadata {

    private int sid;
    private int rev;
    private String msg = "";
    private String classtype = "";
    private OptionalInt priority = OptionalInt.empty();
    private final List<String> references = new ArrayList<>();
    private final Map<String, List<String>> metadata = new LinkedHashMap<>();

    /** Takes the option if it is descriptive; returns false when it is not. */
    boolean accept(RuleOption option) {
        switch (option.name()) {
            case "sid" -> sid = positiveInt(option);
            case "rev" -> rev = positiveInt(option);
            case "gid" -> positiveInt(option);
            case "priority" -> priority = OptionalInt.of(positiveInt(option));
            case "msg" -> msg = QuotedValue.parse(option.requireValue()).unescaped();
            case "classtype" -> classtype = option.requireValue();
            case "reference" -> references.add(option.requireValue());
            case "metadata" -> addMetadata(option.requireValue());
            case "target" -> option.requireValue();
            default -> {
                return false;
            }
        }
        return true;
    }

    int sid() {
        return sid;
    }

    int rev() {
        return rev;
    }

    String msg() {
        return msg;
    }

    String classtype() {
        return classtype;
    }

    OptionalInt priority() {
        return priority;
    }

    List<String> references() {
        return references;
    }

    Map<String, List<String>> metadata() {
        return metadata;
    }

    private static int positiveInt(RuleOption option) {
        String text = option.requireValue();
        try {
            int number = Integer.parseInt(text);
            if (number > 0) {
                return number;
            }
        } catch (NumberFormatException notANumber) {
            // reported below with the offending text
        }
        throw Rejection.syntax("'" + option.name() + "' must be a positive whole number, found '" + text + "'");
    }

    /** Splits {@code key value, key value}; a key repeated in the rule keeps every value. */
    private void addMetadata(String pairs) {
        for (String pair : pairs.split(",")) {
            String text = pair.strip();
            if (text.isEmpty()) {
                continue;
            }
            int blank = text.indexOf(' ');
            String key = blank < 0 ? text : text.substring(0, blank);
            String value = blank < 0 ? "" : text.substring(blank + 1).strip();
            metadata.computeIfAbsent(key, k -> new ArrayList<>()).add(value);
        }
    }
}
