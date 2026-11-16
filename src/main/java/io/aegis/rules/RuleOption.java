package io.aegis.rules;

/**
 * One {@code name:value;} item from a rule's option list. The value is verbatim, escapes and
 * quotes included, and empty for a keyword written without one.
 */
record RuleOption(String name, String value) {

    boolean hasValue() {
        return !value.isEmpty();
    }

    /** The value, or a syntax error naming the keyword when there is none. */
    String requireValue() {
        if (!hasValue()) {
            throw Rejection.syntax("'" + name + "' needs a value");
        }
        return value;
    }
}
