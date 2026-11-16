package io.aegis.rules;

/**
 * A rule value of the form {@code "text"} or {@code !"text"}. {@code body} is the text between the
 * quotes, with its escapes still in place.
 */
record QuotedValue(boolean negated, String body) {

    static QuotedValue parse(String value) {
        boolean negated = value.startsWith("!");
        String quoted = negated ? value.substring(1).stripLeading() : value;
        if (quoted.length() < 2 || !quoted.startsWith("\"") || !quoted.endsWith("\"")) {
            throw Rejection.syntax("value " + value + " is not in double quotes");
        }
        return new QuotedValue(negated, quoted.substring(1, quoted.length() - 1));
    }

    /** The body with {@code \\ \" \; \:} replaced by the character they stand for. */
    String unescaped() {
        StringBuilder text = new StringBuilder();
        for (int i = 0; i < body.length(); i++) {
            char c = body.charAt(i);
            boolean escapes = c == '\\' && i + 1 < body.length() && "\\\";:".indexOf(body.charAt(i + 1)) >= 0;
            text.append(escapes ? body.charAt(++i) : c);
        }
        return text.toString();
    }
}
