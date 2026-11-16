package io.aegis.rules;

/**
 * Turns the text of a {@code content} keyword into the bytes it stands for, one char per byte.
 *
 * <p>Between pipes the text is hex ({@code |0d 0a|}); outside it, {@code \\ \" \; \: \|} stand
 * for the character after the backslash. Any other backslash sequence and any non-ASCII
 * character is rejected rather than guessed: the rule must say {@code |hex|} for such bytes.
 */
final class ContentDecoder {

    private ContentDecoder() {
    }

    static String decode(String body) {
        StringBuilder bytes = new StringBuilder();
        boolean hex = false;
        for (int i = 0; i < body.length(); i++) {
            char c = body.charAt(i);
            if (hex) {
                i = appendHexOrClose(body, i, bytes);
                hex = c != '|';
            } else if (c == '|') {
                hex = true;
            } else if (c == '\\') {
                bytes.append(escaped(body, ++i));
            } else {
                bytes.append(ascii(c));
            }
        }
        if (hex) {
            throw Rejection.syntax("hex section in content is missing its closing '|'");
        }
        if (bytes.isEmpty()) {
            throw Rejection.syntax("content is empty");
        }
        return bytes.toString();
    }

    /** Reads one hex byte at {@code i} and returns the index of its last digit; skips blanks and the closing pipe. */
    private static int appendHexOrClose(String body, int i, StringBuilder bytes) {
        char c = body.charAt(i);
        if (c == ' ' || c == '|') {
            return i;
        }
        int high = Character.digit(c, 16);
        int low = i + 1 < body.length() ? Character.digit(body.charAt(i + 1), 16) : -1;
        if (high < 0 || low < 0) {
            throw Rejection.syntax("'" + body.substring(i, Math.min(i + 2, body.length())) + "' is not a hex byte");
        }
        bytes.append((char) (high * 16 + low));
        return i + 1;
    }

    private static char escaped(String body, int i) {
        if (i >= body.length()) {
            throw Rejection.syntax("content ends with a lone backslash");
        }
        char c = body.charAt(i);
        if ("\\\";:|".indexOf(c) < 0) {
            throw Rejection.syntax("unknown escape '\\" + c + "' in content");
        }
        return c;
    }

    private static char ascii(char c) {
        if (c > 0x7f) {
            throw Rejection.syntax("non-ASCII character in content; write its bytes as |hex|");
        }
        return c;
    }
}
