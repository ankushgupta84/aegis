package io.aegis.waf;

import io.aegis.rules.Transform;
import java.util.List;

/**
 * The four Suricata buffer transforms, applied to strings that hold one byte per char. Each
 * returns its input unchanged when there is nothing to do, so the common case allocates nothing.
 */
final class ViewTransforms {

    private ViewTransforms() {
    }

    static String apply(String text, List<Transform> transforms) {
        String result = text;
        for (Transform transform : transforms) {
            result = switch (transform) {
                case URL_DECODE -> urlDecode(result);
                case TO_LOWERCASE -> Ascii.toLower(result);
                case COMPRESS_WHITESPACE -> compressWhitespace(result);
                case STRIP_WHITESPACE -> stripWhitespace(result);
            };
        }
        return result;
    }

    /** Percent-decodes once, so {@code %2541} becomes {@code %41}. A malformed escape stays as written. */
    private static String urlDecode(String text) {
        if (text.indexOf('%') < 0 && text.indexOf('+') < 0) {
            return text;
        }
        StringBuilder decoded = new StringBuilder(text.length());
        for (int i = 0; i < text.length(); i++) {
            char c = text.charAt(i);
            if (c == '+') {
                decoded.append(' ');
            } else if (c == '%' && i + 2 < text.length() && isEscapeAt(text, i)) {
                decoded.append((char) (hexValue(text.charAt(i + 1)) * 16 + hexValue(text.charAt(i + 2))));
                i += 2;
            } else {
                decoded.append(c);
            }
        }
        return decoded.toString();
    }

    private static boolean isEscapeAt(String text, int percent) {
        return hexValue(text.charAt(percent + 1)) >= 0 && hexValue(text.charAt(percent + 2)) >= 0;
    }

    private static int hexValue(char c) {
        if (c >= '0' && c <= '9') {
            return c - '0';
        }
        char lower = Ascii.toLower(c);
        return lower >= 'a' && lower <= 'f' ? lower - 'a' + 10 : -1;
    }

    private static String compressWhitespace(String text) {
        StringBuilder compressed = new StringBuilder(text.length());
        boolean inRun = false;
        for (int i = 0; i < text.length(); i++) {
            char c = text.charAt(i);
            if (!isWhitespace(c)) {
                compressed.append(c);
                inRun = false;
            } else if (!inRun) {
                compressed.append(' ');
                inRun = true;
            }
        }
        return compressed.toString();
    }

    private static String stripWhitespace(String text) {
        StringBuilder stripped = new StringBuilder(text.length());
        for (int i = 0; i < text.length(); i++) {
            if (!isWhitespace(text.charAt(i))) {
                stripped.append(text.charAt(i));
            }
        }
        return stripped.length() == text.length() ? text : stripped.toString();
    }

    /** Space, tab, newline, vertical tab, form feed, carriage return: C's {@code isspace}. */
    private static boolean isWhitespace(char c) {
        return c == ' ' || (c >= '\t' && c <= '\r');
    }
}
