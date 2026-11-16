package io.aegis.waf;

/**
 * ASCII-only case folding. Suricata's {@code nocase} folds A–Z and nothing else, whereas
 * {@link Character#toLowerCase(char)} would also fold Latin-1 letters such as {@code É}, which
 * here are just bytes of a request.
 */
final class Ascii {

    private Ascii() {
    }

    static char toLower(char c) {
        return c >= 'A' && c <= 'Z' ? (char) (c + ('a' - 'A')) : c;
    }

    static String toLower(String text) {
        int i = 0;
        while (i < text.length() && !(text.charAt(i) >= 'A' && text.charAt(i) <= 'Z')) {
            i++;
        }
        if (i == text.length()) {
            return text;
        }
        StringBuilder folded = new StringBuilder(text);
        for (; i < folded.length(); i++) {
            folded.setCharAt(i, toLower(folded.charAt(i)));
        }
        return folded.toString();
    }
}
