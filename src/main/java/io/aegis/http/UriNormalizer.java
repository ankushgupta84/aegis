package io.aegis.http;

import java.util.ArrayDeque;
import java.util.Deque;

/**
 * Produces the {@link RuleBuffer#HTTP_URI} text from a raw request target, following Suricata's
 * default HTTP normalization so imported rules see what they were written against.
 *
 * <p>Input and output are strings with one char per byte (ISO-8859-1). The rules:
 * <ul>
 *   <li><b>Percent-decode exactly once.</b> Rules expect one layer of decoding; decoding twice
 *       would hide {@code %2527} (a literal {@code %27}) from rules that look for it.
 *   <li><b>Keep invalid escapes as sent.</b> {@code %zz} or a trailing {@code %4} is not data we
 *       can interpret, and guessing would let an attacker pick what the rule sees.
 *   <li><b>{@code %00} becomes byte 0.</b> Rules that match NUL-byte tricks must see the NUL.
 *   <li><b>Collapse repeated {@code /} in the path</b>, after decoding, so {@code %2f%2f} cannot
 *       dodge a rule that expects {@code /}.
 *   <li><b>Do not resolve {@code .} or {@code ..} segments.</b> Traversal attempts must stay
 *       visible to rules.
 *   <li><b>Do not turn {@code +} into a space.</b> Suricata leaves it alone; rules are written
 *       with a literal {@code +}.
 *   <li><b>Decode the query once, too, without collapsing slashes.</b> Slashes in a query are
 *       data, not path structure.
 * </ul>
 */
public final class UriNormalizer {

    private UriNormalizer() {}

    /** Normalizes a whole request target: the path, then {@code ?} and the decoded query if any. */
    public static String normalize(String rawTarget) {
        int question = rawTarget.indexOf('?');
        if (question < 0) {
            return normalizePath(rawTarget);
        }
        return normalizePath(rawTarget.substring(0, question))
                + '?' + decodeOnce(rawTarget.substring(question + 1));
    }

    /** Decodes once and collapses repeated slashes; the query must already be removed. */
    public static String normalizePath(String rawPath) {
        String decoded = decodeOnce(rawPath);
        StringBuilder collapsed = new StringBuilder(decoded.length());
        for (int i = 0; i < decoded.length(); i++) {
            char c = decoded.charAt(i);
            boolean repeatedSlash = c == '/' && i > 0 && decoded.charAt(i - 1) == '/';
            if (!repeatedSlash) {
                collapsed.append(c);
            }
        }
        return collapsed.toString();
    }

    /**
     * The path a request is routed by: {@link #normalizePath normalized}, then with {@code .} and
     * {@code ..} segments resolved as a backend would resolve them.
     *
     * <p>Rules must see {@code ..}, but routing must not be fooled by it: {@code /public/../admin}
     * reaches {@code /admin} on the backend, so it has to be judged by the policy of the route
     * that owns {@code /admin}. A {@code ..} that would climb above the root stays at the root.
     */
    public static String routingPath(String rawPath) {
        Deque<String> kept = new ArrayDeque<>();
        String normalized = normalizePath(rawPath);
        for (String segment : normalized.split("/", -1)) {
            if (segment.equals("..")) {
                kept.pollLast();
            } else if (!segment.equals(".") && !segment.isEmpty()) {
                kept.addLast(segment);
            }
        }
        boolean endsInDirectory = normalized.endsWith("/") || normalized.endsWith("/.") || normalized.endsWith("/..");
        String resolved = "/" + String.join("/", kept);
        return endsInDirectory && !kept.isEmpty() ? resolved + "/" : resolved;
    }

    /** Replaces each valid {@code %XX} with its byte; anything else is copied unchanged. */
    static String decodeOnce(String text) {
        StringBuilder out = new StringBuilder(text.length());
        for (int i = 0; i < text.length(); i++) {
            char c = text.charAt(i);
            int high = c == '%' && i + 2 < text.length() ? Character.digit(text.charAt(i + 1), 16) : -1;
            int low = high >= 0 ? Character.digit(text.charAt(i + 2), 16) : -1;
            if (low >= 0) {
                out.append((char) (high * 16 + low));
                i += 2;
            } else {
                out.append(c);
            }
        }
        return out.toString();
    }
}
