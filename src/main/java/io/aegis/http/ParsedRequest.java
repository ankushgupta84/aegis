package io.aegis.http;

import java.nio.charset.StandardCharsets;
import java.util.AbstractMap.SimpleImmutableEntry;
import java.util.Arrays;
import java.util.EnumMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;

/**
 * An HTTP request decoded once. The firewall, the rule engine, and the load balancer all read
 * this object, so they cannot disagree about what the request says.
 *
 * <p>Text fields hold one char per byte (ISO-8859-1), exactly as the rule buffers do. Instances
 * are immutable except for the lazily filled buffer cache, which assumes a single event-loop
 * thread: two threads racing would at worst compute the same buffer twice and store equal
 * strings, which is harmless.
 */
public final class ParsedRequest implements RequestBuffers {

    private final String method;
    private final String rawTarget;
    private final String httpVersion;
    private final List<Map.Entry<String, String>> headers;
    private final byte[] scannedBody;
    private final int bodyLength;
    private final EnumMap<RuleBuffer, String> buffers = new EnumMap<>(RuleBuffer.class);

    private ParsedRequest(String method, String rawTarget, String httpVersion,
            List<Map.Entry<String, String>> headers, byte[] scannedBody, int bodyLength) {
        this.method = method;
        this.rawTarget = rawTarget;
        this.httpVersion = httpVersion;
        this.headers = headers;
        this.scannedBody = scannedBody;
        this.bodyLength = bodyLength;
    }

    /**
     * @param headers in the order sent, duplicates included
     * @param body the whole body; only the first {@code bodyScanLimitBytes} are exposed to rules
     * @throws IllegalArgumentException if the limit is negative or any text holds a char above
     *     0xFF, which means the caller decoded bytes as something other than ISO-8859-1
     */
    public static ParsedRequest of(String method, String rawTarget, String httpVersion,
            List<Map.Entry<String, String>> headers, byte[] body, int bodyScanLimitBytes) {
        if (bodyScanLimitBytes < 0) {
            throw new IllegalArgumentException(
                    "The body scan limit is " + bodyScanLimitBytes + " bytes; it must be 0 or more.");
        }
        requireOneCharPerByte("method", method);
        requireOneCharPerByte("request target", rawTarget);
        requireOneCharPerByte("HTTP version", httpVersion);
        List<Map.Entry<String, String>> copy = headers.stream()
                .<Map.Entry<String, String>>map(h -> new SimpleImmutableEntry<>(h.getKey(), h.getValue()))
                .toList();
        copy.forEach(h -> {
            requireOneCharPerByte("header name", h.getKey());
            requireOneCharPerByte("value of header " + h.getKey(), h.getValue());
        });
        byte[] scanned = Arrays.copyOf(body, Math.min(body.length, bodyScanLimitBytes));
        return new ParsedRequest(method, rawTarget, httpVersion, copy, scanned, body.length);
    }

    private static void requireOneCharPerByte(String what, String text) {
        if (text.chars().anyMatch(c -> c > 0xFF)) {
            throw new IllegalArgumentException("The " + what + " contains a character above U+00FF. "
                    + "Decode request bytes as ISO-8859-1 so each char is one byte.");
        }
    }

    public String method() {
        return method;
    }

    public String rawTarget() {
        return rawTarget;
    }

    public String httpVersion() {
        return httpVersion;
    }

    /** The normalized path, without the query; see {@link UriNormalizer}. */
    public String path() {
        int question = rawTarget.indexOf('?');
        return UriNormalizer.normalizePath(question < 0 ? rawTarget : rawTarget.substring(0, question));
    }

    /** The text after the first {@code ?}, undecoded, or empty when there is none. */
    public String rawQuery() {
        int question = rawTarget.indexOf('?');
        return question < 0 ? "" : rawTarget.substring(question + 1);
    }

    /** The Host header lowercased without its port, or empty. An IPv6 literal keeps its brackets. */
    public String host() {
        return header("Host").map(ParsedRequest::hostWithoutPort).orElse("");
    }

    private static String hostWithoutPort(String value) {
        String host = value.strip().toLowerCase(Locale.ROOT);
        int closingBracket = host.lastIndexOf(']');
        int colon = host.lastIndexOf(':');
        return colon > closingBracket ? host.substring(0, colon) : host;
    }

    /** The first value of the named header, matched case-insensitively. */
    public Optional<String> header(String name) {
        return headers.stream()
                .filter(h -> h.getKey().equalsIgnoreCase(name))
                .map(Map.Entry::getValue)
                .findFirst();
    }

    /** Every value of the named header, in the order sent. */
    public List<String> headers(String name) {
        return headers.stream()
                .filter(h -> h.getKey().equalsIgnoreCase(name))
                .map(Map.Entry::getValue)
                .toList();
    }

    /** All headers in the order sent, duplicates included. The list is unmodifiable. */
    public List<Map.Entry<String, String>> allHeaders() {
        return headers;
    }

    /** The full body length in bytes, including bytes beyond the scan limit. */
    public int bodyLength() {
        return bodyLength;
    }

    /** True when the body was longer than the scan limit, so rules saw only a prefix. */
    public boolean bodyTruncated() {
        return bodyLength > scannedBody.length;
    }

    @Override
    public String get(RuleBuffer buffer) {
        String cached = buffers.get(buffer);
        if (cached == null) {
            cached = compute(buffer);
            buffers.put(buffer, cached);
        }
        return cached;
    }

    private String compute(RuleBuffer buffer) {
        return switch (buffer) {
            case HTTP_METHOD -> method;
            case HTTP_URI -> UriNormalizer.normalize(rawTarget);
            case HTTP_URI_RAW -> rawTarget;
            case HTTP_HEADER -> headerLines();
            case HTTP_HOST -> host();
            case HTTP_USER_AGENT -> header("User-Agent").orElse("");
            // Joined, so splitting a cookie across two headers cannot hide it from a rule.
            case HTTP_COOKIE -> String.join("; ", headers("Cookie"));
            case HTTP_CONTENT_TYPE -> header("Content-Type").orElse("");
            case HTTP_REQUEST_BODY -> new String(scannedBody, StandardCharsets.ISO_8859_1);
            case HTTP_REQUEST_LINE -> method + ' ' + rawTarget + ' ' + httpVersion;
        };
    }

    private String headerLines() {
        return headers.stream()
                .map(h -> h.getKey() + ": " + h.getValue() + "\r\n")
                .collect(Collectors.joining());
    }
}
