package io.aegis.http;

/**
 * The parts of an HTTP request a rule can inspect. Each maps to one Suricata sticky buffer.
 *
 * <p>Every buffer is exposed as a {@link String} in which each char is one byte (ISO-8859-1), so
 * byte-oriented rule patterns compare directly against it.
 */
public enum RuleBuffer {

    /** {@code http.method}: the request method, as sent. */
    HTTP_METHOD("http.method", "http_method"),

    /**
     * {@code http.uri}: the request target, percent-decoded once with repeated slashes collapsed.
     * Dot segments are left in place so traversal stays visible to rules.
     */
    HTTP_URI("http.uri", "http_uri"),

    /** {@code http.uri.raw}: the request target exactly as sent. */
    HTTP_URI_RAW("http.uri.raw", "http_raw_uri"),

    /** {@code http.header}: all headers as {@code Name: value\r\n} lines, in the order sent. */
    HTTP_HEADER("http.header", "http_header"),

    /** {@code http.host}: the Host header, lowercased, without the port. */
    HTTP_HOST("http.host", "http_host"),

    /** {@code http.user_agent}: the User-Agent header value. */
    HTTP_USER_AGENT("http.user_agent", "http_user_agent"),

    /** {@code http.cookie}: the Cookie header value. */
    HTTP_COOKIE("http.cookie", "http_cookie"),

    /** {@code http.content_type}: the Content-Type header value. */
    HTTP_CONTENT_TYPE("http.content_type", "http_content_type"),

    /** {@code http.request_body}: the body, up to the scan limit. */
    HTTP_REQUEST_BODY("http.request_body", "http_client_body"),

    /** {@code http.request_line}: method, raw target, and version as sent. */
    HTTP_REQUEST_LINE("http.request_line", null);

    private final String stickyKeyword;
    private final String legacyModifier;

    RuleBuffer(String stickyKeyword, String legacyModifier) {
        this.stickyKeyword = stickyKeyword;
        this.legacyModifier = legacyModifier;
    }

    /** The Suricata sticky-buffer keyword, e.g. {@code http.uri}. */
    public String stickyKeyword() {
        return stickyKeyword;
    }

    /** The older content-modifier spelling, e.g. {@code http_uri}, or null if there is none. */
    public String legacyModifier() {
        return legacyModifier;
    }
}
