package io.aegis.proxy;

/** How a request ended, as written to the log and used as a metric label. */
enum Decision {
    ALLOWED("allowed"),
    BAD_REQUEST("bad_request"),
    FIREWALL_DENIED("firewall_denied"),
    RATE_LIMITED("rate_limited"),
    NO_ROUTE("no_route"),
    WAF_BLOCKED("waf_blocked"),
    NO_BACKEND("no_backend"),
    UPSTREAM_FAILED("upstream_failed"),
    UPSTREAM_TIMEOUT("upstream_timeout"),
    /** A bug or an unexpected failure inside Aegis; the request is refused rather than guessed at. */
    INTERNAL_ERROR("internal_error"),
    /** The client went away before the response finished; nothing more could be sent. */
    CLIENT_ABORTED("client_aborted");

    private final String label;

    Decision(String label) {
        this.label = label;
    }

    String label() {
        return label;
    }
}
