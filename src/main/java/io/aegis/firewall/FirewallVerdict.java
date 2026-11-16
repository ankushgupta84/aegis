package io.aegis.firewall;

/** The outcome of the IP firewall for one request. Only {@link #ALLOW} lets the request continue. */
public enum FirewallVerdict {
    /** The client passed every check. */
    ALLOW,
    /** The client is inside a deny block. */
    DENY_LISTED,
    /** An allow list exists and the client is not in it. */
    NOT_ALLOW_LISTED,
    /** The client's token bucket is empty. */
    RATE_LIMITED
}
