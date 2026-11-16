package io.aegis.policy;

import java.time.Duration;

/**
 * The client-facing socket and the limits every connection lives under.
 *
 * @param tls               whether clients connect over TLS; plaintext is for tests and for running
 *                          behind something that already terminated TLS
 * @param maxHeaderBytes    the request line and headers together may not exceed this
 * @param maxBodyBytes      a longer request body is refused with 413
 * @param headerTimeout     the longest a client may take to send the request head
 * @param idleTimeout       an idle keep-alive connection is closed after this long
 * @param drainTimeout      on shutdown, in-flight requests get this long to finish
 */
public record Listener(
        String bindAddress,
        int port,
        boolean tls,
        int maxHeaderBytes,
        int maxBodyBytes,
        Duration headerTimeout,
        Duration idleTimeout,
        Duration drainTimeout) {
}
