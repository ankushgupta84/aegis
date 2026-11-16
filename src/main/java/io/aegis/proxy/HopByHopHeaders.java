package io.aegis.proxy;

import io.netty.handler.codec.http.HttpHeaders;
import java.util.List;
import java.util.Locale;
import java.util.Set;

/**
 * Removes the headers that describe one connection, not the message, so they never cross the
 * proxy in either direction. Headers named by {@code Connection} go too, except the two a
 * hostile peer could name to damage framing or routing: Aegis rebuilds {@code Content-Length}
 * itself and must keep {@code Host}.
 */
final class HopByHopHeaders {

    private static final List<String> ALWAYS = List.of(
            "Connection", "Keep-Alive", "Proxy-Authenticate", "Proxy-Authorization",
            "TE", "Trailer", "Transfer-Encoding", "Upgrade");
    private static final Set<String> NEVER_BY_CONNECTION = Set.of("host", "content-length");

    private HopByHopHeaders() {
    }

    static void strip(HttpHeaders headers) {
        for (String value : headers.getAll("Connection")) {
            for (String name : value.split(",")) {
                String trimmed = name.strip();
                if (!trimmed.isEmpty() && !NEVER_BY_CONNECTION.contains(trimmed.toLowerCase(Locale.ROOT))) {
                    headers.remove(trimmed);
                }
            }
        }
        ALWAYS.forEach(headers::remove);
    }
}
