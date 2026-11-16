package io.aegis.proxy;

import io.netty.handler.codec.http.DefaultFullHttpRequest;
import io.netty.handler.codec.http.FullHttpRequest;
import io.netty.handler.codec.http.HttpHeaderNames;
import io.netty.handler.codec.http.HttpVersion;
import io.netty.util.AsciiString;
import java.util.Map;

/** Builds the request Aegis sends to a backend from the one the client sent. */
final class UpstreamRequest {

    private UpstreamRequest() {
    }

    /**
     * The body is shared with the client request (retained, not copied), so a retry can send it
     * again. The caller releases the client request once the exchange ends.
     *
     * <p>Header text is wrapped as {@link AsciiString}, which writes one byte per char. A plain
     * String would be written as US-ASCII and turn bytes above 0x7F into '?', so the backend
     * would see different bytes from the ones the WAF inspected.
     */
    static FullHttpRequest build(FullHttpRequest client, String requestId, String peerAddress, boolean viaTls) {
        FullHttpRequest out = new DefaultFullHttpRequest(
                HttpVersion.HTTP_1_1, client.method(), client.uri(), client.content().retainedDuplicate());
        for (Map.Entry<String, String> header : client.headers()) {
            out.headers().add(new AsciiString(header.getKey()), new AsciiString(header.getValue()));
        }
        boolean declaredLength = out.headers().contains(HttpHeaderNames.CONTENT_LENGTH);
        HopByHopHeaders.strip(out.headers());
        // The aggregator already answered Expect: 100-continue; forwarding it would invite a second 100.
        out.headers().remove(HttpHeaderNames.EXPECT);

        String forwardedFor = String.join(", ", client.headers().getAll("X-Forwarded-For"));
        out.headers().set("X-Forwarded-For", forwardedFor.isEmpty() ? peerAddress : forwardedFor + ", " + peerAddress);
        out.headers().set("X-Forwarded-Proto", viaTls ? "https" : "http");
        out.headers().set("X-Request-Id", requestId);
        // Rebuilt from the real body: whatever the client declared, and however it framed the body,
        // the backend gets one unambiguous length.
        out.headers().remove(HttpHeaderNames.CONTENT_LENGTH);
        if (declaredLength || client.content().isReadable()) {
            out.headers().set(HttpHeaderNames.CONTENT_LENGTH, client.content().readableBytes());
        }
        return out;
    }
}
