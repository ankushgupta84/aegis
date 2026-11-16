package io.aegis.proxy;

import io.netty.handler.codec.http.DefaultHttpResponse;
import io.netty.handler.codec.http.HttpHeaderNames;
import io.netty.handler.codec.http.HttpHeaderValues;
import io.netty.handler.codec.http.HttpResponse;
import io.netty.handler.codec.http.HttpUtil;
import io.netty.handler.codec.http.HttpVersion;
import io.netty.util.AsciiString;
import java.util.Map;

/** Builds the response head the client receives from the one the backend sent. */
final class ResponseHead {

    private ResponseHead() {
    }

    /**
     * Framing is decided here, not copied: the backend's connection headers are dropped, and a body
     * without a length is re-chunked for HTTP/1.1 clients. An HTTP/1.0 client cannot be sent
     * chunks, so its connection ends with the body instead.
     *
     * @param headRequest true when the client asked with HEAD, so no body follows whatever the headers say
     */
    static HttpResponse forClient(HttpResponse backend, boolean headRequest, boolean clientHttp11,
            boolean clientKeepAlive, String requestId) {
        HttpResponse out = new DefaultHttpResponse(HttpVersion.HTTP_1_1, backend.status());
        for (Map.Entry<String, String> header : backend.headers()) {
            out.headers().add(new AsciiString(header.getKey()), new AsciiString(header.getValue()));
        }
        boolean hasLength = out.headers().contains(HttpHeaderNames.CONTENT_LENGTH);
        HopByHopHeaders.strip(out.headers());
        out.headers().set("X-Request-Id", requestId);

        boolean keepAlive = clientKeepAlive;
        if (!hasLength && !hasNoBody(backend, headRequest)) {
            if (clientHttp11) {
                out.headers().set(HttpHeaderNames.TRANSFER_ENCODING, HttpHeaderValues.CHUNKED);
            } else {
                keepAlive = false;
            }
        }
        HttpUtil.setKeepAlive(out, keepAlive);
        return out;
    }

    private static boolean hasNoBody(HttpResponse backend, boolean headRequest) {
        int code = backend.status().code();
        return headRequest || code == 204 || code == 304;
    }
}
