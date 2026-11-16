package io.aegis.proxy;

import io.netty.buffer.Unpooled;
import io.netty.handler.codec.http.DefaultFullHttpResponse;
import io.netty.handler.codec.http.FullHttpResponse;
import io.netty.handler.codec.http.HttpHeaderNames;
import io.netty.handler.codec.http.HttpResponseStatus;
import io.netty.handler.codec.http.HttpUtil;
import io.netty.handler.codec.http.HttpVersion;
import java.nio.charset.StandardCharsets;

/**
 * A request Aegis ends itself. The client learns the status and the incident ID and nothing else:
 * rule names, scores, and backend addresses never leave the process. {@code reason} is for the log.
 *
 * @param closeConnection true when the connection cannot be reused, e.g. unread body bytes remain
 */
record Refusal(HttpResponseStatus status, Decision decision, String reason, boolean closeConnection) {

    static Refusal badRequest(String reason) {
        return new Refusal(HttpResponseStatus.BAD_REQUEST, Decision.BAD_REQUEST, reason, true);
    }

    static Refusal uriTooLong() {
        return new Refusal(HttpResponseStatus.REQUEST_URI_TOO_LONG, Decision.BAD_REQUEST, "request line too long", true);
    }

    static Refusal headersTooLarge() {
        return new Refusal(HttpResponseStatus.REQUEST_HEADER_FIELDS_TOO_LARGE, Decision.BAD_REQUEST,
                "request headers too large", true);
    }

    static Refusal bodyTooLarge() {
        return new Refusal(HttpResponseStatus.REQUEST_ENTITY_TOO_LARGE, Decision.BAD_REQUEST,
                "request body over listener.max_body_bytes", true);
    }

    static Refusal headerTimeout() {
        return new Refusal(HttpResponseStatus.REQUEST_TIMEOUT, Decision.BAD_REQUEST,
                "request head not received within listener.header_timeout", true);
    }

    static Refusal methodNotAllowed(String method) {
        return new Refusal(HttpResponseStatus.METHOD_NOT_ALLOWED, Decision.BAD_REQUEST, method + " is not supported", false);
    }

    static Refusal upgradeNotSupported() {
        return new Refusal(HttpResponseStatus.NOT_IMPLEMENTED, Decision.BAD_REQUEST, "WebSocket upgrade is not supported", false);
    }

    static Refusal firewallDenied(String verdict) {
        return new Refusal(HttpResponseStatus.FORBIDDEN, Decision.FIREWALL_DENIED, verdict, false);
    }

    static Refusal rateLimited() {
        return new Refusal(HttpResponseStatus.TOO_MANY_REQUESTS, Decision.RATE_LIMITED, "rate limit", false);
    }

    static Refusal noRoute() {
        return new Refusal(HttpResponseStatus.NOT_FOUND, Decision.NO_ROUTE, "no route matches host and path", false);
    }

    static Refusal wafBlocked() {
        return new Refusal(HttpResponseStatus.FORBIDDEN, Decision.WAF_BLOCKED, "waf", false);
    }

    static Refusal noBackend() {
        return new Refusal(HttpResponseStatus.SERVICE_UNAVAILABLE, Decision.NO_BACKEND, "every backend is ejected", false);
    }

    static Refusal upstreamFailed(String reason) {
        return new Refusal(HttpResponseStatus.BAD_GATEWAY, Decision.UPSTREAM_FAILED, reason, false);
    }

    static Refusal upstreamTimeout(String reason) {
        return new Refusal(HttpResponseStatus.GATEWAY_TIMEOUT, Decision.UPSTREAM_TIMEOUT, reason, false);
    }

    static Refusal internalError(String reason) {
        return new Refusal(HttpResponseStatus.INTERNAL_SERVER_ERROR, Decision.INTERNAL_ERROR, reason, true);
    }

    /** @param headRequest true when the client asked with HEAD: the headers promise the body but it is not sent */
    FullHttpResponse response(String requestId, boolean keepAlive, boolean headRequest) {
        String text = (status == HttpResponseStatus.FORBIDDEN ? "Request blocked" : status.reasonPhrase())
                + ". Incident ID: " + requestId + "\n";
        FullHttpResponse response = new DefaultFullHttpResponse(HttpVersion.HTTP_1_1, status,
                Unpooled.copiedBuffer(text, StandardCharsets.US_ASCII));
        response.headers().set(HttpHeaderNames.CONTENT_TYPE, "text/plain; charset=utf-8");
        response.headers().set("X-Request-Id", requestId);
        HttpUtil.setContentLength(response, response.content().readableBytes());
        HttpUtil.setKeepAlive(response, keepAlive && !closeConnection);
        if (headRequest) {
            response.content().clear();
        }
        return response;
    }
}
